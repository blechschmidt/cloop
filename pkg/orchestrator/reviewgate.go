package orchestrator

// reviewgate.go runs a project's review gate inside a task (Task 20357).
//
// While the agent works, its pushes are held (pkg/reviewgate/hold.go). When it
// reports the task done, the configured reviewer — its own provider and model,
// not necessarily the ones doing the work — reviews every change the task
// made. In fix mode a request for changes goes back to the agent, in the same
// conversation where the provider can resume one, and the result is reviewed
// again. Only an approval lets the task's work out: the held pushes are
// replayed at the reviewed commits, and the merges the orchestrator performs
// itself (git mode, the parallel merge queue) proceed only if the tree they
// merge is the tree that was reviewed. Anything else fails the task with the
// reviewer's findings as its diagnosis.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/reviewgate"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
)

// gateRun is one task's passage through the review gate.
type gateRun struct {
	settings *pm.ReviewGate
	root     string
	snap     *reviewgate.Snapshot
	hold     *reviewgate.Hold
	// holdErr says why pushes are not held, when they are not. The review
	// still runs; the agent is then told not to push at all.
	holdErr error
}

// openGate prepares the gate for a task about to run in workDir. It returns
// nil when the project's gate is off.
func (o *Orchestrator) openGate(ctx context.Context, settings *pm.ReviewGate, workDir string) *gateRun {
	if !settings.Active() {
		return nil
	}
	g := &gateRun{settings: settings.Clone(), root: workDir}
	g.snap = reviewgate.TakeSnapshot(ctx, workDir)
	argv, err := o.reviewGateHelper()
	if err == nil {
		g.hold, err = reviewgate.NewHold(argv)
	}
	g.holdErr = err
	return g
}

// reviewGateHelper returns the program that holds the agent's pushes.
func (o *Orchestrator) reviewGateHelper() ([]string, error) {
	if len(o.config.ReviewGateHelper) > 0 {
		return o.config.ReviewGateHelper, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("cannot locate the cloop binary: %w", err)
	}
	// A test binary is not cloop: exec'ing it with the helper's arguments
	// would run the test suite from inside git.
	if strings.HasSuffix(exe, ".test") {
		return nil, errors.New("running under go test, where there is no cloop binary to hold pushes with")
	}
	return []string{exe, reviewgate.HelperSubcommand}, nil
}

func (g *gateRun) holding() bool { return g != nil && g.hold != nil }

// env is what the agent's process gets so its pushes land in the hold.
func (g *gateRun) env() []string {
	if !g.holding() {
		return nil
	}
	return g.hold.Env()
}

// promptSection is appended to the task prompt while the gate is on.
func (g *gateRun) promptSection() string {
	if g == nil {
		return ""
	}
	return reviewgate.PromptSection(g.settings.EffectiveMode(), g.holding())
}

// withheldNote annotates a task that ended without reaching the gate while
// pushes were held, and reports whether there were any. Those pushes are not
// sent: nothing about the task was approved.
func (g *gateRun) withheldNote(task *pm.Task) bool {
	if !g.holding() {
		return false
	}
	held := reviewgate.Dedupe(g.hold.Pushes())
	if len(held) == 0 {
		return false
	}
	pm.AddAnnotation(task, "cloop", fmt.Sprintf("Review gate: the task ended %s without passing review, so its %d held push(es) were not sent.",
		task.Status, len(held)))
	return true
}

func (g *gateRun) close() {
	if g != nil {
		g.hold.Close()
	}
}

// gateInput is what passGate needs to know about the task and its agent.
type gateInput struct {
	task        *pm.Task // read only
	goal        string
	conventions string
	prompt      string // the task prompt, for a provider that cannot resume
	output      string
	signal      pm.TaskStatus
	sessionID   string
	background  *provider.BackgroundActivity
	worker      provider.Provider
	workerOpts  provider.Options // for fix turns: model, effort, workdir, env
	model       string           // the project's model
	// commit holds fix turns to the project's commit policy, as it holds the
	// task's own (Task 20370). Nil when the policy is off.
	commit *commitGuard
}

// gateStep is one fix turn, for the step log.
type gateStep struct {
	output              string
	duration            time.Duration
	inputTok, outputTok int
}

// gateOutcome is what the gate decided and everything it spent getting there.
type gateOutcome struct {
	review *pm.TaskReview
	// fail means the task must not count as done: the review blocked it, or
	// it was approved and its held pushes could not all be delivered.
	fail bool
	note string

	// The agent's latest turn — after any fix rounds.
	output     string
	signal     pm.TaskStatus
	background *provider.BackgroundActivity
	sessionID  string
	steps      []gateStep

	workIn, workOut, workThinking int
	reviewIn, reviewOut           int
	reviewerName, reviewerModel   string

	changes *reviewgate.Changes
	snap    *reviewgate.Snapshot
}

// passGate reviews a finished task and decides what leaves the machine.
func (o *Orchestrator) passGate(ctx context.Context, g *gateRun, in gateInput) *gateOutcome {
	settings := g.settings
	mode := settings.EffectiveMode()
	maxFix := settings.EffectiveFixRounds()
	out := &gateOutcome{output: in.output, signal: in.signal, background: in.background, sessionID: in.sessionID, snap: g.snap}

	reviewer, rerr := o.reviewerFor(settings, in.model)
	rec := &pm.TaskReview{Mode: mode}
	if reviewer != nil {
		rec.Provider, rec.Model = reviewer.ProviderName, reviewer.Model
		out.reviewerName, out.reviewerModel = reviewer.ProviderName, reviewer.Model
	}

	var prior *reviewgate.Verdict
	for {
		held := g.hold.Pushes()
		changes, err := reviewgate.Collect(ctx, g.snap, held)
		if err != nil {
			rec.Verdict, rec.Error = pm.ReviewUnavailable, "the task's changes could not be read: "+err.Error()
			break
		}
		out.changes = changes
		if changes.Empty() {
			rec.Verdict, rec.Error = pm.ReviewNothing, ""
			break
		}
		if rerr != nil {
			rec.Verdict, rec.Error = pm.ReviewUnavailable, rerr.Error()
			break
		}
		in2 := reviewgate.Input{
			Goal:         in.goal,
			Conventions:  in.conventions,
			TaskID:       in.task.ID,
			TaskTitle:    in.task.Title,
			TaskDesc:     in.task.Description,
			AgentReport:  out.output,
			Changes:      changes,
			Instructions: settings.Instructions,
			Round:        rec.Rounds + 1,
		}
		if prior != nil {
			in2.PriorFindings, in2.PriorSummary = prior.Findings, prior.Summary
		}
		round := reviewer.Review(ctx, g.root, in2)
		rec.Rounds++
		out.reviewIn += round.InputTokens
		out.reviewOut += round.OutputTokens
		if round.Model != "" && rec.Model == "" {
			rec.Model = round.Model
		}
		if round.Err != nil {
			rec.Verdict, rec.Error = pm.ReviewUnavailable, round.Err.Error()
			break
		}
		v := round.Verdict
		rec.Summary, rec.Findings, rec.Error = v.Summary, v.Findings, ""
		if v.Approved {
			rec.Verdict = pm.ReviewApproved
			break
		}
		rec.Verdict = pm.ReviewChangesRequested
		if mode != pm.ReviewModeFix || rec.FixRounds >= maxFix || ctx.Err() != nil {
			break
		}

		// Send the agent back with the findings.
		rec.FixRounds++
		fixOpts := in.workerOpts
		fixOpts.ResumeSession = out.sessionID
		resumed := out.sessionID != ""
		prompt := reviewgate.FixPrompt(reviewer.Label(), v, rec.FixRounds, maxFix, g.holding(), resumed, in.prompt, out.output)
		start := time.Now()
		res, _, ferr := completeTask(ctx, in.worker, prompt, fixOpts, in.commit)
		if ferr != nil || res == nil || strings.TrimSpace(res.Output) == "" {
			why := "it returned nothing"
			if ferr != nil {
				why = ferr.Error()
			}
			rec.Error = "the agent could not be sent back with the findings: " + why
			break
		}
		out.steps = append(out.steps, gateStep{output: res.Output, duration: time.Since(start),
			inputTok: res.InputTokens, outputTok: res.OutputTokens})
		out.workIn += res.InputTokens
		out.workOut += res.OutputTokens
		out.workThinking += res.ThinkingTokens
		out.output, out.background = res.Output, res.Background
		out.signal = pm.CheckTaskSignal(res.Output)
		if res.SessionID != "" {
			out.sessionID = res.SessionID
		}
		if out.signal == pm.TaskFailed || out.signal == pm.TaskSkipped {
			rec.Error = fmt.Sprintf("the agent ended its fix turn with %s instead of addressing the findings",
				strings.ToUpper("TASK_"+string(out.signal)))
			break
		}
		if res.Background.Incomplete() {
			rec.Error = "the agent's fix turn left background work running, so its result is not finished"
			break
		}
		prior = v
	}
	rec.ReviewedAt = time.Now().UTC()
	if out.changes != nil {
		rec.Repos = reposRecord(out.changes)
	}

	switch rec.Verdict {
	case pm.ReviewApproved, pm.ReviewNothing:
	default:
		rec.Blocked = mode != pm.ReviewModeAdvisory
	}
	held := g.hold.Pushes()
	switch {
	case rec.Blocked:
		rec.Published = reviewgate.Withhold(g.root, held, "the review did not approve the task")
		out.fail = true
		out.note = rec.Headline()
	default:
		rec.Published = reviewgate.Publish(ctx, out.changes, held)
		var failed []string
		for _, p := range rec.Published {
			if p.Outcome == pm.PublishRefused || p.Outcome == pm.PublishFailed {
				failed = append(failed, fmt.Sprintf("%s %s: %s", p.Remote, p.Ref, p.Detail))
			}
		}
		out.note = rec.Headline()
		if n := countOutcome(rec.Published, pm.PublishPushed); n > 0 {
			out.note += fmt.Sprintf(" Published %d held push(es).", n)
		}
		if len(failed) > 0 {
			out.fail = true
			out.note += fmt.Sprintf(" %d held push(es) were not delivered — %s.", len(failed), strings.Join(failed, "; "))
		}
	}
	if !g.holding() && g.holdErr != nil {
		out.note += " (Pushes were not held: " + g.holdErr.Error() + "; the agent was told not to push.)"
	}
	rec.Bound()
	out.review = rec
	return out
}

// reviewerFor builds the reviewer a gate names, cached per provider for the
// run. The model falls back to the project's own when the reviewer shares its
// provider — "use a stronger model" is the change most gates make, and a
// blank model there should mean "the one we work with", not whatever that
// provider's default is — and otherwise to config.yaml's model for it.
func (o *Orchestrator) reviewerFor(g *pm.ReviewGate, projectModel string) (*reviewgate.Reviewer, error) {
	name := g.Provider
	same := name == "" || name == o.config.ProviderName
	if name == "" {
		name = o.config.ProviderName
	}
	model := g.Model
	if model == "" && same {
		model = projectModel
	}
	if model == "" {
		model = o.config.ProviderModels[name]
	}
	r := &reviewgate.Reviewer{ProviderName: name, Model: model, Effort: g.Effort, Timeout: o.config.StepTimeout}
	if o.config.ReviewProvider != nil {
		r.Provider = o.config.ReviewProvider
		if r.ProviderName == "" {
			r.ProviderName = o.config.ReviewProvider.Name()
		}
		return r, nil
	}
	if name == "" {
		return r, errors.New("the reviewer's provider is not known: set one in the review gate settings")
	}
	o.reviewersMu.Lock()
	defer o.reviewersMu.Unlock()
	if p, ok := o.reviewers[name]; ok {
		r.Provider = p
		return r, nil
	}
	cfg := o.config.ProviderCfg
	cfg.Name = name
	p, err := provider.Build(cfg)
	if err != nil {
		return r, fmt.Errorf("the reviewer (%s) could not be set up: %w", name, err)
	}
	if o.reviewers == nil {
		o.reviewers = map[string]provider.Provider{}
	}
	o.reviewers[name] = p
	r.Provider = p
	return r, nil
}

// gateAllowsMerge reports whether the orchestrator may merge commit in the
// repository at dir after the gate ran: only if the review let the task
// through and the commit's tree is the tree the reviewer saw. A nil outcome
// — the gate was off — allows everything.
func gateAllowsMerge(ctx context.Context, out *gateOutcome, dir, commit string) (bool, string) {
	if out == nil {
		return true, ""
	}
	if out.review == nil || !out.review.Approved() {
		return false, "the review gate did not approve the task"
	}
	got := reviewgate.TreeOf(ctx, dir, commit)
	want := ""
	if rc := out.changes.Repo(dir); rc != nil {
		want = rc.Tree
	} else if head, ok := out.snap.Head(dir); ok && head != "" {
		// The review saw no change here, so the merge must bring none.
		want = reviewgate.TreeOf(ctx, dir, head)
	}
	if got == "" || want == "" || got != want {
		return false, "the tree to be merged is not the tree the reviewer approved"
	}
	return true, ""
}

func reposRecord(c *reviewgate.Changes) []pm.ReviewedRepo {
	var out []pm.ReviewedRepo
	for _, r := range c.Repos {
		out = append(out, pm.ReviewedRepo{
			Path: r.Rel, Base: r.Base, Head: r.Head,
			Files: r.Files, Insertions: r.Insertions, Deletions: r.Deletions,
			Commits: r.CommitCount, Uncommitted: r.Uncommitted, Truncated: r.Truncated,
		})
	}
	return out
}

func countOutcome(ps []pm.ReviewPublish, outcome string) int {
	n := 0
	for _, p := range ps {
		if p.Outcome == outcome {
			n++
		}
	}
	return n
}

// logReviewEvent journals the gate's decision on the task.
func (o *Orchestrator) logReviewEvent(s *state.ProjectState, task *pm.Task, out *gateOutcome) {
	if out == nil || out.review == nil {
		return
	}
	r := out.review
	step := 0
	if s != nil {
		step = s.CurrentStep
	}
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type:      state.EventTaskReview,
		TaskID:    task.ID,
		TaskTitle: task.Title,
		Step:      step,
		Message:   fmt.Sprintf("Task #%d — %s", task.ID, strings.TrimPrefix(out.note, "Review gate: ")),
	}, map[string]any{
		"verdict":    string(r.Verdict),
		"mode":       r.Mode,
		"blocked":    r.Blocked,
		"failed":     out.fail,
		"provider":   r.Provider,
		"model":      r.Model,
		"rounds":     r.Rounds,
		"fix_rounds": r.FixRounds,
		"findings":   len(r.Findings),
		"pushed":     countOutcome(r.Published, pm.PublishPushed),
		"withheld":   countOutcome(r.Published, pm.PublishWithheld),
		"refused":    countOutcome(r.Published, pm.PublishRefused) + countOutcome(r.Published, pm.PublishFailed),
	})
}

// recordReviewCost bills the reviewer's tokens to the task in the cost ledger,
// under the reviewer's own provider and model, so a gate on a more expensive
// model shows up as what it costs. Best-effort like the task's own ledger
// entry: a failure is reported, not returned.
func (o *Orchestrator) recordReviewCost(task *pm.Task, out *gateOutcome) {
	if out == nil || (out.reviewIn == 0 && out.reviewOut == 0) {
		return
	}
	usd, _ := cost.Estimate(strings.ToLower(out.reviewerModel), out.reviewIn, out.reviewOut)
	err := cost.AppendLedger(o.config.WorkDir, cost.LedgerEntry{
		TaskID:       task.ID,
		TaskTitle:    task.Title + " (review)",
		Provider:     out.reviewerName,
		Model:        out.reviewerModel,
		InputTokens:  out.reviewIn,
		OutputTokens: out.reviewOut,
		EstimatedUSD: usd,
		Identity:     resolveRunIdentity(o.config.WorkDir),
	})
	if err != nil {
		color.New(color.Faint).Printf("  cost ledger write error for task %d's review (ignored): %v\n", task.ID, err)
	}
}

// withGateSection puts the gate's section into a task prompt ahead of its
// closing instructions, so the TASK_* signal lines stay the last thing the
// agent reads. A prompt without them — a hand-edited context override — gets
// the section appended.
func withGateSection(prompt, section string) string {
	if section == "" {
		return prompt
	}
	const marker = "## INSTRUCTIONS\n"
	if i := strings.LastIndex(prompt, marker); i >= 0 {
		return prompt[:i] + section + prompt[i:]
	}
	return prompt + "\n\n" + section
}

// gateAllowsMergeOf decides whether the orchestrator may merge commit, in the
// repository containing workDir, once a task is over: always while the gate
// is off; with it on, only the tree the reviewer approved — or, for a task
// that never reached the review, a commit that brings no change at all.
func (o *Orchestrator) gateAllowsMergeOf(ctx context.Context, g *gateRun, out *gateOutcome, workDir, commit string) (bool, string) {
	if g == nil {
		return true, ""
	}
	dir := reviewgate.Toplevel(ctx, workDir)
	if dir == "" {
		return true, ""
	}
	if out == nil {
		if head, ok := g.snap.Head(dir); ok && head != "" &&
			reviewgate.TreeOf(ctx, dir, commit) == reviewgate.TreeOf(ctx, dir, head) {
			return true, ""
		}
		return false, "the task's changes did not pass the review gate"
	}
	return gateAllowsMerge(ctx, out, dir, commit)
}
