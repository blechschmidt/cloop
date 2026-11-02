package requirements

// standing.go: where each approved requirement stands against the plan, and
// what it would take to close its gap (Task 20463) — the requirement status
// summary every planner is given: `cloop requirements plan`, the suggestions
// panel, auto-evolve, the plan assistant and the Split preview.
//
// A requirement's standing has two halves. What the project's database knows
// — its latest verdict, and whether that verdict is about its current
// definition — is the same wherever it is read, and travels as is to an
// executor that holds no copy of the database (a device's run gets it in its
// seed). What the plan adds — which tasks implement it, which of them are
// still open, which finished or failed since the verdict — is worked out where
// the plan is (Assess), because a run's plan moves on after its seed is made.
//
// # Gaps and actions
//
// Gaps describe; actions decide. A requirement may be untested and implemented
// by no task at once, but one task closes it, and which task is the action:
//
//	fix        it fails: its latest check found it unfulfilled, or could not
//	           run its tests
//	implement  nothing shows it holds: never checked, or only by an earlier
//	           definition, or checked by nobody but the model and found unknown
//	verify     it was found to hold, but it has changed since
//	test       it holds by the model's or a person's word and lacks only a test
//
// Those four are a planner's targets. The rest are not a task's to close:
//
//	covered      an open task implements it already
//	check        a task implementing it finished after its verdict, or tasks
//	             finished since it was last found to hold: a check would say
//	attach_test  a task implementing it finished and it still has no test: a
//	             person gives it the one that task wrote — tests are commands
//	             that run, which a model does not get to add
//	stuck        a task meant to close it failed or was skipped, or is done
//	             while it still fails: a person looks
//
// Which is why auto-evolve cannot loop on a requirement: once a task linked to
// a target finishes, fails or is skipped, the target is one no planner plans
// for until the requirement changes, a check finds it holding, or a person
// resets the task. A check that finds it failing again — the requirements gate
// checks every must requirement at every task — confirms a failed attempt
// rather than undoing it.
//
// Drafts and deprecated requirements have no standing. Nobody has agreed to a
// draft, and the project no longer requires a deprecated one: no planner
// plans for either.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Gap kinds: why an approved requirement is open.
const (
	// GapUnfulfilled: its latest check of its current definition found it does
	// not hold, or could not run its tests.
	GapUnfulfilled = "unfulfilled"
	// GapStale: its latest verdict is about an earlier definition, or tasks
	// finished since it — what the Requirements tab calls stale.
	GapStale = "stale"
	// GapUntested: it has no test.
	GapUntested = "untested"
	// GapUnlinked: no task implements it.
	GapUnlinked = "unlinked"
	// GapUnchecked: nothing has checked it.
	GapUnchecked = "unchecked"
)

// Gaps lists the gap kinds in the order a standing lists them.
var Gaps = []string{GapUnfulfilled, GapStale, GapUntested, GapUnlinked, GapUnchecked}

// Actions: what closes a requirement's gap. See the file comment.
const (
	ActionFix        = "fix"
	ActionImplement  = "implement"
	ActionVerify     = "verify"
	ActionTest       = "test"
	ActionCovered    = "covered"
	ActionCheck      = "check"
	ActionAttachTest = "attach_test"
	ActionStuck      = "stuck"
	// ActionNone: it holds, as far as the project knows.
	ActionNone = ""
)

// targetActions are the actions a task closes, strongest first: a task
// closing gaps of several kinds is the kind of its strongest.
var targetActions = []string{ActionFix, ActionImplement, ActionVerify, ActionTest}

// IsTarget reports whether action is one a task closes.
func IsTarget(action string) bool { return slices.Contains(targetActions, action) }

func validAction(a string) bool {
	return a == ActionNone || IsTarget(a) || a == ActionCovered || a == ActionCheck || a == ActionAttachTest || a == ActionStuck
}

// Bounds on a status summary. It travels to an executor as one argument of
// the command that plans from it — Linux caps one at 128 KiB — beside the
// others that command takes, and in a device's seed.
const (
	// MaxStatusBytes bounds an encoded summary. Past it the least pressing
	// requirements are left out and counted (StatusSummary.Omitted).
	MaxStatusBytes = 64 << 10
	// maxStandingSummaryRunes bounds what a standing quotes of its verdict.
	maxStandingSummaryRunes = 300
	// maxStandingTasks bounds each list of tasks a standing names.
	maxStandingTasks = 16
)

// Standing is where one approved requirement stands.
type Standing struct {
	// What the project's database records.
	ID       int    `json:"id"`
	Title    string `json:"title"`
	Priority string `json:"priority,omitempty"`
	Tested   bool   `json:"tested,omitempty"`
	// ChangedAt is when its definition last changed.
	ChangedAt time.Time `json:"changed_at,omitzero"`
	// Verdict is its latest check's verdict, empty when nothing has checked
	// it; CheckedAt when that was; Summary what the check said, on one line.
	Verdict   string    `json:"verdict,omitempty"`
	CheckedAt time.Time `json:"checked_at,omitzero"`
	Summary   string    `json:"summary,omitempty"`
	// Earlier reports that the verdict is about an earlier definition: the
	// requirement has changed since it was checked.
	Earlier bool `json:"earlier,omitempty"`
	// HeldAt is when a check of its current definition last found it
	// fulfilled; zero when none has.
	HeldAt time.Time `json:"held_at,omitzero"`

	// What the plan adds (Assess).
	Gaps   []string `json:"gaps,omitempty"`
	Action string   `json:"action,omitempty"`
	// Open are the pending or running tasks that implement it, Done the
	// finished ones, and Failed the ones that failed after its verdict.
	Open   []int `json:"open_tasks,omitempty"`
	Done   []int `json:"done_tasks,omitempty"`
	Failed []int `json:"failed_tasks,omitempty"`
}

// Key is how the standing's requirement is named to people.
func (s Standing) Key() string { return Key(s.ID) }

// Target reports whether a task closes s's gap.
func (s Standing) Target() bool { return IsTarget(s.Action) }

// Rank is s's priority as a number, must first: what orders work by its
// requirements.
func (s Standing) Rank() int { return PriorityRank(s.Priority) }

// PriorityRank orders priorities: must 0, should 1, could 2, none 3.
func PriorityRank(p string) int {
	switch p {
	case PriorityMust:
		return 0
	case PriorityShould:
		return 1
	case PriorityCould:
		return 2
	}
	return 3
}

// NoRank is the rank of work that closes no requirement's gap: after all of
// it.
const NoRank = 4

// RankPriority is the priority a rank stands for: PriorityRank's inverse, ""
// for a requirement without one and for NoRank.
func RankPriority(rank int) string {
	if rank >= 0 && rank < len(Priorities) {
		return Priorities[rank]
	}
	return ""
}

// TaskPriority is the run-queue priority of a task made to close a gap of a
// requirement of priority p (1 runs first): must ahead of the default, could
// behind it.
func TaskPriority(p string) int {
	switch p {
	case PriorityMust:
		return 1
	case PriorityCould:
		return 4
	}
	return 2
}

// LastCheck is a requirement's latest recorded verdict, as Standings reads it.
type LastCheck struct {
	Verdict     string
	Summary     string
	Fingerprint string
	CheckedAt   time.Time
	// HeldAt is when a check of the requirement's current definition last
	// found it fulfilled; zero when none has.
	HeldAt time.Time
}

// Standings is what the project's database knows of each approved
// requirement of reqs, most important first; last holds each one's latest
// check by id. Drafts and deprecated requirements are left out.
func Standings(reqs []Requirement, last map[int]LastCheck) []Standing {
	out := make([]Standing, 0, len(reqs))
	for _, r := range reqs {
		if r.CurrentStatus() != StatusApproved {
			continue
		}
		st := Standing{ID: r.ID, Title: oneLine(r.Title), Priority: r.Priority, Tested: r.Tested(), ChangedAt: r.UpdatedAt.UTC()}
		if st.ChangedAt.IsZero() {
			st.ChangedAt = r.CreatedAt.UTC()
		}
		if c, ok := last[r.ID]; ok && ValidVerdict(c.Verdict) {
			st.Verdict, st.CheckedAt = c.Verdict, c.CheckedAt.UTC()
			st.Summary = truncateRunes(oneLine(c.Summary), maxStandingSummaryRunes)
			st.Earlier = c.Fingerprint != "" && c.Fingerprint != r.Fingerprint()
			st.HeldAt = c.HeldAt.UTC()
		}
		out = append(out, st)
	}
	sortStandings(out)
	return out
}

// sortStandings orders standings by priority, then id.
func sortStandings(st []Standing) {
	sort.SliceStable(st, func(i, j int) bool {
		if a, b := st[i].Rank(), st[j].Rank(); a != b {
			return a < b
		}
		return st[i].ID < st[j].ID
	})
}

// Task statuses, as TaskView carries them: the values of pm.TaskStatus, which
// this package cannot import.
const (
	taskPending    = "pending"
	taskInProgress = "in_progress"
	taskDone       = "done"
	taskFailed     = "failed"
	taskTimedOut   = "timed_out"
	taskSkipped    = "skipped"
)

// TaskView is a task of the plan as Assess reads it (pm.TaskViews).
type TaskView struct {
	ID           int
	Status       string
	CompletedAt  time.Time
	Requirements []int
}

func (t TaskView) open() bool { return t.Status == taskPending || t.Status == taskInProgress }

// Assess works out each standing's gaps and action against the plan's tasks,
// and returns the standings in the order Standings gives them. The plan-made
// fields st carried are recomputed: a run's plan moves on after its seed is
// made.
func Assess(st []Standing, tasks []TaskView) []Standing {
	linked := map[int][]TaskView{}
	var lastDone time.Time
	for _, t := range tasks {
		if t.Status == taskDone && t.CompletedAt.After(lastDone) {
			lastDone = t.CompletedAt
		}
		seen := map[int]bool{}
		for _, id := range t.Requirements {
			if !seen[id] {
				seen[id] = true
				linked[id] = append(linked[id], t)
			}
		}
	}
	out := make([]Standing, len(st))
	for i, s := range st {
		s.Gaps, s.Open, s.Done, s.Failed = nil, nil, nil, nil
		s.Action = assess(&s, linked[s.ID], lastDone)
		out[i] = s
	}
	sortStandings(out)
	return out
}

// assess fills in s's gaps and task lists from the tasks that implement it,
// and returns its action. lastDone is when the plan's latest task finished.
//
// A linked task that is no longer open is an attempt, and counts against the
// latest news about the requirement:
//
//   - one that finished, when it finished after the verdict — the verdict's
//     time for one about what the requirement says now, else when it last
//     changed: what it did is unknown until a check, or a test, says. One with
//     no completion time — marked done by hand, or in a dry run — counts as
//     after, since nothing shows it came first; of a requirement that fails,
//     it makes the requirement one a person looks at;
//   - one that failed or was skipped, when it ended after the requirement
//     last changed and after it was last found to hold. Checks that find it
//     failing since confirm the failure rather than undo it.
func assess(s *Standing, linked []TaskView, lastDone time.Time) string {
	verdict := s.Verdict
	failing := !s.Earlier && (verdict == VerdictUnfulfilled || verdict == VerdictError)
	checked := verdict != "" && verdict != VerdictUnverified
	since := s.ChangedAt
	if checked && !s.Earlier {
		since = s.CheckedAt
	}
	attemptSince := s.ChangedAt
	if s.HeldAt.After(attemptSince) {
		attemptSince = s.HeldAt
	}
	var workedSince, doneWhenUnknown, failedSince bool
	for _, t := range linked {
		switch {
		case t.open():
			s.Open = appendBounded(s.Open, t.ID)
		case t.Status == taskDone:
			s.Done = appendBounded(s.Done, t.ID)
			if t.CompletedAt.IsZero() {
				doneWhenUnknown = true
			} else if t.CompletedAt.After(since) {
				workedSince = true
			}
		case t.Status == taskFailed || t.Status == taskTimedOut || t.Status == taskSkipped:
			if t.CompletedAt.IsZero() || t.CompletedAt.After(attemptSince) {
				s.Failed = appendBounded(s.Failed, t.ID)
				failedSince = true
			}
		}
	}

	if failing {
		s.Gaps = append(s.Gaps, GapUnfulfilled)
	}
	// Stale as the Requirements tab says it: any verdict once the
	// requirement has changed, and any but unverified once a task finished.
	if verdict != "" && (s.Earlier || (verdict != VerdictUnverified && lastDone.After(s.CheckedAt))) {
		s.Gaps = append(s.Gaps, GapStale)
	}
	if !s.Tested {
		s.Gaps = append(s.Gaps, GapUntested)
	}
	if len(linked) == 0 {
		s.Gaps = append(s.Gaps, GapUnlinked)
	}
	if verdict == "" {
		s.Gaps = append(s.Gaps, GapUnchecked)
	}

	holds := verdict == VerdictFulfilled && !s.Earlier
	worked := workedSince || (doneWhenUnknown && !failing)
	switch {
	case len(s.Open) > 0:
		return ActionCovered
	case worked && !s.Tested && !failing:
		return ActionAttachTest
	case worked:
		return ActionCheck
	case doneWhenUnknown || failedSince:
		return ActionStuck
	case failing:
		return ActionFix
	case !s.Tested && holds:
		return ActionTest
	case !s.Tested:
		return ActionImplement
	case !checked:
		return ActionImplement
	case s.Earlier:
		return ActionVerify
	case slices.Contains(s.Gaps, GapStale):
		return ActionCheck
	}
	return ActionNone
}

func appendBounded(ids []int, id int) []int {
	if len(ids) >= maxStandingTasks {
		return ids
	}
	return append(ids, id)
}

// StatusSummary is the requirement status summary a planner is given: where
// each approved requirement stands, most pressing first.
type StatusSummary struct {
	Requirements []Standing `json:"requirements"`
	// Omitted counts approved requirements left out so the summary fits
	// (Encode): the least pressing ones.
	Omitted int `json:"omitted,omitempty"`
}

// Empty reports whether the project has no approved requirement.
func (s StatusSummary) Empty() bool { return len(s.Requirements) == 0 && s.Omitted == 0 }

// Summarize assesses st against tasks into a summary.
func Summarize(st []Standing, tasks []TaskView) StatusSummary {
	return StatusSummary{Requirements: Assess(st, tasks)}
}

// Targets are the standings a task closes, most important first: must before
// should before could, then by id.
func (s StatusSummary) Targets() []Standing {
	var out []Standing
	for _, st := range s.Requirements {
		if st.Target() {
			out = append(out, st)
		}
	}
	return out
}

// MustGaps are the targets of priority must: the gaps that come before any
// new feature.
func (s StatusSummary) MustGaps() []Standing {
	var out []Standing
	for _, st := range s.Targets() {
		if st.Priority == PriorityMust {
			out = append(out, st)
		}
	}
	return out
}

// Lookup finds the standing of requirement id.
func (s StatusSummary) Lookup(id int) (Standing, bool) {
	for _, st := range s.Requirements {
		if st.ID == id {
			return st, true
		}
	}
	return Standing{}, false
}

// Facts is s with only what the database records: what a seed carries, for
// the run at the other end to assess against its own plan.
func (s StatusSummary) Facts() StatusSummary {
	out := StatusSummary{Requirements: make([]Standing, len(s.Requirements)), Omitted: s.Omitted}
	for i, st := range s.Requirements {
		st.Gaps, st.Action, st.Open, st.Done, st.Failed = nil, "", nil, nil, nil
		out.Requirements[i] = st
	}
	return out
}

// pressing orders standings for a summary that must be cut: targets first,
// the requirements an open task implements next, then the ones waiting for a
// check or a person, then the ones that hold — each by priority, then id.
func pressing(st Standing) int {
	switch {
	case st.Target():
		return 0
	case st.Action == ActionCovered:
		return 1
	case st.Action != ActionNone:
		return 2
	}
	return 3
}

// Encode is s as it travels: JSON without HTML escaping, at most
// MaxStatusBytes of it. Past that the least pressing requirements are left
// out and counted in Omitted.
func (s StatusSummary) Encode() ([]byte, error) { return s.encode(false) }

// EncodeFacts is s's facts (Facts) as a seed carries them, cut like Encode:
// by how pressing each requirement is on the hub's plan, so the ones a run
// most needs to know of are the ones that fit.
func (s StatusSummary) EncodeFacts() ([]byte, error) { return s.encode(true) }

func (s StatusSummary) encode(facts bool) ([]byte, error) {
	keep := slices.Clone(s.Requirements)
	sort.SliceStable(keep, func(i, j int) bool { return pressing(keep[i]) < pressing(keep[j]) })
	omitted := s.Omitted
	for {
		out := StatusSummary{Requirements: restoreOrder(keep), Omitted: omitted}
		if facts {
			out = out.Facts()
		}
		raw, err := encodeJSON(out)
		if err != nil {
			return nil, err
		}
		if len(raw) <= MaxStatusBytes || len(keep) == 0 {
			return raw, nil
		}
		// Cut a tenth at a time: one encoding per requirement would be
		// quadratic in a large project's.
		cut := max(1, len(keep)/10)
		keep, omitted = keep[:len(keep)-cut], omitted+cut
	}
}

// restoreOrder puts the standings a summary keeps back in priority order.
func restoreOrder(st []Standing) []Standing {
	out := slices.Clone(st)
	sortStandings(out)
	return out
}

func encodeJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// ParseStatusSummary reads a summary a hub sent, holding every field to what
// Standings and Assess produce: one bad entry refuses the whole summary — it
// came from a hub, and a hub that sends one is not one to plan from. A field,
// gap or action this build does not know is a newer hub's, and is passed
// over rather than refused: a device's cloop is often older than its hub.
func ParseStatusSummary(raw []byte) (StatusSummary, error) {
	var s StatusSummary
	if len(raw) > MaxStatusBytes {
		return s, invalid("the requirement status is %d bytes, more than %d", len(raw), MaxStatusBytes)
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return StatusSummary{}, invalid("the requirement status is not a status summary: %v", err)
	}
	if len(s.Requirements) > MaxRequirements || s.Omitted < 0 || s.Omitted > MaxRequirements {
		return StatusSummary{}, invalid("the requirement status names too many requirements")
	}
	seen := map[int]bool{}
	for i := range s.Requirements {
		st := &s.Requirements[i]
		if err := st.check(); err != nil {
			return StatusSummary{}, fmt.Errorf("requirement %d of the status: %w", i+1, err)
		}
		if seen[st.ID] {
			return StatusSummary{}, invalid("the requirement status names %s twice", st.Key())
		}
		seen[st.ID] = true
	}
	sortStandings(s.Requirements)
	return s, nil
}

func (st *Standing) check() error {
	var err error
	if st.ID <= 0 {
		return invalid("a standing needs a requirement id")
	}
	if st.Title, err = NormalizeTitle(st.Title); err != nil {
		return err
	}
	// A priority or a verdict this build does not know is a newer hub's: as
	// none, rather than a reason to plan without the summary.
	if st.Priority, err = NormalizePriority(st.Priority); err != nil {
		st.Priority = ""
	}
	if st.Verdict != "" && !ValidVerdict(st.Verdict) {
		st.Verdict, st.CheckedAt, st.Summary, st.Earlier = "", time.Time{}, "", false
	}
	if !utf8.ValidString(st.Summary) || utf8.RuneCountInString(st.Summary) > maxStandingSummaryRunes {
		return invalid("the verdict's summary is longer than %d characters", maxStandingSummaryRunes)
	}
	st.Summary = oneLine(st.Summary)
	if !validAction(st.Action) {
		st.Action = ActionNone
	}
	st.Gaps = slices.DeleteFunc(st.Gaps, func(g string) bool { return !slices.Contains(Gaps, g) })
	for _, ids := range [][]int{st.Open, st.Done, st.Failed} {
		if len(ids) > maxStandingTasks {
			return invalid("a standing names at most %d tasks of each kind", maxStandingTasks)
		}
		for _, id := range ids {
			if id <= 0 {
				return invalid("%d is not a task", id)
			}
		}
	}
	return nil
}

// MergeStandings is the standings a run's own database knows, laid over
// facts — the ones its seed carried from the hub. A requirement checked here
// since the seed was made (the requirements gate checks where the run is)
// takes this verdict; everything else about it is the seed's, which knows when
// the hub last changed it — a seeded copy is written when the seed arrives,
// and its own times say only that. One the facts leave out was cut from the
// seed to fit, and its copy here — a contract's, with no check — says nothing
// of where it stands: it is left out too, and counted in unknown.
func MergeStandings(facts, local []Standing) (merged []Standing, unknown int) {
	byID := make(map[int]int, len(facts))
	merged = make([]Standing, 0, len(facts))
	for _, f := range facts {
		byID[f.ID] = len(merged)
		merged = append(merged, f)
	}
	for _, l := range local {
		i, ok := byID[l.ID]
		if !ok {
			unknown++
			continue
		}
		f := &merged[i]
		if l.Verdict != "" && l.CheckedAt.After(f.CheckedAt) {
			f.Verdict, f.CheckedAt, f.Summary, f.Earlier = l.Verdict, l.CheckedAt, l.Summary, l.Earlier
		}
		if l.HeldAt.After(f.HeldAt) {
			f.HeldAt = l.HeldAt
		}
	}
	sortStandings(merged)
	return merged, unknown
}

// Count tallies a summary for the line that opens its section.
func (s StatusSummary) count() (fulfilled, unfulfilled, never, stale, untested, unlinked int) {
	for _, st := range s.Requirements {
		switch {
		case slices.Contains(st.Gaps, GapUnfulfilled):
			unfulfilled++
		case st.Verdict == "":
			never++
		case st.Verdict == VerdictFulfilled && !st.Earlier:
			fulfilled++
		}
		if slices.Contains(st.Gaps, GapStale) {
			stale++
		}
		if !st.Tested {
			untested++
		}
		if slices.Contains(st.Gaps, GapUnlinked) {
			unlinked++
		}
	}
	return
}

// maxSectionTargets bounds the open gaps a section lists one per line; the
// rest are counted.
const maxSectionTargets = 60

// Section is the summary as a prompt states it: the facts, for the caller to
// add what it asks of them. Empty when the project has no approved
// requirement.
func (s StatusSummary) Section() string {
	if s.Empty() {
		return ""
	}
	var b strings.Builder
	b.WriteString("## REQUIREMENTS — WHERE THE PROJECT'S SPEC STANDS\n")
	b.WriteString("The approved requirements are what the project must do and keep doing. Drafts nobody has\n" +
		"approved and deprecated requirements are not part of the spec, and are left out.\n")
	total := len(s.Requirements) + s.Omitted
	ful, unf, never, stale, untested, unlinked := s.count()
	fmt.Fprintf(&b, "%d approved: %d fulfilled, %d unfulfilled, %d never checked, %d stale, %d without a test, "+
		"%d implemented by no task.", total, ful, unf, never, stale, untested, unlinked)
	if s.Omitted > 0 {
		fmt.Fprintf(&b, " (%d of them are not listed here: the least pressing.)", s.Omitted)
	}
	b.WriteString("\n")

	targets := s.Targets()
	if len(targets) > 0 {
		b.WriteString("\nOpen gaps, most important first — no open task closes them yet:\n")
		for i, st := range targets {
			if i == maxSectionTargets {
				fmt.Fprintf(&b, "- and %d more open gaps.\n", len(targets)-i)
				break
			}
			b.WriteString(standingLine(st))
		}
	} else {
		b.WriteString("\nNo open gaps: every approved requirement holds, is being worked on, or waits for a check or a person.\n")
	}
	groups := []struct {
		action, head string
	}{
		{ActionCovered, "Being worked on — an open task implements it; plan nothing more for these"},
		{ActionCheck, "Waiting for a check, not a task — work on it finished, or tasks finished, since its verdict"},
		{ActionAttachTest, "Waiting for a person to give it the test a finished task wrote"},
		{ActionStuck, "Waiting for a person — a task meant to close it failed or was skipped, or is done while it still fails"},
	}
	for _, g := range groups {
		var keys []string
		for _, st := range s.Requirements {
			if st.Action != g.action {
				continue
			}
			k := st.Key()
			switch g.action {
			case ActionCovered:
				k += " (" + taskList(st.Open) + ")"
			case ActionStuck:
				if len(st.Failed) > 0 {
					k += " (" + taskList(st.Failed) + " failed or skipped)"
				} else if len(st.Done) > 0 {
					k += " (" + taskList(st.Done) + " done)"
				}
			}
			keys = append(keys, k)
		}
		if len(keys) > 0 {
			fmt.Fprintf(&b, "%s: %s.\n", g.head, strings.Join(keys, ", "))
		}
	}
	b.WriteString("\n")
	return b.String()
}

// standingLine is one open gap as a section lists it.
func standingLine(st Standing) string {
	var b strings.Builder
	fmt.Fprintf(&b, "- %s", st.Key())
	if st.Priority != "" {
		fmt.Fprintf(&b, " [%s]", st.Priority)
	}
	fmt.Fprintf(&b, " %s — %s", st.Title, describeGaps(st))
	fmt.Fprintf(&b, ". To close it: %s.\n", ActionPhrase(st.Action))
	return b.String()
}

// describeGaps says what is open about st, in words.
func describeGaps(st Standing) string {
	var parts []string
	for _, g := range st.Gaps {
		switch g {
		case GapUnfulfilled:
			p := "unfulfilled"
			if st.Verdict == VerdictError {
				p = "its check could not run"
			}
			if st.Summary != "" {
				p += " (" + st.Summary + ")"
			}
			parts = append(parts, p)
		case GapStale:
			if st.Earlier {
				parts = append(parts, "changed since it was last checked")
			} else {
				parts = append(parts, "tasks finished since its last check")
			}
		case GapUntested:
			parts = append(parts, "no test")
		case GapUnlinked:
			parts = append(parts, "no task implements it")
		case GapUnchecked:
			parts = append(parts, "never checked")
		}
	}
	if st.Verdict == VerdictFulfilled && !st.Earlier && !st.Tested {
		parts = append(parts, "it holds by the model's or a person's word")
	}
	if len(parts) == 0 {
		return "holds"
	}
	return strings.Join(parts, "; ")
}

// ActionPhrase says what closing a gap takes, for a prompt or a person.
func ActionPhrase(action string) string {
	switch action {
	case ActionFix:
		return "a task that restores it"
	case ActionImplement:
		return "a task that implements it, with a test if it has none"
	case ActionVerify:
		return "a task that verifies it against the current code and restores it if it no longer holds"
	case ActionTest:
		return "a task that only adds its test: it is believed to hold"
	case ActionCovered:
		return "nothing: an open task implements it"
	case ActionCheck:
		return "a check of its tests, not a task"
	case ActionAttachTest:
		return "a person attaching the test a finished task wrote"
	case ActionStuck:
		return "a person: a task meant to close it did not"
	}
	return "nothing: it holds"
}

func taskList(ids []int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("#%d", id)
	}
	return strings.Join(parts, ", ")
}
