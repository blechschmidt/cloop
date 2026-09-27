package orchestrator

// unfinished.go handles an agent that ends its turn before the task is
// finished (Task 20349).
//
// An agent that starts a test suite, a CI run or a deploy in the background
// and then says "the suite is still running; I'll commit and push once it
// reports" is behaving as it would in an interactive session, where the
// harness wakes it when the job finishes. A cloop run is not interactive:
// `claude --print` returns when the turn ends, the harness stops what the
// agent left running, and nothing ever reports back. The orchestrator then saw
// no TASK_* signal, found a summary and a diff, and promoted the task to done —
// 38 of the 55 tasks this project's own ledger recorded as implicitly
// completed ended exactly that way, and several left their work uncommitted in
// the tree for the next task to trip over.
//
// So an unsignalled turn whose final message says it is waiting is given the
// turn back — in the same conversation where the provider can resume one, so
// the agent still knows what it was waiting for — and told plainly that
// nothing will notify it. A turn that still ends that way is not accepted as
// done (AbortUnfinishedTurn).

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// maxTurnContinuations bounds how many times one task's turn is handed back.
const maxTurnContinuations = 2

// unfinishedTurnPatterns match a final message saying that the turn is ending
// with work still outstanding: first-person waiting, a monitor left armed, a
// promise to act once something reports. They were calibrated against every
// final message this project's ledger holds: they match 38 of the 55 turns
// that ended without a signal, and none of the 204 that ended with one.
var unfinishedTurnPatterns = compileUnfinishedTurnPatterns(
	`\bi(?:'ll| will| am going to|'m going to) (?:wait|hold)\b`,
	`\bi(?:'m| am) (?:waiting|holding)\b`,
	`(?:^|[.!?]\s+|\*\*)(?:still )?(?:waiting|holding) (?:on|for)\b`,
	`\b(?:monitors?|waiters?|watchers?|wakeups?) (?:is|are) (?:armed|running|watching|set)\b`,
	`\bwill (?:notify|wake|ping|alert) me\b`,
	`\bi(?:'ll| will) (?:report|pick (?:it |this |that )?up|continue|follow up|check back|resume|get back)\b[^.\n]{0,120}\b(?:when|once|after|as soon as)\b`,
	`\b(?:once|when|after|as soon as) (?:it|that|they|this|the [\w`+"`"+`./ -]{1,40}?) (?:reports?|finish(?:es)?|completes?|lands?|settles?|(?:is|are) done|comes? back)\b[^.\n]{0,80}\bi(?:'ll| will)\b`,
	`\brather than poll`,
	`\b(?:is|are|'s|'re) still (?:running|in progress|working through)\b`,
	`(?:^|[.!?]\s+|\*\*)still (?:running|in progress)\b`,
	`\b(?:hasn't|has not|haven't|have not|aren't|are not|isn't|is not) (?:registered|finished|completed|landed|reported)(?: \w+)? yet\b`,
	`\bnot (?:yet )?(?:call|declare|claim|signal)(?:ing)? (?:this |it |the task )?(?:done|complete|completion)\b`,
	`\bwon't (?:call|declare|claim) (?:this |it )?(?:done|complete|completion)\b`,
	`\bstatus while\b`,
	`\bwhile i wait\b`,
	`\bverification is (?:still )?in progress\b`,
)

func compileUnfinishedTurnPatterns(exprs ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(exprs))
	for i, e := range exprs {
		out[i] = regexp.MustCompile(`(?im)` + e)
	}
	return out
}

// negatedClause matches a negation before a "still running" in the same
// clause — "nothing of mine is still running" is a finished turn saying so.
var negatedClause = regexp.MustCompile(`(?i)\b(?:nothing|no|not|none|never|without)\b`)

// unfinishedTurnRegionBytes is how much of each end of a final message is
// read. The waiting statement leads or closes it; a long summary's middle
// describes the work, where the same words can be about the feature.
const unfinishedTurnRegionBytes = 900

// looksLikeUnfinishedTurn reports whether an agent's final message says it
// ended its turn waiting on work it had started.
func looksLikeUnfinishedTurn(output string) bool {
	_, ok := unfinishedTurnEvidence(output)
	return ok
}

// unfinishedTurnEvidence returns the phrase that shows the turn was
// unfinished, for the abort record.
func unfinishedTurnEvidence(output string) (string, bool) {
	text := strings.TrimSpace(strings.ReplaceAll(output, "’", "'"))
	if text == "" {
		return "", false
	}
	for _, region := range unfinishedTurnRegions(text) {
		for _, rx := range unfinishedTurnPatterns {
			for _, loc := range rx.FindAllStringIndex(region, -1) {
				match := region[loc[0]:loc[1]]
				if strings.Contains(strings.ToLower(match), "still") &&
					negatedClause.MatchString(region[clauseStart(region, loc[0]):loc[0]]) {
					continue
				}
				return strings.TrimSpace(strings.TrimLeft(match, ".!?* \t\n")), true
			}
		}
	}
	return "", false
}

// unfinishedTurnRegions returns the leading and trailing parts of text that
// are read, cut on rune boundaries.
func unfinishedTurnRegions(text string) []string {
	if len(text) <= 2*unfinishedTurnRegionBytes {
		return []string{text}
	}
	head := unfinishedTurnRegionBytes
	for head > 0 && !utf8.RuneStart(text[head]) {
		head--
	}
	tail := len(text) - unfinishedTurnRegionBytes
	for tail < len(text) && !utf8.RuneStart(text[tail]) {
		tail++
	}
	return []string{text[:head], text[tail:]}
}

// clauseStart returns where the clause containing pos begins.
func clauseStart(text string, pos int) int {
	start := 0
	for _, sep := range []string{".", "\n", ";", ":", "!", "?", "—"} {
		if i := strings.LastIndex(text[:pos], sep); i >= 0 && i+len(sep) > start {
			start = i + len(sep)
		}
	}
	return start
}

// continueTurnInstruction is the message that hands a turn back. It says the
// one thing an agent behaving as it would interactively does not know.
const continueTurnInstruction = "Your turn ended before the task was finished: you were waiting on work you " +
	"had started — a test run, a build, CI, a deploy or a monitor. This run is not interactive. Nothing " +
	"will notify you: ending your turn is what ends the task, and anything you left running in the " +
	"background was stopped when your turn ended, so it will not report back.\n\n" +
	"Continue the task now, in this turn:\n" +
	"- Re-run in the foreground whatever you were waiting on, and wait for it to finish.\n" +
	"- Finish the remaining steps, such as committing and pushing, and check that they worked.\n" +
	"- Do not end your turn while anything you depend on is still running.\n\n" +
	"End with TASK_DONE, TASK_FAILED or TASK_SKIPPED on the last line."

// completeTask runs a task's provider call and hands the turn back, up to
// maxTurnContinuations times, while the agent ends it waiting on its own work.
// It returns the final result, with the token counts of every turn summed,
// and how many times the turn was handed back.
//
// A provider that reports a SessionID is resumed in that conversation, so the
// agent keeps everything it knew; one that does not is re-prompted with its
// previous answer, and finds the rest in the working tree. A continuation
// that fails leaves the previous result to be judged as it stands — where
// decideUnsignalled refuses to promote an unfinished turn — except that a
// cancelled run returns the cancellation, so the caller can tell a stop from
// an outcome.
func completeTask(ctx context.Context, p provider.Provider, prompt string, opts provider.Options) (*provider.Result, int, error) {
	result, err := safeComplete(ctx, p, prompt, opts)
	continued := 0
	for err == nil && result != nil && continued < maxTurnContinuations {
		if pm.CheckTaskSignal(result.Output) != pm.TaskInProgress || !looksLikeUnfinishedTurn(result.Output) {
			break
		}
		next := opts
		var nextPrompt string
		if result.SessionID != "" {
			next.ResumeSession = result.SessionID
			nextPrompt = continueTurnInstruction
		} else {
			next.ResumeSession = ""
			nextPrompt = prompt + "\n\n--- YOUR PREVIOUS RESPONSE ---\n" + result.Output +
				"\n--- END OF PREVIOUS RESPONSE ---\n\n" + continueTurnInstruction +
				"\n\nThe working directory still holds everything that attempt changed."
		}
		continued++
		more, moreErr := safeComplete(ctx, p, nextPrompt, next)
		if moreErr != nil {
			if ctx.Err() != nil {
				return nil, continued, moreErr
			}
			break
		}
		if more == nil || strings.TrimSpace(more.Output) == "" {
			break
		}
		more.InputTokens += result.InputTokens
		more.OutputTokens += result.OutputTokens
		more.ThinkingTokens += result.ThinkingTokens
		more.Duration += result.Duration
		result = more
	}
	return result, continued, err
}

// continuedTurnNote is the task annotation recording that its turn was handed
// back, so the reader of a finished task can see it did not finish in one.
func continuedTurnNote(times int) string {
	plural := "once"
	if times > 1 {
		plural = fmt.Sprintf("%d times", times)
	}
	return fmt.Sprintf("The agent ended its turn waiting on work it had started, before the task "+
		"was finished; its turn was handed back %s (at most %d).", plural, maxTurnContinuations)
}
