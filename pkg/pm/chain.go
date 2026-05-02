// Package pm — chain pipeline helpers.
// BuildChainPrompt prepends the output from the previous pipeline step so the
// AI has full context when executing a chained task.
package pm

import (
	"fmt"
	"strings"
)

// BuildChainPrompt returns a formatted section that prepends the previous
// pipeline step's output to the task prompt.  The returned string is inserted
// directly into ExecuteTaskPrompt when task.ChainInput is non-empty.
func BuildChainPrompt(task *Task, previousOutput string) string {
	if previousOutput == "" {
		return ""
	}

	var b strings.Builder
	b.WriteString("## PREVIOUS STEP OUTPUT\n")
	b.WriteString(fmt.Sprintf(
		"The task immediately preceding task %d in this pipeline produced the following output.\n"+
			"Use it as input / context for your work below — do not repeat it verbatim.\n\n",
		task.ID,
	))

	// Trim very long outputs to avoid blowing the context window.
	const maxLen = 8000
	out := previousOutput
	if len(out) > maxLen {
		out = out[:maxLen] + "\n...(output truncated)"
	}
	b.WriteString("```\n")
	b.WriteString(out)
	if !strings.HasSuffix(out, "\n") {
		b.WriteByte('\n')
	}
	b.WriteString("```\n\n")

	return b.String()
}
