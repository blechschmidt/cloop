package feature

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// maxPRBodyTasks bounds how many tasks a generated pull request body lists
// per section. An auto-evolving feature can accumulate hundreds; a reviewer
// needs the shape of the work, and the rest is one line saying how many more.
const maxPRBodyTasks = 60

// PRTitle is the title a feature's pull request gets when none is given.
func PRTitle(m *Meta) string {
	if m == nil {
		return ""
	}
	if t := strings.TrimSpace(m.Title); t != "" {
		return t
	}
	return m.Slug
}

// PRBody renders the description of a feature's pull request from its record
// and its task list: what the feature is for, which tasks were completed, and
// which were not — so a reviewer can tell a finished feature from one being
// proposed early without opening the dashboard.
//
// It is deterministic on purpose. The PR is opened from a button, often by
// someone other than the person reviewing it, and a description that changes
// on every click — or that needs a model call to exist at all — is a worse
// default than one that says exactly what the plan says.
func PRBody(m *Meta, tasks []*pm.Task) string {
	var b strings.Builder
	if m != nil {
		if d := strings.TrimSpace(m.Description); d != "" {
			b.WriteString(d)
			b.WriteString("\n\n")
		}
	}

	var done, open, dropped []*pm.Task
	for _, t := range tasks {
		if t == nil {
			continue
		}
		switch t.Status {
		case pm.TaskDone:
			done = append(done, t)
		case pm.TaskSkipped, pm.TaskFailed, pm.TaskTimedOut:
			dropped = append(dropped, t)
		default:
			open = append(open, t)
		}
	}

	section := func(title string, list []*pm.Task, box string) {
		if len(list) == 0 {
			return
		}
		fmt.Fprintf(&b, "## %s\n\n", title)
		for i, t := range list {
			if i == maxPRBodyTasks {
				fmt.Fprintf(&b, "- … and %d more\n", len(list)-maxPRBodyTasks)
				break
			}
			fmt.Fprintf(&b, "- [%s] #%d %s", box, t.ID, oneLine(t.Title))
			if box == " " && t.Status != "" && t.Status != pm.TaskPending {
				fmt.Fprintf(&b, " (%s)", t.Status)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	section("Completed tasks", done, "x")
	section("Not completed", open, " ")
	section("Skipped or failed", dropped, " ")
	if len(done)+len(open)+len(dropped) == 0 {
		b.WriteString("_This feature has no tasks recorded._\n\n")
	}

	b.WriteString("---\n")
	if m != nil {
		fmt.Fprintf(&b, "Opened by [cloop](https://github.com/blechschmidt/cloop) from feature `%s` "+
			"(branch `%s`, based on `%s`).\n", m.Slug, m.Branch, m.Base)
	} else {
		b.WriteString("Opened by [cloop](https://github.com/blechschmidt/cloop).\n")
	}
	return b.String()
}

// oneLine flattens a task title for a Markdown list item: a newline in a
// title would otherwise end the item and turn the rest into a paragraph.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
