package ui

// The boxes a task's description is typed into are multi-line (Task 20343).
//
// The Add Task form's was an <input>, which cannot hold a line break: a brief
// typed or pasted into it — steps, acceptance criteria, an error message —
// reached the plan as one run-on line. add_task_form_browser_test.go proves
// the replacement behaves in a browser; this is the part of that claim a
// runner without Chrome can still check.

import (
	"regexp"
	"strings"
	"testing"
)

func TestTaskDescriptionBoxesAreMultiline(t *testing.T) {
	page := loadAssets().page.contents
	for _, c := range []struct{ id, where string }{
		{"newTaskDesc", "the Tasks tab's Add Task form"},
		{"modalDesc", "the edit task dialog"},
	} {
		re := regexp.MustCompile(`<([a-zA-Z][a-zA-Z0-9]*)\b[^<>]*\bid="` + regexp.QuoteMeta(c.id) + `"`)
		m := re.FindAllStringSubmatch(page, -1)
		if len(m) != 1 {
			t.Errorf("%s: %d elements with id=%q, want 1", c.where, len(m), c.id)
			continue
		}
		if tag := strings.ToLower(m[0][1]); tag != "textarea" {
			t.Errorf("%s: the description box #%s is an <%s>, which cannot hold a line break; want a <textarea>",
				c.where, c.id, tag)
		}
	}
}
