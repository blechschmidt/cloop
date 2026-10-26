package chat

import (
	"reflect"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

func TestPlanSystemPromptDescribesThePlan(t *testing.T) {
	ps := &state.ProjectState{Goal: "ship it", Plan: &pm.Plan{Tasks: []*pm.Task{
		{ID: 1, Title: "Migrate", Status: pm.TaskDone, Priority: 1},
		{ID: 2, Title: "Deploy", Description: "to prod", Status: pm.TaskPending, Priority: 2, DependsOn: []int{1},
			Annotations: []pm.Annotation{{Author: "ai-blocker", Text: "waiting on review"}}},
	}}}
	p := PlanSystemPrompt(ps)
	for _, want := range []string{"**Goal:** ship it", "**Progress:** 1/2 done", "[#2] **Deploy**",
		"depends on: [1]", "  to prod", "[ai-blocker] waiting on review"} {
		if !strings.Contains(p, want) {
			t.Errorf("the prompt omits %q:\n%s", want, p)
		}
	}
	if p := PlanSystemPrompt(nil); !strings.Contains(p, "No plan is currently initialised") {
		t.Errorf("a project with no state: %q", p)
	}
}

func TestPlanConversationAndItsWindow(t *testing.T) {
	h := []PlanMessage{{"user", "first"}, {"system", "ignored"}, {"assistant", "second"}}
	if got := PlanConversation(h, "third"); got != "Human: first\n\nAssistant: second\n\nHuman: third\n\nAssistant: " {
		t.Errorf("conversation %q", got)
	}
	// The latest turns that fit, in order; a turn too big ends the window.
	long := []PlanMessage{{"user", strings.Repeat("x", 100)}, {"assistant", "ok"}, {"user", "why?"}}
	if got := RecentPlanHistory(long, 20); !reflect.DeepEqual(got, long[1:]) {
		t.Errorf("window %v, want the two latest turns", got)
	}
	if got := RecentPlanHistory(long, 1000); !reflect.DeepEqual(got, long) {
		t.Errorf("a window that fits everything dropped %v", got)
	}
	if got := RecentPlanHistory(long, 1); len(got) != 0 {
		t.Errorf("a window nothing fits kept %v", got)
	}
}
