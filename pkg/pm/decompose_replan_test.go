package pm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

type decomposeMockProvider struct {
	result *provider.Result
	err    error
}

func (m *decomposeMockProvider) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	return m.result, m.err
}
func (m *decomposeMockProvider) Name() string         { return "decompose-mock" }
func (m *decomposeMockProvider) DefaultModel() string { return "mock-model" }

func TestDecompose_EmptyOutputReturnsError(t *testing.T) {
	for _, output := range []string{"", "   ", "\n\t  \n"} {
		p := &decomposeMockProvider{result: &provider.Result{Output: output}}
		plan, err := Decompose(context.Background(), p, "goal", "", "model", time.Second, "")
		if err == nil {
			t.Errorf("output=%q: expected error for empty/whitespace decompose response, got nil (plan=%v)", output, plan)
		}
		if plan != nil {
			t.Errorf("output=%q: expected nil plan on empty response, got %v", output, plan)
		}
		if err != nil && !strings.Contains(err.Error(), "empty response") {
			t.Errorf("output=%q: expected error to mention 'empty response', got %v", output, err)
		}
	}
}

func TestDecompose_NilResultReturnsError(t *testing.T) {
	p := &decomposeMockProvider{result: nil}
	plan, err := Decompose(context.Background(), p, "goal", "", "model", time.Second, "")
	if err == nil {
		t.Fatalf("expected error for nil result, got nil (plan=%v)", plan)
	}
	if plan != nil {
		t.Errorf("expected nil plan on nil result, got %v", plan)
	}
	if !strings.Contains(err.Error(), "nil result") {
		t.Errorf("expected error to mention 'nil result', got %v", err)
	}
}

func TestDecompose_ProviderErrorPropagated(t *testing.T) {
	sentinel := errors.New("upstream provider failure")
	p := &decomposeMockProvider{err: sentinel}
	plan, err := Decompose(context.Background(), p, "goal", "", "model", time.Second, "")
	if err == nil {
		t.Fatalf("expected error to propagate, got nil (plan=%v)", plan)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel, got %v", err)
	}
	if plan != nil {
		t.Errorf("expected nil plan on provider error, got %v", plan)
	}
}

func TestDecompose_ValidPlanParsed(t *testing.T) {
	json := `{"tasks":[{"id":1,"title":"first","description":"do it","priority":1}]}`
	p := &decomposeMockProvider{result: &provider.Result{Output: json}}
	plan, err := Decompose(context.Background(), p, "goal", "", "model", time.Second, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan == nil || len(plan.Tasks) != 1 {
		t.Fatalf("expected 1 task, got plan=%v", plan)
	}
	if plan.Tasks[0].Title != "first" {
		t.Errorf("expected task title 'first', got %q", plan.Tasks[0].Title)
	}
}

func TestAdaptiveReplan_EmptyOutputReturnsError(t *testing.T) {
	plan := &Plan{Tasks: []*Task{{ID: 1, Title: "old"}}}
	failedTask := &Task{ID: 1, Title: "old"}
	for _, output := range []string{"", "   ", "\n\t  \n"} {
		p := &decomposeMockProvider{result: &provider.Result{Output: output}}
		tasks, err := AdaptiveReplan(context.Background(), p, "goal", "", "model", time.Second, plan, failedTask, "reason")
		if err == nil {
			t.Errorf("output=%q: expected error for empty/whitespace replan response, got nil (tasks=%v)", output, tasks)
		}
		if tasks != nil {
			t.Errorf("output=%q: expected nil tasks on empty response, got %v", output, tasks)
		}
		if err != nil && !strings.Contains(err.Error(), "empty response") {
			t.Errorf("output=%q: expected error to mention 'empty response', got %v", output, err)
		}
	}
}

func TestAdaptiveReplan_NilResultReturnsError(t *testing.T) {
	plan := &Plan{Tasks: []*Task{{ID: 1, Title: "old"}}}
	failedTask := &Task{ID: 1, Title: "old"}
	p := &decomposeMockProvider{result: nil}
	tasks, err := AdaptiveReplan(context.Background(), p, "goal", "", "model", time.Second, plan, failedTask, "reason")
	if err == nil {
		t.Fatalf("expected error for nil result, got nil (tasks=%v)", tasks)
	}
	if tasks != nil {
		t.Errorf("expected nil tasks on nil result, got %v", tasks)
	}
	if !strings.Contains(err.Error(), "nil result") {
		t.Errorf("expected error to mention 'nil result', got %v", err)
	}
}

func TestAdaptiveReplan_ProviderErrorPropagated(t *testing.T) {
	plan := &Plan{Tasks: []*Task{{ID: 1, Title: "old"}}}
	failedTask := &Task{ID: 1, Title: "old"}
	sentinel := errors.New("upstream provider failure")
	p := &decomposeMockProvider{err: sentinel}
	tasks, err := AdaptiveReplan(context.Background(), p, "goal", "", "model", time.Second, plan, failedTask, "reason")
	if err == nil {
		t.Fatalf("expected error to propagate, got nil (tasks=%v)", tasks)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel, got %v", err)
	}
	if tasks != nil {
		t.Errorf("expected nil tasks on provider error, got %v", tasks)
	}
}
