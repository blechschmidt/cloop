package pm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

type verifyMockProvider struct {
	result *provider.Result
	err    error
}

func (m *verifyMockProvider) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	return m.result, m.err
}
func (m *verifyMockProvider) Name() string         { return "verify-mock" }
func (m *verifyMockProvider) DefaultModel() string { return "mock-model" }

func TestVerifyTask_EmptyOutputReturnsError(t *testing.T) {
	task := &Task{ID: 1, Title: "test", Description: "do the thing"}
	for _, output := range []string{"", "   ", "\n\t  \n"} {
		p := &verifyMockProvider{result: &provider.Result{Output: output}}
		pass, err := VerifyTask(context.Background(), p, "goal", "", "model", time.Second, task, "executor output")
		if err == nil {
			t.Errorf("output=%q: expected error for empty/whitespace verifier response, got nil (pass=%v)", output, pass)
		}
		if pass {
			t.Errorf("output=%q: expected pass=false on empty response, got true", output)
		}
		if err != nil && !strings.Contains(err.Error(), "empty response") {
			t.Errorf("output=%q: expected error to mention 'empty response', got %v", output, err)
		}
	}
}

func TestVerifyTask_NilResultReturnsError(t *testing.T) {
	task := &Task{ID: 1, Title: "test", Description: "do the thing"}
	p := &verifyMockProvider{result: nil}
	pass, err := VerifyTask(context.Background(), p, "goal", "", "model", time.Second, task, "executor output")
	if err == nil {
		t.Fatalf("expected error for nil result, got nil (pass=%v)", pass)
	}
	if pass {
		t.Errorf("expected pass=false on nil result, got true")
	}
	if !strings.Contains(err.Error(), "nil result") {
		t.Errorf("expected error to mention 'nil result', got %v", err)
	}
}

func TestVerifyTask_ProviderErrorPropagated(t *testing.T) {
	task := &Task{ID: 1, Title: "test", Description: "do the thing"}
	sentinel := errors.New("upstream provider failure")
	p := &verifyMockProvider{err: sentinel}
	pass, err := VerifyTask(context.Background(), p, "goal", "", "model", time.Second, task, "executor output")
	if err == nil {
		t.Fatalf("expected error to propagate, got nil (pass=%v)", pass)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped sentinel, got %v", err)
	}
	if pass {
		t.Errorf("expected pass=false on provider error, got true")
	}
}

func TestVerifyTask_PassSignal(t *testing.T) {
	task := &Task{ID: 1, Title: "test", Description: "do the thing"}
	p := &verifyMockProvider{result: &provider.Result{Output: "Looks good.\nVERIFY_PASS"}}
	pass, err := VerifyTask(context.Background(), p, "goal", "", "model", time.Second, task, "executor output")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pass {
		t.Errorf("expected pass=true on VERIFY_PASS, got false")
	}
}

func TestVerifyTask_FailSignal(t *testing.T) {
	task := &Task{ID: 1, Title: "test", Description: "do the thing"}
	p := &verifyMockProvider{result: &provider.Result{Output: "Files missing.\nVERIFY_FAIL"}}
	pass, err := VerifyTask(context.Background(), p, "goal", "", "model", time.Second, task, "executor output")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pass {
		t.Errorf("expected pass=false on VERIFY_FAIL, got true")
	}
}

func TestVerifyTask_UnsignedResponseTreatedAsPass(t *testing.T) {
	task := &Task{ID: 1, Title: "test", Description: "do the thing"}
	p := &verifyMockProvider{result: &provider.Result{Output: "Some narrative review with no explicit signal."}}
	pass, err := VerifyTask(context.Background(), p, "goal", "", "model", time.Second, task, "executor output")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pass {
		t.Errorf("expected pass=true for unsigned non-empty response (existing semantics), got false")
	}
}
