package hooks

import (
	"strings"
	"testing"
	"time"
)

func TestParseTimeout(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"", 0, false},
		{"   ", 0, false},
		{"30s", 30 * time.Second, false},
		{"5m", 5 * time.Minute, false},
		{"-1s", -1 * time.Second, false},
		{"banana", 0, true},
	}
	for _, tc := range cases {
		got, err := ParseTimeout(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseTimeout(%q) expected error, got %v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTimeout(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("ParseTimeout(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestEffectiveTimeout(t *testing.T) {
	if got := effectiveTimeout(0); got != DefaultTimeout {
		t.Errorf("zero should yield DefaultTimeout, got %v", got)
	}
	if got := effectiveTimeout(-1); got != 0 {
		t.Errorf("negative should yield 0 (no timeout), got %v", got)
	}
	if got := effectiveTimeout(2 * time.Second); got != 2*time.Second {
		t.Errorf("positive should pass through, got %v", got)
	}
}

// TestRunPreTask_TimeoutKillsHungHook is the load-bearing test: without the
// CommandContext timeout in runHook, this test would hang for the full 5
// seconds (or until the test framework times out the whole package). With the
// timeout it returns within ~200ms with an error wrapping the timeout message.
func TestRunPreTask_TimeoutKillsHungHook(t *testing.T) {
	cfg := Config{
		PreTask: "sleep 5",
		Timeout: 200 * time.Millisecond,
	}
	start := time.Now()
	err := RunPreTask(cfg, TaskContext{ID: 1, Title: "t"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected error to mention 'timed out', got: %v", err)
	}
	// The kill+drain (WaitDelay=5s) means we may take a bit longer than the
	// timeout, but we should be well under the full sleep duration.
	if elapsed > 4*time.Second {
		t.Errorf("hook took %v to terminate, expected <4s", elapsed)
	}
}

// TestRunPreTask_HappyPath ensures the timeout doesn't break normal hooks.
func TestRunPreTask_HappyPath(t *testing.T) {
	cfg := Config{
		PreTask: "true",
		Timeout: 5 * time.Second,
	}
	if err := RunPreTask(cfg, TaskContext{ID: 1, Title: "t"}); err != nil {
		t.Fatalf("happy-path hook returned error: %v", err)
	}
}

// TestRunPreTask_NonZeroExit verifies that non-zero exits surface as errors
// (not timeout errors) and are wrapped with the hook name.
func TestRunPreTask_NonZeroExit(t *testing.T) {
	cfg := Config{
		PreTask: "exit 7",
		Timeout: 5 * time.Second,
	}
	err := RunPreTask(cfg, TaskContext{ID: 1, Title: "t"})
	if err == nil {
		t.Fatal("expected non-zero exit to return error, got nil")
	}
	if strings.Contains(err.Error(), "timed out") {
		t.Errorf("non-zero exit was misreported as timeout: %v", err)
	}
	if !strings.Contains(err.Error(), "pre_task") {
		t.Errorf("expected error to identify the hook (pre_task), got: %v", err)
	}
}

// TestRunPostTask_EmptyHookIsNoop confirms that an unset hook returns nil
// without invoking sh, so adding a timeout did not regress the no-op path.
func TestRunPostTask_EmptyHookIsNoop(t *testing.T) {
	if err := RunPostTask(Config{}, TaskContext{}); err != nil {
		t.Errorf("empty hook should be a no-op, got: %v", err)
	}
	// Unwrapping shouldn't matter, but make sure we're not returning a sentinel.
	if err := RunPostTask(Config{Timeout: 1 * time.Hour}, TaskContext{}); err != nil {
		t.Errorf("empty hook with timeout set should still no-op, got: %v", err)
	}
}
