package ui

import (
	"fmt"
	"strings"
	"testing"
)

// TestRunProgressFollowsTheOrchestratorsAnnouncements: the lines the
// orchestrator prints when it starts and ends tasks — sequential, parallel, an
// evolve round, coloured or not, split across chunks however a stream splits
// them — leave exactly the tasks still running (Task 20391).
func TestRunProgressFollowsTheOrchestratorsAnnouncements(t *testing.T) {
	steps := []struct {
		out  string
		want string
	}{
		{"Resuming plan: 3/9 done\n", "[]"},
		{"━━━ Task 7/12: Fix the parser ━━━\n       description\n\n", "[7]"},
		{"✓ Task 7 complete: Fix the parser\n\n", "[]"},
		// Coloured, as a run writing to a terminal prints it.
		{"\x1b[36m━━━ Task 8/12: Next one ━━━\x1b[0m\n", "[8]"},
		// A header ends the previous round even when its end line was missed.
		{"━━━ Task 9/12: After that ━━━  (ready=1, cap=2)\n", "[9]"},
		{"✗ Task 9 failed: After that\n", "[]"},
		{"━━━ Running 2 tasks in parallel  (ready=3, cap=2) ━━━\n   • Task 10: a\n   • Task 11: b\n", "[10 11]"},
		{"[HEAL attempt 1/3] Task 10 still failing — retrying\n", "[10 11]"},
		{"[HEAL attempt 2/3] ✓ Task 10 healed successfully (signal: done)\n", "[11]"},
		{"⏱ Task 11 timed out (30m): b\n", "[]"},
		{"━━━ Task 12/12: Last ━━━\n", "[12]"},
		{"━━━ Evolve #3 — Discovering new tasks ━━━\n", "[]"},
	}
	var p runProgress
	for i, st := range steps {
		p.observe(st.out)
		if got := fmt.Sprint(p.tasks()); got != st.want {
			t.Fatalf("step %d (%q): running = %s, want %s", i, st.out, got, st.want)
		}
	}

	// The same stream cut into arbitrary chunks reads the same.
	var whole strings.Builder
	for _, st := range steps[:3] {
		whole.WriteString(st.out)
	}
	var q runProgress
	for _, b := range []byte(whole.String()) {
		q.observe(string([]byte{b}))
	}
	if got := fmt.Sprint(q.tasks()); got != "[]" {
		t.Fatalf("byte-by-byte: running = %s, want []", got)
	}
	var r runProgress
	r.observe("━━━ Task 3/")
	if len(r.tasks()) != 0 {
		t.Fatal("half a header counted as a start")
	}
	r.observe("4: split ━━━\n")
	if got := fmt.Sprint(r.tasks()); got != "[3]" {
		t.Fatalf("a header split across chunks: running = %s, want [3]", got)
	}
}

// TestRunProgressIsBoundedAgainstAHostileRun: the output is a hostile
// workload's, so a line without end and a round naming thousands of tasks cost
// a bounded amount.
func TestRunProgressIsBoundedAgainstAHostileRun(t *testing.T) {
	var p runProgress
	p.observe(strings.Repeat("x", 1<<20))
	if p.partial.Len() > maxProgressLine {
		t.Fatalf("held %d bytes of an unterminated line", p.partial.Len())
	}
	p.observe("\n━━━ Running 999 tasks in parallel ━━━\n")
	var b strings.Builder
	for i := 1; i <= 1000; i++ {
		fmt.Fprintf(&b, "   • Task %d: x\n", i)
	}
	p.observe(b.String())
	if n := len(p.tasks()); n > 64 {
		t.Fatalf("a round recorded %d tasks", n)
	}
	// A task id too long to be one is not parsed into an overflow.
	var q runProgress
	q.observe("━━━ Task 99999999999999999999/1: overflow ━━━\n")
	if len(q.tasks()) != 0 {
		t.Fatalf("an absurd task id was recorded: %v", q.tasks())
	}
}
