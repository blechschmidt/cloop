package ui

// run_progress.go follows which tasks a dispatched run is working on, from the
// run's own output (Task 20391).
//
// A failover has to say which tasks a lost node was running: it fails them
// when the run used up executors.failover.max_attempts, and it quarantines a
// task two distinct nodes went down under. For a run that writes the hub's own
// plan — an executor sharing this host's filesystem — the plan's in_progress
// tasks are the answer. A run on a device works on a copy of the project and
// reports back only when it ends, which a node that died never does; the hub
// then knows nothing of what it was doing except what it printed.
//
// What it printed is precise enough. The orchestrator announces every task it
// starts and every outcome, in fixed forms it has printed for as long as remote
// executors have existed — so a device on an older build is followed too:
//
//	━━━ Task 7/12: Title ━━━                     one task starts
//	━━━ Running 3 tasks in parallel (…) ━━━       a parallel round starts …
//	   • Task 7: Title                            … with these tasks
//	✓ Task 7 complete / ✗ Task 7 failed / → Task 7 skipped / ⏱ Task 7 timed out
//	━━━ Evolve #3 — Discovering new tasks ━━━    no task is running
//
// A header starts a new round, so a task whose end line was missed — an
// outcome worded in a way this file does not know — is dropped at the next
// header rather than charged forever. The record is evidence of what a run
// said, written by a workload the hub does not trust, so it is bounded and
// only ever names task ids, which settleFailover matches against the hub's own
// plan: a run can mislead the hub only about its own project's tasks.

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	// progressHeader is a sequential task start (or a parallel round of one).
	progressHeader = regexp.MustCompile(`━━━ Task (\d{1,9})/\d+: `)
	// progressRound opens a parallel round, whose tasks follow as bullets.
	progressRound = regexp.MustCompile(`━━━ Running \d+ tasks in parallel`)
	// progressBullet names one task of a parallel round.
	progressBullet = regexp.MustCompile(`^\s*• Task (\d{1,9}): `)
	// progressQuiet is a header after which no task is running.
	progressQuiet = regexp.MustCompile(`━━━ Evolve #\d+`)
	// progressEnd is any outcome line: done, failed, skipped, timed out,
	// aborted, healed.
	progressEnd = regexp.MustCompile(`(?:✓|✗|→|⏱|⚠) Task (\d{1,9})\b`)
	// ansiEscape strips colour codes, which a run writing to a terminal
	// emits and one writing to a pipe does not.
	ansiEscape = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")
)

// maxProgressLine bounds a partial line held while waiting for its newline.
// A workload that prints megabytes without one must not be buffered whole.
const maxProgressLine = 8 << 10

// runProgress is the running-task set of one dispatched run.
type runProgress struct {
	running []int
	partial strings.Builder
	// inRound is set between a parallel round's header and the first line
	// that is not one of its bullets.
	inRound bool
}

// observe feeds one chunk of the run's output and reports whether the set of
// running tasks changed.
func (p *runProgress) observe(chunk string) bool {
	changed := false
	for {
		i := strings.IndexByte(chunk, '\n')
		if i < 0 {
			if p.partial.Len()+len(chunk) <= maxProgressLine {
				p.partial.WriteString(chunk)
			} else {
				p.partial.Reset() // unbounded line: drop it, it is not a marker
			}
			return changed
		}
		line := chunk[:i]
		chunk = chunk[i+1:]
		if p.partial.Len() > 0 {
			if p.partial.Len()+len(line) <= maxProgressLine {
				p.partial.WriteString(line)
				line = p.partial.String()
			} else {
				line = ""
			}
			p.partial.Reset()
		}
		if p.line(line) {
			changed = true
		}
	}
}

// line applies one complete line.
func (p *runProgress) line(line string) bool {
	// Every marker names a task or opens with the header rule; anything else
	// — nearly all of a run's output — costs two substring scans and ends a
	// parallel round's bullet list.
	if !strings.Contains(line, "Task") && !strings.Contains(line, "━━━") {
		p.inRound = false
		return false
	}
	if strings.IndexByte(line, 0x1b) >= 0 {
		line = ansiEscape.ReplaceAllString(line, "")
	}
	if p.inRound {
		if m := progressBullet.FindStringSubmatch(line); m != nil {
			return p.add(m[1])
		}
		p.inRound = false
	}
	switch {
	case progressRound.MatchString(line):
		p.inRound = true
		return p.reset()
	case progressQuiet.MatchString(line):
		return p.reset()
	}
	if m := progressHeader.FindStringSubmatch(line); m != nil {
		changed := p.reset()
		if p.add(m[1]) {
			changed = true
		}
		return changed
	}
	if m := progressEnd.FindStringSubmatch(line); m != nil {
		return p.remove(m[1])
	}
	return false
}

func (p *runProgress) reset() bool {
	if len(p.running) == 0 {
		return false
	}
	p.running = nil
	return true
}

func (p *runProgress) add(raw string) bool {
	id, err := strconv.Atoi(raw)
	if err != nil || id <= 0 {
		return false
	}
	for _, have := range p.running {
		if have == id {
			return false
		}
	}
	// Bounded like the column it is written to (statedb.maxRunningTasks):
	// a round larger than any worker pool is not a round.
	if len(p.running) >= 64 {
		return false
	}
	p.running = append(p.running, id)
	return true
}

func (p *runProgress) remove(raw string) bool {
	id, err := strconv.Atoi(raw)
	if err != nil {
		return false
	}
	for i, have := range p.running {
		if have == id {
			p.running = append(p.running[:i], p.running[i+1:]...)
			return true
		}
	}
	return false
}

// tasks returns a copy of the running set.
func (p *runProgress) tasks() []int {
	return append([]int(nil), p.running...)
}
