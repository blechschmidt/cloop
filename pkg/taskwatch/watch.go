// Package taskwatch implements live streaming output tailing for a running
// cloop PM task. It polls the live artifact file written by the orchestrator
// and streams new bytes to an io.Writer, similar to `tail -f`.
package taskwatch

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/notify"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

const (
	pollInterval = 100 * time.Millisecond
)

// ExitCode encodes the terminal task status as a process exit code.
const (
	ExitDone    = 0
	ExitFailed  = 1
	ExitSkipped = 2
)

// Config controls the behaviour of Watch.
type Config struct {
	WorkDir  string
	TaskID   int
	Timeout  time.Duration // max time to wait for the task to start; default 5m
	NoNotify bool          // suppress desktop notification on completion
	Output   io.Writer     // where to stream output; defaults to os.Stdout
}

// Watch tails live output for a running task identified by cfg.TaskID.
//
// Behaviour:
//   - If the task is pending, it waits up to cfg.Timeout for it to become
//     in_progress.
//   - While the task is in_progress it streams new bytes from the live
//     artifact file every 100 ms.
//   - When the task reaches a terminal status (done/failed/skipped/timed_out)
//     it prints a final status banner, fires a desktop notification (unless
//     cfg.NoNotify is true) and returns the appropriate exit code.
//
// Returns (exitCode, error).
func Watch(ctx context.Context, cfg Config) (int, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Minute
	}
	out := cfg.Output
	if out == nil {
		out = os.Stdout
	}

	// ── Locate the task ──────────────────────────────────────────────────
	task, err := findTask(cfg.WorkDir, cfg.TaskID)
	if err != nil {
		return 1, err
	}

	// ── Wait for task to start ───────────────────────────────────────────
	if !isTerminal(task.Status) && task.Status != pm.TaskInProgress {
		fmt.Fprintf(out, "Waiting for task %d (%s) to start (timeout %s)...\n",
			task.ID, task.Title, cfg.Timeout.Round(time.Second))
		deadline := time.Now().Add(cfg.Timeout)
		for task.Status == pm.TaskPending || task.Status == "" {
			if ctx.Err() != nil {
				return 1, ctx.Err()
			}
			if time.Now().After(deadline) {
				return 1, fmt.Errorf("task %d did not start within %s", cfg.TaskID, cfg.Timeout)
			}
			time.Sleep(pollInterval)
			task, err = findTask(cfg.WorkDir, cfg.TaskID)
			if err != nil {
				return 1, err
			}
		}
	}

	// Already terminal before we started watching?
	if isTerminal(task.Status) {
		printBanner(out, task)
		if !cfg.NoNotify {
			notify.Send("cloop task watch", bannerText(task))
		}
		return exitCodeFor(task.Status), nil
	}

	// ── Stream live output ───────────────────────────────────────────────
	artifactPath := artifact.LiveArtifactPath(cfg.WorkDir, cfg.TaskID)
	var offset int64

	fmt.Fprintf(out, "Watching task %d: %s\n", task.ID, task.Title)
	fmt.Fprintln(out, "─────────────────────────────────────────────────────────────────")

	for {
		if ctx.Err() != nil {
			return 1, ctx.Err()
		}

		// Read any new bytes from the live file.
		n, readErr := streamNewBytes(out, artifactPath, &offset)
		if readErr != nil && !os.IsNotExist(readErr) {
			// Non-fatal: file may not exist yet if the provider hasn't written.
			_ = n
		}

		// Re-read state to check for terminal status.
		task, err = findTask(cfg.WorkDir, cfg.TaskID)
		if err != nil {
			return 1, err
		}

		if isTerminal(task.Status) {
			// Drain any remaining bytes before printing the banner.
			_, _ = streamNewBytes(out, artifactPath, &offset)
			fmt.Fprintln(out)
			printBanner(out, task)
			if !cfg.NoNotify {
				notify.Send("cloop task watch", bannerText(task))
			}
			return exitCodeFor(task.Status), nil
		}

		time.Sleep(pollInterval)
	}
}

// streamNewBytes reads bytes from path starting at *offset, writes them to w,
// and advances *offset by the number of bytes read.
func streamNewBytes(w io.Writer, path string, offset *int64) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if info.Size() <= *offset {
		return 0, nil
	}

	if _, err = f.Seek(*offset, io.SeekStart); err != nil {
		return 0, err
	}

	n, err := io.Copy(w, f)
	*offset += n
	return int(n), err
}

// findTask loads state and returns the task with the given ID.
func findTask(workDir string, taskID int) (*pm.Task, error) {
	s, err := state.Load(workDir)
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}
	if !s.PMMode || s.Plan == nil {
		return nil, fmt.Errorf("no task plan found (run cloop run --pm first)")
	}
	for _, t := range s.Plan.Tasks {
		if t.ID == taskID {
			return t, nil
		}
	}
	return nil, fmt.Errorf("task %d not found", taskID)
}

// isTerminal returns true for statuses that represent a final outcome.
func isTerminal(status pm.TaskStatus) bool {
	switch status {
	case pm.TaskDone, pm.TaskFailed, pm.TaskSkipped, pm.TaskTimedOut:
		return true
	}
	return false
}

// exitCodeFor maps terminal task statuses to process exit codes.
func exitCodeFor(status pm.TaskStatus) int {
	switch status {
	case pm.TaskDone:
		return ExitDone
	case pm.TaskSkipped:
		return ExitSkipped
	default: // failed, timed_out
		return ExitFailed
	}
}

// printBanner writes a final status banner to w.
func printBanner(w io.Writer, task *pm.Task) {
	fmt.Fprintln(w, "─────────────────────────────────────────────────────────────────")
	fmt.Fprintf(w, "Task %d (%s): %s\n", task.ID, task.Title, statusLabel(task.Status))
	fmt.Fprintln(w, "─────────────────────────────────────────────────────────────────")
}

// bannerText returns a one-line notification string.
func bannerText(task *pm.Task) string {
	return fmt.Sprintf("Task %d (%s): %s", task.ID, task.Title, statusLabel(task.Status))
}

func statusLabel(s pm.TaskStatus) string {
	switch s {
	case pm.TaskDone:
		return "DONE"
	case pm.TaskFailed:
		return "FAILED"
	case pm.TaskSkipped:
		return "SKIPPED"
	case pm.TaskTimedOut:
		return "TIMED OUT"
	default:
		return string(s)
	}
}
