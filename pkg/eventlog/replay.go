// Replay reconstructs database state from an audit log (Task 20119).
//
// Walking the chain from id 1 to head and re-applying each row's payload to
// a fresh database produces a clone of the source as of the most recent
// audit row. Limitation: step.append rows do NOT carry the raw provider
// output — that field can be megabytes per row and would balloon the audit
// log. The replay therefore restores step *metadata* (task, exit_code,
// duration, time, token counts) but not the textual output. For full
// disaster recovery of step content, also restore from a backup snapshot.

package eventlog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ReplayOptions controls Replay behaviour.
type ReplayOptions struct {
	FromID  int64               // 0 or 1 = entire history; >1 = only events with id >= FromID
	OnEvent func(ev AuditEvent) // optional per-event callback (e.g. progress)
	StopAt  int64               // 0 = no upper bound; otherwise stop after id == StopAt

	// AllowTruncated permits a replay that starts after a retention prune
	// (Task 20218).
	//
	// Replay rebuilds state by applying every mutation in order, so it is only
	// complete if it starts at the first one. Once a prefix has been pruned,
	// the rows before the boundary live in a sealed archive and not in this
	// database — a replay from "the beginning" would quietly produce a partial
	// database that looks whole. Refusing is the safe default; this opts into
	// the partial rebuild deliberately, which is the right call when the tail
	// is all the operator wanted.
	AllowTruncated bool
}

// ReplayReport summarises what Replay applied.
type ReplayReport struct {
	DestPath     string
	EventsRead   int
	TasksWritten int
	StepsWritten int
	ConfigWrites int
	Skipped      int
	BreakAtID    int64 // first id whose payload could not be applied (0 = none)
	BreakReason  string
	StartedAt    time.Time
	FinishedAt   time.Time

	// Truncated reports that a retention prune removed events older than the
	// replay's starting point, so the rebuild is of the surviving tail rather
	// than of the whole history. Set only when the caller passed
	// AllowTruncated; without it a truncated trail is an error.
	Truncated          bool
	TruncatedThroughID int64
	ArchivePath        string
}

// Replay reads audit events from the source workdir and applies them to a
// fresh SQLite database at destPath. The destination is created if missing;
// if it already exists Replay returns an error rather than overwriting —
// the operator should remove or rename it first.
//
// Replay disables audit emission on the destination DB so the rebuild does
// not append a second copy of the events to the new audit log. The hash
// chain in the destination therefore restarts empty; if the operator wants
// to preserve the chain they can copy the audit_events table separately.
func Replay(ctx context.Context, srcWorkDir, destPath string, opts ReplayOptions) (*ReplayReport, error) {
	if destPath == "" {
		return nil, fmt.Errorf("replay: empty destPath")
	}
	if _, err := os.Stat(destPath); err == nil {
		return nil, fmt.Errorf("replay: destination already exists at %s — remove or rename it first", destPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("replay: stat %s: %w", destPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return nil, fmt.Errorf("replay: mkdir %s: %w", filepath.Dir(destPath), err)
	}

	src, err := Open(srcWorkDir)
	if err != nil {
		return nil, fmt.Errorf("replay open src: %w", err)
	}
	defer src.Close()

	from := opts.FromID
	if from < 1 {
		from = 1
	}

	// A pruned trail cannot be replayed from the beginning: the beginning is
	// in a sealed archive. Decide this before creating the destination, so a
	// refusal leaves nothing behind — Replay requires destPath not to exist,
	// so a half-made file would make the corrected re-run fail too.
	var (
		truncated    bool
		truncThrough int64
		archivePath  string
	)
	anchor, aerr := src.DB().LatestAuditAnchor()
	switch {
	case aerr == nil && from <= anchor.PrunedThroughID:
		if !opts.AllowTruncated {
			return nil, fmt.Errorf(
				"replay: events %d–%d were pruned by retention on %s and are archived at %s — "+
					"replay from id %d would rebuild only the surviving tail; "+
					"re-run with --allow-truncated to accept that, or restore the archive first",
				anchor.PrunedFirstID, anchor.PrunedThroughID,
				anchor.CreatedAt.Format(time.RFC3339), anchor.ExportPath, from)
		}
		truncated = true
		truncThrough = anchor.PrunedThroughID
		archivePath = anchor.ExportPath
	case aerr != nil && !errors.Is(aerr, statedb.ErrAuditAnchorNotFound):
		return nil, fmt.Errorf("replay: read retention anchor: %w", aerr)
	}

	dst, err := statedb.Open(destPath)
	if err != nil {
		return nil, fmt.Errorf("replay open dst: %w", err)
	}
	defer dst.Close()

	// Suppress audit emission on the destination so we don't pollute the
	// rebuilt DB's own audit log. Restored at function exit. We assume the
	// caller had it enabled (the default); flipping back to true is the
	// safe choice if the caller had also disabled it for unrelated reasons,
	// they'll re-disable after Replay returns.
	statedb.SetAuditEnabled(false)
	defer statedb.SetAuditEnabled(true)

	report := &ReplayReport{
		DestPath:           destPath,
		StartedAt:          time.Now(),
		Truncated:          truncated,
		TruncatedThroughID: truncThrough,
		ArchivePath:        archivePath,
	}

	// Stream events in id-ascending order via Tail with Follow=false. We do
	// the streaming here rather than ListAuditEvents because the log can be
	// arbitrarily long and we don't want to materialise it all in memory.
	out := make(chan AuditEvent, 64)
	tailErrCh := make(chan error, 1)
	go func() {
		tailErrCh <- src.Tail(ctx, TailOptions{
			FromID: from,
			Follow: false,
			Filter: AuditFilter{},
		}, out)
	}()

loop:
	for {
		select {
		case <-ctx.Done():
			report.FinishedAt = time.Now()
			return report, ctx.Err()
		case ev, ok := <-out:
			if !ok {
				break loop
			}
			report.EventsRead++
			if opts.OnEvent != nil {
				opts.OnEvent(ev)
			}
			if err := applyEvent(dst, ev, report); err != nil {
				report.BreakAtID = ev.ID
				report.BreakReason = err.Error()
				// Stop on first failure; the operator decides whether to
				// continue past a broken row.
				report.FinishedAt = time.Now()
				return report, fmt.Errorf("replay event id=%d type=%s: %w", ev.ID, ev.EventType, err)
			}
			if opts.StopAt > 0 && ev.ID >= opts.StopAt {
				break loop
			}
		}
	}

	if err := <-tailErrCh; err != nil && !errors.Is(err, context.Canceled) {
		report.FinishedAt = time.Now()
		return report, fmt.Errorf("replay tail: %w", err)
	}
	report.FinishedAt = time.Now()
	return report, nil
}

// applyEvent re-creates the mutation described by one audit row in dst.
func applyEvent(dst *statedb.DB, ev AuditEvent, report *ReplayReport) error {
	switch ev.EventType {
	case "task.upsert":
		var t pm.Task
		if err := json.Unmarshal([]byte(ev.Payload), &t); err != nil {
			return fmt.Errorf("decode task payload: %w", err)
		}
		if err := dst.UpsertTask(&t); err != nil {
			return fmt.Errorf("upsert task %d: %w", t.ID, err)
		}
		report.TasksWritten++

	case "task.delete":
		var p struct {
			ID int `json:"id"`
		}
		if err := json.Unmarshal([]byte(ev.Payload), &p); err != nil {
			return fmt.Errorf("decode delete payload: %w", err)
		}
		if err := dst.DeleteTask(p.ID); err != nil {
			return fmt.Errorf("delete task %d: %w", p.ID, err)
		}

	case "task.status":
		// Informational; the eventual task.upsert that follows carries the new
		// status. Skipped on replay to avoid re-applying an out-of-order flip.
		report.Skipped++

	case "step.append":
		var p struct {
			Step         int       `json:"step"`
			Task         string    `json:"task"`
			ExitCode     int       `json:"exit_code"`
			Duration     string    `json:"duration"`
			Time         time.Time `json:"time"`
			InputTokens  int       `json:"input_tokens"`
			OutputTokens int       `json:"output_tokens"`
		}
		if err := json.Unmarshal([]byte(ev.Payload), &p); err != nil {
			return fmt.Errorf("decode step payload: %w", err)
		}
		row := statedb.StepRow{
			Step:         p.Step,
			Task:         p.Task,
			ExitCode:     p.ExitCode,
			Duration:     p.Duration,
			Time:         p.Time,
			InputTokens:  p.InputTokens,
			OutputTokens: p.OutputTokens,
			// Output deliberately empty — see package doc.
		}
		if err := dst.AppendStep(row); err != nil {
			return fmt.Errorf("append step %d: %w", row.Step, err)
		}
		report.StepsWritten++

	case "config.set":
		var p struct {
			YAML string `json:"yaml"`
		}
		if err := json.Unmarshal([]byte(ev.Payload), &p); err != nil {
			return fmt.Errorf("decode config payload: %w", err)
		}
		if err := dst.SetConfigBlob(p.YAML); err != nil {
			return fmt.Errorf("set config: %w", err)
		}
		report.ConfigWrites++

	case "state.save":
		// state.save is a snapshot summary, not a mutation. We could project
		// some fields into metadata, but the per-task and per-step events
		// already carry the authoritative state. Skip on replay.
		report.Skipped++

	default:
		// Unknown event types are silently skipped. The chain remains intact
		// so verify still works; the replay is just incomplete.
		report.Skipped++
	}
	return nil
}
