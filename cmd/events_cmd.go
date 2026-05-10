package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// eventsCmd is the parent for forensic audit-log subcommands. Distinct from
// `cloop log` (raw stdout history) and `cloop audit` (security scan): this
// one is the hash-chained mutation journal.
var eventsCmd = &cobra.Command{
	Use:   "events",
	Short: "Inspect, replay, and verify the forensic audit log",
	Long: `cloop events inspects the append-only, hash-chained audit log of every
state mutation (task changes, plan updates, config writes, step appends).

Subcommands:
  tail [--follow]            Stream events latest-first
  replay --to <db>           Rebuild a database from the audit log alone
  verify                     Validate the SHA-256 hash chain (tamper detection)
  list                       Show recent events with rich filters
`,
}

var (
	eventsTailFollow  bool
	eventsTailFromID  int64
	eventsTailFilter  string
	eventsTailEntity  string
	eventsTailActor   string
	eventsTailLimit   int
	eventsTailJSON    bool
	eventsTailNoColor bool
)

var eventsTailCmd = &cobra.Command{
	Use:   "tail",
	Short: "Stream the audit log; with --follow, keep streaming new events",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		log, err := eventlog.Open(workdir)
		if err != nil {
			return err
		}
		defer log.Close()

		// SIGINT/SIGTERM cancels the stream cleanly.
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		out := make(chan eventlog.AuditEvent, 16)
		// Without --follow, default the start cursor to "tail" — show only
		// the last N events, like `tail -n N`. With --follow we still respect
		// FromID so an operator can resume from a known cursor.
		fromID := eventsTailFromID
		if fromID <= 0 && !eventsTailFollow {
			max, err := log.MaxID()
			if err != nil {
				return err
			}
			limit := eventsTailLimit
			if limit <= 0 {
				limit = 50
			}
			fromID = max - int64(limit) + 1
			if fromID < 1 {
				fromID = 1
			}
		}
		if fromID < 1 {
			fromID = 1
		}

		opts := eventlog.TailOptions{
			FromID: fromID,
			Follow: eventsTailFollow,
			Filter: eventlog.AuditFilter{
				Actor:      eventsTailActor,
				EntityType: eventsTailEntity,
				EventType:  eventsTailFilter,
			},
		}

		errCh := make(chan error, 1)
		go func() { errCh <- log.Tail(ctx, opts, out) }()

		printer := newEventPrinter(eventsTailJSON, eventsTailNoColor)
		for ev := range out {
			printer.print(ev)
		}
		err = <-errCh
		if errors.Is(err, context.Canceled) || err == nil {
			return nil
		}
		return err
	},
}

var (
	eventsListLimit    int
	eventsListOffset   int
	eventsListEntity   string
	eventsListEntityID string
	eventsListActor    string
	eventsListType     string
	eventsListSince    string
	eventsListUntil    string
	eventsListSearch   string
	eventsListJSON     bool
	eventsListNoColor  bool
	eventsListOrder    string
)

var eventsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List audit events with filtering",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		log, err := eventlog.Open(workdir)
		if err != nil {
			return err
		}
		defer log.Close()

		f := eventlog.AuditFilter{
			Actor:      eventsListActor,
			EntityType: eventsListEntity,
			EntityID:   eventsListEntityID,
			EventType:  eventsListType,
			Search:     eventsListSearch,
			Limit:      eventsListLimit,
			Offset:     eventsListOffset,
			Order:      eventsListOrder,
		}
		if eventsListSince != "" {
			ts, err := parseTimeFlag(eventsListSince)
			if err != nil {
				return fmt.Errorf("--since: %w", err)
			}
			f.Since = ts
		}
		if eventsListUntil != "" {
			ts, err := parseTimeFlag(eventsListUntil)
			if err != nil {
				return fmt.Errorf("--until: %w", err)
			}
			f.Until = ts
		}

		rows, total, err := log.List(f)
		if err != nil {
			return err
		}

		if eventsListJSON {
			enc := json.NewEncoder(os.Stdout)
			for _, r := range rows {
				_ = enc.Encode(r)
			}
			return nil
		}

		printer := newEventPrinter(false, eventsListNoColor)
		for _, r := range rows {
			printer.print(r)
		}
		printer.dim.Fprintf(os.Stderr, "\n%d shown / %d total\n", len(rows), total)
		return nil
	},
}

var (
	eventsReplayTo     string
	eventsReplayFromID int64
	eventsReplayStopAt int64
	eventsReplayQuiet  bool
)

var eventsReplayCmd = &cobra.Command{
	Use:   "replay",
	Short: "Rebuild a fresh state.db by re-applying every audit event",
	Long: `Walks the audit log from --from (default 1) to head, re-applying each
recorded mutation to a fresh SQLite database at --to. The destination must
not already exist.

Limitation: step output text is NOT carried in the audit log (it would balloon
the journal). Replayed steps therefore have empty Output strings; everything
else (task list, plan goal, config blob, step metadata) is faithful.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if eventsReplayTo == "" {
			return fmt.Errorf("--to <path> is required")
		}
		workdir, _ := os.Getwd()

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		opts := eventlog.ReplayOptions{
			FromID: eventsReplayFromID,
			StopAt: eventsReplayStopAt,
		}
		if !eventsReplayQuiet {
			opts.OnEvent = func(ev eventlog.AuditEvent) {
				if ev.ID%100 == 0 {
					fmt.Fprintf(os.Stderr, "  ... id=%d type=%s\n", ev.ID, ev.EventType)
				}
			}
		}

		report, err := eventlog.Replay(ctx, workdir, eventsReplayTo, opts)
		if report != nil {
			fmt.Println()
			fmt.Println("Replay report:")
			fmt.Printf("  destination:    %s\n", report.DestPath)
			fmt.Printf("  events read:    %d\n", report.EventsRead)
			fmt.Printf("  tasks written:  %d\n", report.TasksWritten)
			fmt.Printf("  steps written:  %d\n", report.StepsWritten)
			fmt.Printf("  config writes:  %d\n", report.ConfigWrites)
			fmt.Printf("  skipped:        %d\n", report.Skipped)
			if !report.StartedAt.IsZero() && !report.FinishedAt.IsZero() {
				fmt.Printf("  duration:       %s\n", report.FinishedAt.Sub(report.StartedAt).Round(time.Millisecond))
			}
			if report.BreakAtID > 0 {
				color.New(color.FgRed, color.Bold).Printf("  break at id=%d: %s\n", report.BreakAtID, report.BreakReason)
			}
		}
		return err
	},
}

var eventsVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Validate the SHA-256 hash chain (tamper detection)",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		log, err := eventlog.Open(workdir)
		if err != nil {
			return err
		}
		defer log.Close()

		report, err := log.Verify()
		if err != nil {
			return err
		}
		if report.OK {
			color.New(color.FgGreen, color.Bold).Printf("OK — %d events verified\n", report.Total)
			return nil
		}
		color.New(color.FgRed, color.Bold).Printf("CHAIN BROKEN at id=%d after %d verified events\n", report.BreakAtID, report.Total-1)
		fmt.Printf("  reason: %s\n", report.Reason)
		os.Exit(2)
		return nil
	},
}

// parseTimeFlag accepts RFC3339 ("2026-05-10T12:00:00Z"), date-only
// ("2026-05-10"), or a relative duration ("1h", "30m", "2d").
func parseTimeFlag(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty value")
	}
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-d), nil
	}
	if strings.HasSuffix(s, "d") {
		// Allow "7d" — Go's time.ParseDuration doesn't accept days.
		var n int
		if _, err := fmt.Sscanf(s, "%dd", &n); err == nil && n > 0 {
			return time.Now().Add(-time.Duration(n) * 24 * time.Hour), nil
		}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unrecognised time format %q (try RFC3339, YYYY-MM-DD, or 30m / 2h / 7d)", s)
}

// eventPrinter is a small helper that renders events to stdout, either as
// JSON (one line per event) or coloured text.
type eventPrinter struct {
	asJSON  bool
	noColor bool
	enc     *json.Encoder
	header  *color.Color
	actor   *color.Color
	entity  *color.Color
	dim     *color.Color
}

func newEventPrinter(asJSON, noColor bool) *eventPrinter {
	p := &eventPrinter{
		asJSON:  asJSON,
		noColor: noColor,
		enc:     json.NewEncoder(os.Stdout),
		header:  color.New(color.FgCyan, color.Bold),
		actor:   color.New(color.FgMagenta),
		entity:  color.New(color.FgYellow),
		dim:     color.New(color.Faint),
	}
	if noColor {
		color.NoColor = true
	}
	return p
}

func (p *eventPrinter) print(ev eventlog.AuditEvent) {
	if p.asJSON {
		_ = p.enc.Encode(ev)
		return
	}
	ts := ev.Timestamp.Local().Format("15:04:05.000")
	fmt.Printf("[%s] ", ts)
	p.header.Printf("#%d ", ev.ID)
	p.actor.Printf("%-12s ", ev.Actor)
	fmt.Printf("%-18s ", ev.EventType)
	if ev.EntityType != "" || ev.EntityID != "" {
		p.entity.Printf("%s/%s ", ev.EntityType, ev.EntityID)
	}
	if ev.Payload != "" {
		// Fold the payload onto one line. JSON pretty-printing would break
		// terminal pagers; raw is fine because it's already escaped.
		payload := ev.Payload
		if len(payload) > 200 {
			payload = payload[:197] + "..."
		}
		p.dim.Printf("%s", payload)
	}
	fmt.Println()
}

func init() {
	eventsTailCmd.Flags().BoolVarP(&eventsTailFollow, "follow", "f", false, "Keep streaming new events as they appear")
	eventsTailCmd.Flags().Int64Var(&eventsTailFromID, "from", 0, "Start at audit event id (default: tail last N)")
	eventsTailCmd.Flags().IntVarP(&eventsTailLimit, "limit", "n", 50, "When not following, show this many trailing events")
	eventsTailCmd.Flags().StringVar(&eventsTailFilter, "type", "", "Only show events with this event_type")
	eventsTailCmd.Flags().StringVar(&eventsTailEntity, "entity", "", "Only show events for this entity_type (task, plan, config, step)")
	eventsTailCmd.Flags().StringVar(&eventsTailActor, "actor", "", "Only show events from this actor")
	eventsTailCmd.Flags().BoolVar(&eventsTailJSON, "json", false, "Emit one JSON object per line")
	eventsTailCmd.Flags().BoolVar(&eventsTailNoColor, "no-color", false, "Disable ANSI colour output")

	eventsListCmd.Flags().IntVarP(&eventsListLimit, "limit", "n", 100, "Page size")
	eventsListCmd.Flags().IntVar(&eventsListOffset, "offset", 0, "Skip the first N matching rows")
	eventsListCmd.Flags().StringVar(&eventsListEntity, "entity", "", "Filter by entity_type")
	eventsListCmd.Flags().StringVar(&eventsListEntityID, "entity-id", "", "Filter by entity_id")
	eventsListCmd.Flags().StringVar(&eventsListActor, "actor", "", "Filter by actor")
	eventsListCmd.Flags().StringVar(&eventsListType, "type", "", "Filter by event_type")
	eventsListCmd.Flags().StringVar(&eventsListSince, "since", "", "Filter to events at/after RFC3339, YYYY-MM-DD, or 30m/2h/7d")
	eventsListCmd.Flags().StringVar(&eventsListUntil, "until", "", "Filter to events at/before RFC3339, YYYY-MM-DD, or 30m/2h/7d")
	eventsListCmd.Flags().StringVar(&eventsListSearch, "search", "", "Case-insensitive substring match on payload JSON")
	eventsListCmd.Flags().StringVar(&eventsListOrder, "order", "desc", "Sort order: asc or desc (default desc)")
	eventsListCmd.Flags().BoolVar(&eventsListJSON, "json", false, "Emit one JSON object per line")
	eventsListCmd.Flags().BoolVar(&eventsListNoColor, "no-color", false, "Disable ANSI colour output")

	eventsReplayCmd.Flags().StringVar(&eventsReplayTo, "to", "", "Destination .db path (must not exist)")
	eventsReplayCmd.Flags().Int64Var(&eventsReplayFromID, "from", 1, "Replay events with id >= FROM")
	eventsReplayCmd.Flags().Int64Var(&eventsReplayStopAt, "stop-at", 0, "Stop after replaying event with this id (0 = head)")
	eventsReplayCmd.Flags().BoolVar(&eventsReplayQuiet, "quiet", false, "Suppress per-100-event progress output")

	eventsCmd.AddCommand(eventsTailCmd, eventsListCmd, eventsReplayCmd, eventsVerifyCmd)
	rootCmd.AddCommand(eventsCmd)
}
