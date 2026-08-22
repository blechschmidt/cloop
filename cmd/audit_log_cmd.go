package cmd

// `cloop audit-log` — the compliance-facing view of the audit trail
// (Task 20167).
//
// Three commands that already existed in some form under `cloop events` are
// reachable here under the name an auditor would look for, and one that did
// not exist at all is the reason this command is worth having:
//
//	audit-log list     filtered read of the trail
//	audit-log verify   hash-chain integrity check
//	audit-log export   ship the trail to a SIEM  ← the new capability
//
// The name is deliberately not `audit`: that is the security *scanner*
// (cmd/audit.go), which checks config and file permissions and has nothing to
// do with the event journal. Two different questions — "is this deployment
// configured safely" versus "who did what" — should not share a verb.
//
// `cloop events` remains the developer-facing view (tail --follow, replay
// into a fresh database). This command shares its filter parsing and printer
// rather than reimplementing them, so the two can never disagree about what
// `--since 2h` means.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/auditexport"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var auditLogCmd = &cobra.Command{
	Use:   "audit-log",
	Short: "Read, verify, and export the tamper-evident audit trail",
	Long: `cloop audit-log is the compliance view of the append-only, hash-chained
record of every state mutation: task changes, config writes, authorization
decisions, credential leases, egress grants, and executor fleet changes.

Distinct from 'cloop audit', which is a security scanner for config and file
permissions, and from 'cloop events', which is the developer-facing tail and
replay tool over the same table.

Subcommands:
  list                       Filtered read of the trail
  verify                     Validate the SHA-256 hash chain (tamper detection)
  export --format jsonl|csv|cef   Ship the trail to a SIEM or an auditor

Examples:
  cloop audit-log list --actor alice@example.com --since 7d
  cloop audit-log verify
  cloop audit-log export --format cef --since 24h --output /var/log/cloop.cef`,
}

// ── list ────────────────────────────────────────────────────────────────────

var (
	auditLogListActor    string
	auditLogListEntity   string
	auditLogListEntityID string
	auditLogListType     string
	auditLogListSearch   string
	auditLogListSince    string
	auditLogListUntil    string
	auditLogListLimit    int
	auditLogListOffset   int
	auditLogListOrder    string
	auditLogListJSON     bool
	auditLogListNoColor  bool
)

var auditLogListCmd = &cobra.Command{
	Use:   "list",
	Short: "List audit events with filtering",
	RunE: func(cmd *cobra.Command, args []string) error {
		log, err := openAuditLog()
		if err != nil {
			return err
		}
		defer log.Close()

		f, err := auditLogFilter(auditLogFilterFlags{
			actor:    auditLogListActor,
			entity:   auditLogListEntity,
			entityID: auditLogListEntityID,
			evType:   auditLogListType,
			search:   auditLogListSearch,
			since:    auditLogListSince,
			until:    auditLogListUntil,
			limit:    auditLogListLimit,
			offset:   auditLogListOffset,
			order:    auditLogListOrder,
		})
		if err != nil {
			return err
		}

		rows, total, err := log.List(f)
		if err != nil {
			return err
		}

		if auditLogListJSON {
			return auditexport.Write(os.Stdout, rows, auditexport.Options{
				Format: auditexport.FormatJSONL,
			})
		}
		printer := newEventPrinter(false, auditLogListNoColor)
		for _, r := range rows {
			printer.print(r)
		}
		printer.dim.Fprintf(os.Stderr, "\n%d shown / %d total\n", len(rows), total)
		return nil
	},
}

// ── verify ──────────────────────────────────────────────────────────────────

var auditLogVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Validate the SHA-256 hash chain (tamper detection)",
	Long: `Recompute every row hash from the genesis row forward and compare it to
what is stored. Any edit, deletion, or insertion made behind cloop's back
breaks the chain at the first affected row.

Exit codes:
  0  chain intact
  2  chain broken (the break is described on stdout)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		log, err := openAuditLog()
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
		color.New(color.FgRed, color.Bold).Printf(
			"CHAIN BROKEN at id=%d after %d verified events\n", report.BreakAtID, report.Total-1)
		fmt.Printf("  reason: %s\n", report.Reason)
		// Exit 2 rather than returning an error: a broken chain is a
		// successful detection, not a failure to run. Returning an error
		// would print cobra's usage text over the finding.
		os.Exit(2)
		return nil
	},
}

// ── export ──────────────────────────────────────────────────────────────────

var (
	auditLogExportFormat   string
	auditLogExportOutput   string
	auditLogExportActor    string
	auditLogExportEntity   string
	auditLogExportEntityID string
	auditLogExportType     string
	auditLogExportSince    string
	auditLogExportUntil    string
	auditLogExportLimit    int
	auditLogExportVerify   bool
)

var auditLogExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export the audit trail as jsonl, csv, or cef",
	Long: `Serialise the audit trail for a SIEM or an external auditor.

Formats:
  jsonl  one JSON object per line — lossless, keeps the payload structured
  csv    a flat table for a spreadsheet
  cef    ArcSight Common Event Format, for syslog-based SIEM ingestion

Every format carries prev_hash and row_hash, so a recipient can re-verify the
chain against the export rather than trusting it.

Examples:
  cloop audit-log export --format cef --since 24h
  cloop audit-log export --format csv --output trail.csv
  cloop audit-log export --format jsonl --actor alice@example.com --verify`,
	RunE: func(cmd *cobra.Command, args []string) error {
		format, err := auditexport.ParseFormat(auditLogExportFormat)
		if err != nil {
			return fmt.Errorf("--format: %w", err)
		}

		log, err := openAuditLog()
		if err != nil {
			return err
		}
		defer log.Close()

		// Verify before exporting when asked. An export of a tampered trail
		// is worse than no export: it launders a broken chain into a clean
		// looking feed, and the SIEM has no way to know.
		if auditLogExportVerify {
			report, verr := log.Verify()
			if verr != nil {
				return fmt.Errorf("verify before export: %w", verr)
			}
			if !report.OK {
				return fmt.Errorf("refusing to export a broken chain: break at id=%d (%s) — "+
					"re-run without --verify to export anyway", report.BreakAtID, report.Reason)
			}
		}

		f, err := auditLogFilter(auditLogFilterFlags{
			actor:    auditLogExportActor,
			entity:   auditLogExportEntity,
			entityID: auditLogExportEntityID,
			evType:   auditLogExportType,
			since:    auditLogExportSince,
			until:    auditLogExportUntil,
			limit:    auditLogExportLimit,
			// Exports are read in causal order: a chain is only checkable
			// forwards, and a SIEM ingesting newest-first would report
			// effects before causes.
			order: "asc",
		})
		if err != nil {
			return err
		}

		rows, _, err := log.List(f)
		if err != nil {
			return err
		}

		out := os.Stdout
		if path := strings.TrimSpace(auditLogExportOutput); path != "" {
			if dir := filepath.Dir(path); dir != "" && dir != "." {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return fmt.Errorf("create output directory: %w", err)
				}
			}
			// 0600: the trail names who holds which credential and which
			// hosts an executor may reach. It is not secret material, but it
			// is a map of the deployment.
			file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return fmt.Errorf("open output file: %w", err)
			}
			defer file.Close()
			out = file
		}

		if err := auditexport.Write(out, rows, auditexport.Options{
			Format:         format,
			ProductVersion: Version,
		}); err != nil {
			return err
		}

		// Progress goes to stderr so `cloop audit-log export | logger` stays
		// a clean stream.
		sum := auditexport.Summarize(rows, format)
		dim := color.New(color.Faint)
		if auditLogExportOutput != "" {
			dim.Fprintf(os.Stderr, "wrote %d events (%s) to %s\n", sum.Events, sum.Format, auditLogExportOutput)
		} else {
			dim.Fprintf(os.Stderr, "wrote %d events (%s)\n", sum.Events, sum.Format)
		}
		if sum.Events > 0 {
			dim.Fprintf(os.Stderr, "  ids %d–%d, %d actors, %d event types\n",
				sum.FirstID, sum.LastID, len(sum.Actors), len(sum.EventTypes))
		}
		return nil
	},
}

// ── shared helpers ──────────────────────────────────────────────────────────

// openAuditLog resolves the working directory and opens the trail, turning
// the "no project here" case into advice rather than a stat error.
func openAuditLog() (*eventlog.Log, error) {
	workdir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve working directory: %w", err)
	}
	log, err := eventlog.Open(workdir)
	if err != nil {
		if err == eventlog.ErrNoProject {
			return nil, fmt.Errorf("no cloop project in %s — run 'cloop init' first", workdir)
		}
		return nil, err
	}
	return log, nil
}

// auditLogFilterFlags is the raw, unparsed flag set shared by list and
// export. Keeping it one struct means the two commands cannot drift in how
// they interpret the same flag names.
type auditLogFilterFlags struct {
	actor    string
	entity   string
	entityID string
	evType   string
	search   string
	since    string
	until    string
	limit    int
	offset   int
	order    string
}

// auditLogFilter parses flag values into a storage filter, reusing
// parseTimeFlag from cmd/events_cmd.go so --since accepts the same RFC3339 /
// YYYY-MM-DD / 30m-2h-7d forms everywhere in the CLI.
func auditLogFilter(in auditLogFilterFlags) (eventlog.AuditFilter, error) {
	f := eventlog.AuditFilter{
		Actor:      strings.TrimSpace(in.actor),
		EntityType: strings.TrimSpace(in.entity),
		EntityID:   strings.TrimSpace(in.entityID),
		EventType:  strings.TrimSpace(in.evType),
		Search:     in.search,
		Limit:      in.limit,
		Offset:     in.offset,
		Order:      in.order,
	}
	if s := strings.TrimSpace(in.since); s != "" {
		ts, err := parseTimeFlag(s)
		if err != nil {
			return f, fmt.Errorf("--since: %w", err)
		}
		f.Since = ts
	}
	if s := strings.TrimSpace(in.until); s != "" {
		ts, err := parseTimeFlag(s)
		if err != nil {
			return f, fmt.Errorf("--until: %w", err)
		}
		f.Until = ts
	}
	return f, nil
}

func init() {
	auditLogListCmd.Flags().StringVar(&auditLogListActor, "actor", "", "Filter by actor (exact match)")
	auditLogListCmd.Flags().StringVar(&auditLogListEntity, "entity", "", "Filter by entity_type (task, plan, config, secret, executor, permission)")
	auditLogListCmd.Flags().StringVar(&auditLogListEntityID, "entity-id", "", "Filter by entity_id within --entity")
	auditLogListCmd.Flags().StringVar(&auditLogListType, "type", "", "Filter by event_type (exact match)")
	auditLogListCmd.Flags().StringVar(&auditLogListSearch, "search", "", "Case-insensitive substring match on the payload")
	auditLogListCmd.Flags().StringVar(&auditLogListSince, "since", "", "Events at/after RFC3339, YYYY-MM-DD, or 30m/2h/7d")
	auditLogListCmd.Flags().StringVar(&auditLogListUntil, "until", "", "Events at/before RFC3339, YYYY-MM-DD, or 30m/2h/7d")
	auditLogListCmd.Flags().IntVar(&auditLogListLimit, "limit", 100, "Page size")
	auditLogListCmd.Flags().IntVar(&auditLogListOffset, "offset", 0, "Skip the first N matching rows")
	auditLogListCmd.Flags().StringVar(&auditLogListOrder, "order", "desc", "Sort by id: asc or desc")
	auditLogListCmd.Flags().BoolVar(&auditLogListJSON, "json", false, "Emit JSONL instead of the coloured table")
	auditLogListCmd.Flags().BoolVar(&auditLogListNoColor, "no-color", false, "Disable coloured output")

	auditLogExportCmd.Flags().StringVar(&auditLogExportFormat, "format", "jsonl", "Output format: jsonl, csv, or cef")
	auditLogExportCmd.Flags().StringVarP(&auditLogExportOutput, "output", "o", "", "Write to this file instead of stdout")
	auditLogExportCmd.Flags().StringVar(&auditLogExportActor, "actor", "", "Filter by actor (exact match)")
	auditLogExportCmd.Flags().StringVar(&auditLogExportEntity, "entity", "", "Filter by entity_type")
	auditLogExportCmd.Flags().StringVar(&auditLogExportEntityID, "entity-id", "", "Filter by entity_id within --entity")
	auditLogExportCmd.Flags().StringVar(&auditLogExportType, "type", "", "Filter by event_type (exact match)")
	auditLogExportCmd.Flags().StringVar(&auditLogExportSince, "since", "", "Events at/after RFC3339, YYYY-MM-DD, or 30m/2h/7d")
	auditLogExportCmd.Flags().StringVar(&auditLogExportUntil, "until", "", "Events at/before RFC3339, YYYY-MM-DD, or 30m/2h/7d")
	auditLogExportCmd.Flags().IntVar(&auditLogExportLimit, "limit", 0, "Cap the number of exported events (0 = no cap)")
	auditLogExportCmd.Flags().BoolVar(&auditLogExportVerify, "verify", false, "Verify the hash chain first and refuse to export if it is broken")

	auditLogCmd.AddCommand(auditLogListCmd, auditLogVerifyCmd, auditLogExportCmd)
	rootCmd.AddCommand(auditLogCmd)
}
