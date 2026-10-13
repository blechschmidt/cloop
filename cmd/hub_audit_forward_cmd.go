package cmd

// hub_audit_forward_cmd.go: what an operator asks of audit forwarding
// (Task 20426) — where the trail goes, and how far each sink has got.
//
// The forwarder itself runs inside `cloop ui`, as the cluster leader's duty;
// this command reads what it leaves behind — the cursors in the control plane
// and the head of every chain they name — so it answers with the hub up or
// down, and from any member.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/auditforward"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/state"
)

var hubAuditForwardCmd = &cobra.Command{
	Use:   "forward",
	Short: "Show where the audit trail is forwarded as it is written, and how far each sink has got",
	Long: `Audit forwarding ships every row of every audit chain — the control plane's
and each registered project's — to the sinks in audit.forward as it is written:
syslog over TLS (RFC 5424/5425), an HTTPS endpoint (NDJSON, or Splunk HEC), or a
file kept off the database's volume. The cluster leader does it; each sink has a
cursor per chain in the control plane, advanced only once the sink acknowledges.

  cloop hub audit forward status            each sink, its backlog, lag and last error
  cloop hub audit forward status --json     the same, for a monitoring script
  cloop hub audit forward verify FILE       verify the chains in what a sink received`,
}

var hubAuditForwardVerifyJSON bool

var hubAuditForwardVerifyCmd = &cobra.Command{
	Use:   "verify FILE",
	Short: "Verify the audit chains in a stream an audit sink received",
	Long: `Verify the chains in what an audit sink received, without the hub.

FILE holds one forwarded record per line: a file sink's own file, an export
from the collector of the JSON records it was sent (HEC events are unwrapped),
or syslog lines with the record after their header. "-" reads stdin.

Every record carries its row_hash and prev_hash. Each must hash to its row_hash
and link to the record before it; delivery is at-least-once, so a repeated row
(same id, same row_hash) is counted and not reported. Reported per chain:

  gap          ids missing between the first and the last received
  fork         one id received with two different row hashes — the chain
               changed under the forwarder: a truncation the hub then wrote
               past, a restored backup, a rewrite
  bad hash     a record whose content does not hash to its row_hash
  broken link  a record whose prev_hash is not the record before it

A record sent with its payload left out (payload_truncated, for a syslog
message size) cannot have its hash recomputed; it is listed as unverified and
its links are still checked. A CEF stream cannot be verified: send JSON to the
sink whose copy you mean to check.

Exits 0 when every chain is whole and unaltered, 2 otherwise — including when
the file holds no forwarded record at all.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var in io.Reader = os.Stdin
		if args[0] != "-" {
			f, err := os.Open(args[0])
			if err != nil {
				return err
			}
			defer f.Close()
			in = f
		}
		rep, err := auditforward.VerifyStream(in)
		if err != nil {
			return err
		}
		if hubAuditForwardVerifyJSON {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			if err := enc.Encode(rep); err != nil {
				return err
			}
		} else {
			renderStreamReport(rep)
		}
		// Nothing to verify is not a verified stream: a CEF sink's file, or
		// the wrong file, would otherwise pass.
		if !rep.OK() || len(rep.Chains) == 0 {
			exitProcess(auditExitBroken)
		}
		return nil
	},
}

func renderStreamReport(rep auditforward.StreamReport) {
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	dim := color.New(color.Faint)
	if len(rep.Chains) == 0 {
		red.Println("No forwarded records found: nothing here can be verified.")
		dim.Println("  A CEF stream cannot be: its payloads are truncated. Verify a JSON sink's copy.")
	}
	for _, c := range rep.Chains {
		if c.OK() {
			green.Printf("OK      ")
		} else {
			red.Printf("BROKEN  ")
		}
		fmt.Printf("%-13s %s  ids %d…%d, %d row(s), %d repeat(s)\n", c.Source, c.Dir, c.FirstID, c.LastID, c.Rows, c.Duplicates)
		for _, g := range c.Gaps {
			fmt.Printf("  gap          ids %d…%d not received\n", g.From, g.To)
		}
		for _, id := range c.Forks {
			fmt.Printf("  fork         id %d received with two different row hashes\n", id)
		}
		for _, id := range c.BadHashes {
			fmt.Printf("  bad hash     id %d does not hash to the row_hash it carries\n", id)
		}
		for _, id := range c.BrokenLinks {
			fmt.Printf("  broken link  id %d does not link to the row before it\n", id)
		}
		if n := len(c.Unverified); n > 0 {
			dim.Printf("  %d row(s) arrived with the payload left out; their hashes were not recomputed\n", n)
		}
	}
	if len(rep.Malformed) > 0 {
		red.Printf("%d line(s) hold a record that does not decode (first: line %d)\n", len(rep.Malformed), rep.Malformed[0])
	}
	dim.Printf("%d line(s) read, %d without a record\n", rep.Lines, rep.Skipped)
}

var (
	hubAuditForwardPort int
	hubAuditForwardJSON bool
)

var hubAuditForwardStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Report each audit sink's cursors, backlog, lag and last error",
	Long: `Report each configured audit sink, read from the control plane's cursors and
the head of every chain they name.

  backlog   rows written that the sink has not acknowledged
  lag       the age of the oldest of those
  delivered rows acknowledged over the cursors' lives

The configuration is the hub's on --port, with its per-instance overlay merged,
as 'cloop ui --port' runs. Exits 1 when a configured sink is refused at load,
has never delivered with rows waiting, or lags beyond audit.forward.max_lag.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve working directory: %w", err)
		}
		cfg, _, err := config.LoadUIInstance(dir, hubAuditForwardPort)
		if err != nil {
			return fmt.Errorf("load the hub configuration: %w", err)
		}
		var refused []config.LoadRepair
		for _, r := range cfg.LoadRepairs() {
			if auditforward.IsSinkRepair(r) {
				refused = append(refused, r)
			}
		}
		fwd := cfg.Audit.Forward
		var reports []auditforward.Report
		if len(fwd.Sinks) > 0 {
			cp := state.DBPath(dir)
			if _, err := os.Stat(cp); err != nil {
				return fmt.Errorf("no control plane in %s: %w", dir, err)
			}
			if reports, err = auditforward.Status(cp, fwd); err != nil {
				return err
			}
		}
		now := time.Now()
		bad := len(refused) > 0
		for _, r := range reports {
			if auditforward.Unhealthy(r, fwd.EffectiveMaxLag(), now) != "" {
				bad = true
			}
		}
		if hubAuditForwardJSON {
			if err := writeForwardStatusJSON(cmd, reports, refused, fwd.EffectiveMaxLag(), now); err != nil {
				return err
			}
		} else {
			renderForwardStatus(reports, refused, fwd.EffectiveMaxLag(), now)
		}
		if bad {
			exitProcess(1)
		}
		return nil
	},
}

func renderForwardStatus(reports []auditforward.Report, refused []config.LoadRepair, maxLag time.Duration, now time.Time) {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	green := color.New(color.FgGreen, color.Bold)

	for _, r := range refused {
		red.Printf("✗ %s refused at load: %s\n", r.Field, r.Detail)
	}
	if len(reports) == 0 {
		if len(refused) == 0 {
			fmt.Println("No audit sinks are configured: the trail's content leaves this hub only through `cloop audit-log export`.")
			dim.Println("  Configure audit.forward.sinks — see docs/operations/runbook.md, \"Forwarding the trail off the box\".")
		}
		return
	}
	for _, r := range reports {
		d := auditforward.Describe(r.Sink)
		verdict := auditforward.Unhealthy(r, maxLag, now)
		switch {
		case verdict != "":
			yellow.Printf("! %s", d.Name)
		default:
			green.Printf("✓ %s", d.Name)
		}
		bold.Printf("  %s %s → %s\n", d.Type, d.Format, d.Endpoint)
		if verdict != "" {
			fmt.Printf("  %s\n", verdict)
		}
		fmt.Printf("  backlog %d row(s), lag %s, delivered %d row(s)", r.Backlog(), r.Lag(now).Round(time.Second), r.Delivered())
		if t := r.LastDelivery(); !t.IsZero() {
			fmt.Printf(", last acknowledged %s ago", now.Sub(t).Round(time.Second))
		}
		fmt.Println()
		if msg, at := r.LastError(); msg != "" {
			fmt.Printf("  last error %s ago: %s\n", now.Sub(at).Round(time.Second), msg)
		}
		for _, c := range r.Chains {
			line := fmt.Sprintf("    %-13s %s  acked id %d of %d", c.Cursor.Source, c.Cursor.Dir, c.Cursor.AckedID, c.HeadID)
			if c.Err != nil {
				line += "  (unreadable: " + c.Err.Error() + ")"
			}
			dim.Println(line)
		}
		if len(r.Chains) == 0 {
			dim.Println("    no cursors yet: the hub has not run with this sink")
		}
	}
}

func writeForwardStatusJSON(cmd *cobra.Command, reports []auditforward.Report, refused []config.LoadRepair, maxLag time.Duration, now time.Time) error {
	type chainJSON struct {
		Source       string `json:"source"`
		Dir          string `json:"dir"`
		Database     string `json:"database"`
		AckedID      int64  `json:"acked_id"`
		HeadID       int64  `json:"head_id"`
		Backlog      int64  `json:"backlog"`
		PendingSince string `json:"pending_since,omitempty"`
		Delivered    int64  `json:"delivered"`
		Error        string `json:"error,omitempty"`
	}
	type sinkJSON struct {
		auditforward.SinkDescription
		Backlog       int64       `json:"backlog"`
		LagSeconds    float64     `json:"lag_seconds"`
		Delivered     int64       `json:"delivered"`
		LastDelivery  string      `json:"last_delivery,omitempty"`
		LastError     string      `json:"last_error,omitempty"`
		LastErrorAt   string      `json:"last_error_at,omitempty"`
		Problem       string      `json:"problem,omitempty"`
		Chains        []chainJSON `json:"chains"`
		MaxLagSeconds float64     `json:"max_lag_seconds"`
	}
	type refusedJSON struct {
		Sink   string `json:"sink"`
		File   string `json:"file"`
		Detail string `json:"detail"`
	}
	out := struct {
		Sinks   []sinkJSON    `json:"sinks"`
		Refused []refusedJSON `json:"refused"`
	}{Sinks: []sinkJSON{}, Refused: []refusedJSON{}}
	ts := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339Nano)
	}
	for _, r := range refused {
		out.Refused = append(out.Refused, refusedJSON{Sink: r.Field, File: r.File, Detail: r.Detail})
	}
	for _, r := range reports {
		msg, at := r.LastError()
		s := sinkJSON{
			SinkDescription: auditforward.Describe(r.Sink),
			Backlog:         r.Backlog(),
			LagSeconds:      r.Lag(now).Seconds(),
			Delivered:       r.Delivered(),
			LastDelivery:    ts(r.LastDelivery()),
			LastError:       msg,
			LastErrorAt:     ts(at),
			Problem:         auditforward.Unhealthy(r, maxLag, now),
			Chains:          []chainJSON{},
			MaxLagSeconds:   maxLag.Seconds(),
		}
		for _, c := range r.Chains {
			cj := chainJSON{
				Source: c.Cursor.Source, Dir: c.Cursor.Dir, Database: c.Cursor.Chain,
				AckedID: c.Cursor.AckedID, HeadID: c.HeadID, Backlog: c.Backlog,
				PendingSince: ts(c.PendingSince), Delivered: c.Cursor.Delivered,
			}
			if c.Err != nil {
				cj.Error = c.Err.Error()
			}
			s.Chains = append(s.Chains, cj)
		}
		out.Sinks = append(out.Sinks, s)
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func init() {
	hubAuditForwardStatusCmd.Flags().IntVar(&hubAuditForwardPort, "port", defaultUIPort,
		"port of the hub whose configuration to read (its .cloop/config.ui-<port>.yaml overlay is merged)")
	hubAuditForwardStatusCmd.Flags().BoolVar(&hubAuditForwardJSON, "json", false, "emit JSON")
	hubAuditForwardCmd.AddCommand(hubAuditForwardStatusCmd)
	hubAuditForwardVerifyCmd.Flags().BoolVar(&hubAuditForwardVerifyJSON, "json", false, "emit JSON")
	hubAuditForwardCmd.AddCommand(hubAuditForwardVerifyCmd)
}
