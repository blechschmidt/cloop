package cmd

// hub_telemetry_cmd.go reads the front-end diagnostic trail from a terminal
// (Task 20251).
//
// The panel in the dashboard is the discoverable surface; this is the one that
// gets used. Debugging a display-glasses report starts with somebody already
// ssh'd into the hub, and asking them to open a browser, sign in, find a tab
// and click a session row is enough friction to lose the habit. It is also the
// only reader that works when the thing being debugged is the dashboard.
//
// Read-only by design, apart from `prune`. Nothing here can write an event:
// the trail is written by browsers and by nothing else, which is what keeps
// "what the page did" from being confusable with "what an operator typed".

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/telemetry"
)

var hubTelemetryCmd = &cobra.Command{
	Use:   "telemetry",
	Short: "Read the browser and display-glasses diagnostic trail",
	Long: `Read what the front ends actually did.

The dashboard and the /glasses page record an ordered trail per page load —
gestures received, views opened, requests and their status, uncaught errors —
and post it to the hub. This reads it back. It exists because those front ends
run where the hub cannot look: the glasses in particular have no console, no
network inspector, and a wearer whose entire reporting channel is a sentence.

  cloop hub telemetry sessions                  recent page loads, newest first
  cloop hub telemetry sessions --source glasses just the wearable
  cloop hub telemetry show <session>            one trail, in the order it happened
  cloop hub telemetry list --kind error         recent errors across all sessions
  cloop hub telemetry prune --before 7d         delete old events now

Start with 'sessions': an investigation begins as "someone reported a problem
around ten past four" and has to become a session id before anything else is
useful.`,
}

var (
	hubTelemetrySource  string
	hubTelemetryKind    string
	hubTelemetrySearch  string
	hubTelemetryLimit   int
	hubTelemetryVerbose bool
	hubTelemetryBefore  string
	hubTelemetryYes     bool
)

// openTelemetryDB opens the hub's control-plane database.
//
// Delegates to openHubDB rather than calling statedb.Open, because that helper
// refuses to *create* one — and the failure it prevents is worse here than
// almost anywhere. statedb.Open on a wrong path would migrate a fresh empty
// database into existence and this command would print "No telemetry
// recorded", which somebody debugging a front end reads as "the instrument is
// not working" rather than "you are one directory off". A silent wrong answer
// is the one outcome a diagnostic tool must not produce.
func openTelemetryDB(cmd *cobra.Command) (*statedb.DB, func(), error) {
	workdir, _ := cmd.Flags().GetString("workdir")
	return openHubDB(workdir)
}

var hubTelemetrySessionsCmd = &cobra.Command{
	Use:   "sessions",
	Short: "List recent page loads, newest activity first",
	RunE: func(cmd *cobra.Command, args []string) error {
		if hubTelemetrySource != "" && !telemetry.Source(hubTelemetrySource).Valid() {
			return fmt.Errorf("unknown source %q (want dashboard or glasses)", hubTelemetrySource)
		}
		db, closer, err := openTelemetryDB(cmd)
		if err != nil {
			return err
		}
		defer closer()

		sessions, err := db.ListTelemetrySessions(hubTelemetrySource, hubTelemetryLimit)
		if err != nil {
			return err
		}
		if len(sessions) == 0 {
			fmt.Println("No telemetry recorded. Either no front end has reported yet, or " +
				"collection is off (ui.telemetry.enabled).")
			return nil
		}

		bold := color.New(color.Bold).SprintFunc()
		dim := color.New(color.Faint).SprintFunc()
		red := color.New(color.FgRed).SprintFunc()

		fmt.Printf("%-18s %-10s %7s %7s  %-20s %s\n",
			bold("SESSION"), bold("SOURCE"), bold("EVENTS"), bold("ERRORS"),
			bold("LAST SEEN"), bold("WHO / DEVICE"))
		for _, s := range sessions {
			errs := fmt.Sprintf("%d", s.Errors)
			if s.Errors > 0 {
				errs = red(errs)
			}
			who := strings.TrimSpace(strings.Join(nonEmpty(s.Actor, s.UserAgent), " · "))
			if who == "" {
				who = dim("—")
			}
			fmt.Printf("%-18s %-10s %7d %7s  %-20s %s\n",
				s.Session, s.Source, s.Events, errs,
				s.LastSeen.Local().Format("2006-01-02 15:04:05"), truncateCell(who, 60))
		}
		fmt.Printf("\n%s\n", dim("cloop hub telemetry show <session>  — read one trail in order"))
		return nil
	},
}

var hubTelemetryShowCmd = &cobra.Command{
	Use:   "show <session>",
	Short: "Print one session's trail in the order the page recorded it",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		db, closer, err := openTelemetryDB(cmd)
		if err != nil {
			return err
		}
		defer closer()

		rows, total, err := db.QueryTelemetry(statedb.TelemetryFilter{
			Session: args[0],
			Limit:   hubTelemetryLimit,
		})
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return fmt.Errorf("no events for session %q", args[0])
		}
		// The store returns newest-first, which is right for a list and wrong
		// for a trail: reading what happened means reading it forwards.
		for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
			rows[i], rows[j] = rows[j], rows[i]
		}
		printTelemetryRows(rows, true)
		if total > len(rows) {
			fmt.Printf("\n%s\n", color.New(color.Faint).Sprintf(
				"showing the %d most recent of %d events — raise --limit for the rest",
				len(rows), total))
		}
		return nil
	},
}

var hubTelemetryListCmd = &cobra.Command{
	Use:   "list",
	Short: "List recent events across all sessions, newest first",
	RunE: func(cmd *cobra.Command, args []string) error {
		if hubTelemetrySource != "" && !telemetry.Source(hubTelemetrySource).Valid() {
			return fmt.Errorf("unknown source %q (want dashboard or glasses)", hubTelemetrySource)
		}
		if hubTelemetryKind != "" && !telemetry.Kind(hubTelemetryKind).Valid() {
			return fmt.Errorf("unknown kind %q", hubTelemetryKind)
		}
		db, closer, err := openTelemetryDB(cmd)
		if err != nil {
			return err
		}
		defer closer()

		rows, total, err := db.QueryTelemetry(statedb.TelemetryFilter{
			Source: hubTelemetrySource,
			Kind:   hubTelemetryKind,
			Search: hubTelemetrySearch,
			Limit:  hubTelemetryLimit,
		})
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Println("No telemetry events match.")
			return nil
		}
		printTelemetryRows(rows, false)
		fmt.Printf("\n%s\n", color.New(color.Faint).Sprintf("%d of %d event(s)", len(rows), total))
		return nil
	},
}

var hubTelemetryPruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Delete telemetry events older than a cutoff",
	Long: `Delete telemetry events older than --before.

The table already bounds itself: it trims on the write path once it passes its
row ceiling, so it cannot grow without limit and this is never required for
disk. Use it when a trail should go now rather than when it ages out.

Unlike the audit trail, telemetry is not hash-chained and nothing verifies its
continuity, so deletion needs no seal and leaves no gap to explain.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(hubTelemetryBefore) == "" {
			return fmt.Errorf("--before is required (e.g. 7d, 48h, 2026-01-01)")
		}
		cutoff, err := parseTelemetryCutoff(hubTelemetryBefore)
		if err != nil {
			return err
		}
		db, closer, err := openTelemetryDB(cmd)
		if err != nil {
			return err
		}
		defer closer()

		if !hubTelemetryYes {
			// Count first so the confirmation names a number rather than
			// asking the operator to authorise an unknown quantity.
			_, total, qerr := db.QueryTelemetry(statedb.TelemetryFilter{Limit: 1})
			if qerr != nil {
				return qerr
			}
			fmt.Printf("Delete telemetry events received before %s? (%d event(s) in the table)\n",
				cutoff.Local().Format(time.RFC3339), total)
			fmt.Print("Type 'yes' to confirm: ")
			var answer string
			_, _ = fmt.Scanln(&answer)
			if strings.TrimSpace(strings.ToLower(answer)) != "yes" {
				fmt.Println("Aborted.")
				return nil
			}
		}

		n, err := db.PruneTelemetry(cutoff)
		if err != nil {
			return err
		}
		fmt.Printf("Deleted %d telemetry event(s) older than %s.\n",
			n, cutoff.Local().Format(time.RFC3339))
		return nil
	},
}

// printTelemetryRows renders a trail. inSession drops the session column, which
// is constant there and would cost the width that messages need.
func printTelemetryRows(rows []telemetry.Event, inSession bool) {
	dim := color.New(color.Faint).SprintFunc()

	for _, e := range rows {
		kind := colorTelemetryKind(e.Kind)
		stamp := e.At.Local().Format("15:04:05.000")
		prefix := fmt.Sprintf("%s %4d %-10s", dim(stamp), e.Seq, kind)
		if !inSession {
			prefix = fmt.Sprintf("%s %-16s %-9s", prefix, e.Session, e.Source)
		}
		view := ""
		if e.View != "" {
			view = dim("[" + e.View + "] ")
		}
		fmt.Printf("%s %s%s\n", prefix, view, e.Message)

		if !hubTelemetryVerbose {
			continue
		}
		for _, extra := range []struct{ label, val string }{
			{"url", e.URL}, {"detail", e.Detail}, {"stack", e.Stack},
			{"agent", e.UserAgent}, {"actor", e.Actor}, {"build", e.Release},
		} {
			if extra.val == "" {
				continue
			}
			for _, line := range strings.Split(extra.val, "\n") {
				fmt.Printf("        %s %s\n", dim(extra.label+":"), line)
			}
		}
	}
}

func colorTelemetryKind(k telemetry.Kind) string {
	switch k {
	case telemetry.KindError, telemetry.KindRejection:
		return color.New(color.FgRed, color.Bold).Sprint(string(k))
	case telemetry.KindGesture:
		return color.New(color.FgCyan).Sprint(string(k))
	case telemetry.KindFetch:
		return color.New(color.FgYellow).Sprint(string(k))
	case telemetry.KindView:
		return color.New(color.FgGreen).Sprint(string(k))
	}
	return string(k)
}

// parseTelemetryCutoff accepts a relative duration ("7d", "48h"), a date, or a
// full RFC3339 timestamp — the three spellings an operator actually reaches
// for, and the same set `cloop hub audit prune --before` takes.
func parseTelemetryCutoff(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if d, err := parseSinceDuration(s); err == nil {
		return time.Now().UTC().Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf(
		"could not read %q as a cutoff (use 7d, 48h, 2026-01-01, or an RFC3339 timestamp)", s)
}

func nonEmpty(vals ...string) []string {
	var out []string
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

func truncateCell(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func init() {
	for _, c := range []*cobra.Command{hubTelemetrySessionsCmd, hubTelemetryListCmd} {
		c.Flags().StringVar(&hubTelemetrySource, "source", "",
			"only this front end: dashboard or glasses")
	}
	hubTelemetryListCmd.Flags().StringVar(&hubTelemetryKind, "kind", "",
		"only this kind: error, rejection, gesture, view, fetch, lifecycle, note")
	hubTelemetryListCmd.Flags().StringVar(&hubTelemetrySearch, "grep", "",
		"only events whose message, url, view or detail contains this")

	for _, c := range []*cobra.Command{hubTelemetrySessionsCmd, hubTelemetryListCmd, hubTelemetryShowCmd} {
		c.Flags().IntVar(&hubTelemetryLimit, "limit", 200, "maximum rows to read")
	}

	// Every subcommand reads the hub's own database, and an operator debugging
	// a front end is not necessarily sitting in the hub's directory.
	for _, c := range []*cobra.Command{hubTelemetrySessionsCmd, hubTelemetryListCmd, hubTelemetryShowCmd, hubTelemetryPruneCmd} {
		c.Flags().String("workdir", "", "hub directory holding .cloop/state.db (default: current directory)")
	}
	for _, c := range []*cobra.Command{hubTelemetryListCmd, hubTelemetryShowCmd} {
		c.Flags().BoolVarP(&hubTelemetryVerbose, "verbose", "v", false,
			"also print url, detail, stack, user agent and build for each event")
	}

	hubTelemetryPruneCmd.Flags().StringVar(&hubTelemetryBefore, "before", "",
		"delete events received before this (7d, 48h, 2026-01-01, RFC3339)")
	hubTelemetryPruneCmd.Flags().BoolVar(&hubTelemetryYes, "yes", false,
		"skip the confirmation prompt")

	hubTelemetryCmd.AddCommand(hubTelemetrySessionsCmd)
	hubTelemetryCmd.AddCommand(hubTelemetryShowCmd)
	hubTelemetryCmd.AddCommand(hubTelemetryListCmd)
	hubTelemetryCmd.AddCommand(hubTelemetryPruneCmd)
	hubCmd.AddCommand(hubTelemetryCmd)
}
