package chaos

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// SummaryRow aggregates chaos_runs entries by fault type for the headline
// table that `cloop chaos report` prints.
type SummaryRow struct {
	FaultType   FaultType
	Total       int
	Recovered   int
	Degraded    int
	Crashed     int
	Unknown     int
	LastRunAt   time.Time
	AvgDuration time.Duration
}

// SummaryRows reduces a list of runs to one SummaryRow per fault type,
// sorted by FaultType for stable output.
func SummaryRows(runs []Run) []SummaryRow {
	byType := map[FaultType]*SummaryRow{}
	durationSum := map[FaultType]time.Duration{}
	for _, r := range runs {
		row, ok := byType[r.FaultType]
		if !ok {
			row = &SummaryRow{FaultType: r.FaultType}
			byType[r.FaultType] = row
		}
		row.Total++
		switch r.Outcome {
		case OutcomeRecovered:
			row.Recovered++
		case OutcomeDegraded:
			row.Degraded++
		case OutcomeCrashed:
			row.Crashed++
		default:
			row.Unknown++
		}
		if r.StartedAt.After(row.LastRunAt) {
			row.LastRunAt = r.StartedAt
		}
		durationSum[r.FaultType] += time.Duration(r.DurationMS) * time.Millisecond
	}
	out := make([]SummaryRow, 0, len(byType))
	for ft, row := range byType {
		if row.Total > 0 {
			row.AvgDuration = durationSum[ft] / time.Duration(row.Total)
		}
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FaultType < out[j].FaultType })
	return out
}

// FormatSummary renders summary rows as a fixed-width table suitable for
// printing to a terminal. Includes a totals footer.
func FormatSummary(rows []SummaryRow) string {
	if len(rows) == 0 {
		return "no chaos runs recorded yet — try `cloop chaos inject provider-429`"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-22s %5s %10s %9s %8s %8s %20s %10s\n",
		"FAULT", "TOTAL", "RECOVERED", "DEGRADED", "CRASHED", "UNKNOWN", "LAST_RUN", "AVG_MS")
	fmt.Fprintln(&b, strings.Repeat("─", 95))
	var totals SummaryRow
	for _, r := range rows {
		fmt.Fprintf(&b, "%-22s %5d %10d %9d %8d %8d %20s %10d\n",
			r.FaultType, r.Total, r.Recovered, r.Degraded, r.Crashed, r.Unknown,
			formatTime(r.LastRunAt), r.AvgDuration.Milliseconds(),
		)
		totals.Total += r.Total
		totals.Recovered += r.Recovered
		totals.Degraded += r.Degraded
		totals.Crashed += r.Crashed
		totals.Unknown += r.Unknown
	}
	fmt.Fprintln(&b, strings.Repeat("─", 95))
	fmt.Fprintf(&b, "%-22s %5d %10d %9d %8d %8d\n",
		"TOTAL", totals.Total, totals.Recovered, totals.Degraded, totals.Crashed, totals.Unknown)
	return b.String()
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04:05Z")
}
