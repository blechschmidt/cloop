// Package perfprofile analyzes timing data from task checkpoints and the cost
// ledger to identify execution bottlenecks across a plan run.
package perfprofile

import (
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/checkpoint"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/taskstats"
)

// TaskProfile holds performance data for a single task execution.
type TaskProfile struct {
	TaskID    int
	TaskTitle string
	Status    string

	WallTime    time.Duration
	StartedAt   *time.Time
	CompletedAt *time.Time
	// QueueDelay is the gap between the previous task completing and this one starting.
	QueueDelay time.Duration

	Provider string
	Model    string

	InputTokens  int
	OutputTokens int
	CostUSD      float64
}

// ProviderProfile aggregates latency and usage stats for one provider+model pair.
type ProviderProfile struct {
	Provider string

	// TotalCalls is the number of cost-ledger entries attributed to this provider.
	TotalCalls int
	// Latencies are per-step elapsed-second deltas derived from checkpoint history.
	Latencies []float64

	MeanSec float64
	P95Sec  float64
	MaxSec  float64

	TotalInputTokens  int
	TotalOutputTokens int
	TotalCostUSD      float64
}

// Profile is the complete performance analysis result.
type Profile struct {
	Tasks     []*TaskProfile
	Providers map[string]*ProviderProfile

	// Plan-level span
	PlanStartedAt   *time.Time
	PlanCompletedAt *time.Time
	// TotalWallSpan is latest CompletedAt minus earliest StartedAt across all tasks.
	TotalWallSpan time.Duration
	// SumTaskDurations is the arithmetic sum of every task's WallTime.
	SumTaskDurations time.Duration
	// ParallelEfficiency = SumTaskDurations / TotalWallSpan.
	// Values > 1.0 indicate parallelism was used. 1.0 means purely sequential.
	ParallelEfficiency float64

	// Task duration distribution
	MeanTaskDuration time.Duration
	P95TaskDuration  time.Duration
	MaxTaskDuration  time.Duration
	// Durations contains every non-zero task WallTime, sorted ascending (for histogram).
	Durations []time.Duration

	// MeanQueueDelay is the mean wait time tasks spend queued between executions.
	MeanQueueDelay time.Duration
	// TotalQueueDelay is the sum of all queue delays.
	TotalQueueDelay time.Duration
}

// Build constructs a Profile from project state and on-disk artifacts.
// workDir is the project root (the directory that contains .cloop/).
func Build(workDir string, s *state.ProjectState) *Profile {
	p := &Profile{
		Providers: make(map[string]*ProviderProfile),
	}

	if s == nil || s.Plan == nil {
		return p
	}

	// Gather base task stats (timing, heal attempts, etc.)
	agg := taskstats.Collect(s, workDir, "")

	// Load cost ledger for provider/model attribution per task.
	ledger, _ := cost.ReadLedger(workDir)
	ledgerByTask := make(map[int][]cost.LedgerEntry)
	for _, e := range ledger {
		ledgerByTask[e.TaskID] = append(ledgerByTask[e.TaskID], e)
	}

	var earliest, latest time.Time

	for _, ts := range agg.All {
		tp := &TaskProfile{
			TaskID:      ts.TaskID,
			TaskTitle:   ts.TaskTitle,
			Status:      string(ts.Status),
			WallTime:    ts.WallTime,
			StartedAt:   ts.StartedAt,
			CompletedAt: ts.CompletedAt,
		}

		// Override token/cost data from ledger (more accurate source).
		if entries := ledgerByTask[ts.TaskID]; len(entries) > 0 {
			tp.Provider = entries[0].Provider
			tp.Model = entries[0].Model
			for _, e := range entries {
				tp.InputTokens += e.InputTokens
				tp.OutputTokens += e.OutputTokens
				tp.CostUSD += e.EstimatedUSD
			}
		} else {
			// Fall back to taskstats data when no ledger entry exists.
			tp.InputTokens = ts.InputTokens
			tp.OutputTokens = ts.OutputTokens
			tp.CostUSD = ts.CostUSD
		}

		// Track plan span.
		if ts.StartedAt != nil {
			if earliest.IsZero() || ts.StartedAt.Before(earliest) {
				earliest = *ts.StartedAt
			}
		}
		if ts.CompletedAt != nil {
			if latest.IsZero() || ts.CompletedAt.After(latest) {
				latest = *ts.CompletedAt
			}
		}

		p.Tasks = append(p.Tasks, tp)
	}

	// Compute queue delays: sort tasks by StartedAt then measure gap from
	// the immediately preceding task's CompletedAt.
	var withStart []*TaskProfile
	for _, tp := range p.Tasks {
		if tp.StartedAt != nil {
			withStart = append(withStart, tp)
		}
	}
	sort.Slice(withStart, func(i, j int) bool {
		return withStart[i].StartedAt.Before(*withStart[j].StartedAt)
	})
	var totalQueue time.Duration
	queueCount := 0
	for i := 1; i < len(withStart); i++ {
		prev := withStart[i-1]
		curr := withStart[i]
		if prev.CompletedAt != nil {
			delay := curr.StartedAt.Sub(*prev.CompletedAt)
			if delay > 0 {
				curr.QueueDelay = delay
				totalQueue += delay
				queueCount++
			}
		}
	}
	p.TotalQueueDelay = totalQueue
	if queueCount > 0 {
		p.MeanQueueDelay = totalQueue / time.Duration(queueCount)
	}

	// Plan-level span and sum of task durations.
	if !earliest.IsZero() {
		p.PlanStartedAt = &earliest
	}
	if !latest.IsZero() {
		p.PlanCompletedAt = &latest
	}
	if !earliest.IsZero() && !latest.IsZero() {
		p.TotalWallSpan = latest.Sub(earliest)
	}

	var sumDurations time.Duration
	for _, tp := range p.Tasks {
		if tp.WallTime > 0 {
			sumDurations += tp.WallTime
			p.Durations = append(p.Durations, tp.WallTime)
		}
	}
	p.SumTaskDurations = sumDurations

	if p.TotalWallSpan > 0 {
		p.ParallelEfficiency = float64(sumDurations) / float64(p.TotalWallSpan)
	}

	// Task duration percentiles.
	if len(p.Durations) > 0 {
		sorted := make([]time.Duration, len(p.Durations))
		copy(sorted, p.Durations)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

		var total time.Duration
		for _, d := range sorted {
			total += d
		}
		p.MeanTaskDuration = total / time.Duration(len(sorted))
		p.MaxTaskDuration = sorted[len(sorted)-1]
		p95idx := int(math.Ceil(float64(len(sorted))*0.95)) - 1
		if p95idx < 0 {
			p95idx = 0
		}
		p.P95TaskDuration = sorted[p95idx]
	}

	// Build provider profiles from the cost ledger.
	for _, e := range ledger {
		key := e.Provider
		if e.Model != "" {
			key = e.Provider + "/" + e.Model
		}
		pp := p.Providers[key]
		if pp == nil {
			pp = &ProviderProfile{Provider: key}
			p.Providers[key] = pp
		}
		pp.TotalCalls++
		pp.TotalInputTokens += e.InputTokens
		pp.TotalOutputTokens += e.OutputTokens
		pp.TotalCostUSD += e.EstimatedUSD
	}

	// Enrich provider latency from checkpoint elapsed-time deltas.
	enrichFromCheckpoints(workDir, p)

	// Finalize provider latency statistics.
	for _, pp := range p.Providers {
		if len(pp.Latencies) == 0 {
			continue
		}
		sort.Float64s(pp.Latencies)
		var sum float64
		for _, lat := range pp.Latencies {
			sum += lat
		}
		pp.MeanSec = sum / float64(len(pp.Latencies))
		pp.MaxSec = pp.Latencies[len(pp.Latencies)-1]
		p95idx := int(math.Ceil(float64(len(pp.Latencies))*0.95)) - 1
		if p95idx < 0 {
			p95idx = 0
		}
		pp.P95Sec = pp.Latencies[p95idx]
	}

	return p
}

// enrichFromCheckpoints loads checkpoint history files and derives per-step
// latency values (elapsed-second deltas between consecutive checkpoints),
// then adds them to the corresponding ProviderProfile.
func enrichFromCheckpoints(workDir string, p *Profile) {
	base := filepath.Join(workDir, ".cloop", "task-checkpoints")
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}

	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "task-") {
			continue
		}
		var taskID int
		if _, err := fmt.Sscanf(e.Name(), "task-%d", &taskID); err != nil {
			continue
		}

		cps, err := checkpoint.ListHistory(workDir, taskID)
		if err != nil || len(cps) < 2 {
			continue
		}

		// Determine provider: prefer the task's cost-ledger attribution, then
		// fall back to what the checkpoint itself recorded.
		provider := ""
		for _, tp := range p.Tasks {
			if tp.TaskID == taskID && tp.Provider != "" {
				provider = tp.Provider
				break
			}
		}
		if provider == "" {
			for _, cp := range cps {
				if cp.Checkpoint.Provider != "" {
					provider = cp.Checkpoint.Provider
					break
				}
			}
		}
		if provider == "" {
			provider = "unknown"
		}

		// cps is already sorted oldest-first (by unix-nano filename).
		// Compute elapsed-second deltas as individual step latencies.
		for i := 1; i < len(cps); i++ {
			delta := cps[i].Checkpoint.ElapsedSec - cps[i-1].Checkpoint.ElapsedSec
			if delta > 0 {
				pp := p.Providers[provider]
				if pp == nil {
					pp = &ProviderProfile{Provider: provider}
					p.Providers[provider] = pp
				}
				pp.Latencies = append(pp.Latencies, delta)
			}
		}
	}
}

// RenderBottleneckTable writes a ranked bottleneck table to w.
// top limits the number of tasks shown (0 = show all).
func RenderBottleneckTable(p *Profile, top int, w io.Writer) {
	// Rank tasks by WallTime descending (longest first = biggest bottleneck).
	ranked := make([]*TaskProfile, len(p.Tasks))
	copy(ranked, p.Tasks)
	sort.Slice(ranked, func(i, j int) bool {
		return ranked[i].WallTime > ranked[j].WallTime
	})

	limit := len(ranked)
	if top > 0 && top < limit {
		limit = top
	}

	fmt.Fprintf(w, "\n%-4s  %-40s  %-10s  %-10s  %-10s  %-14s  %s\n",
		"RANK", "TASK", "WALL TIME", "QUEUE DLY", "STATUS", "PROVIDER", "COST")
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 110))

	for i, tp := range ranked[:limit] {
		wall := fmtDuration(tp.WallTime)
		queue := "-"
		if tp.QueueDelay > 0 {
			queue = fmtDuration(tp.QueueDelay)
		}
		prov := tp.Provider
		if prov == "" {
			prov = "-"
		}
		costStr := "-"
		if tp.CostUSD > 0 {
			costStr = fmt.Sprintf("$%.4f", tp.CostUSD)
		}
		title := tp.TaskTitle
		if len(title) > 40 {
			title = title[:37] + "..."
		}
		fmt.Fprintf(w, "#%-3d  %-40s  %-10s  %-10s  %-10s  %-14s  %s\n",
			i+1, title, wall, queue, tp.Status, prov, costStr)
	}

	// Provider latency summary.
	if len(p.Providers) > 0 {
		fmt.Fprintf(w, "\n%-30s  %6s  %8s  %8s  %8s  %8s  %s\n",
			"PROVIDER", "CALLS", "MEAN(s)", "P95(s)", "MAX(s)", "TOK-IN", "TOK-OUT")
		fmt.Fprintf(w, "%s\n", strings.Repeat("-", 90))

		// Sort providers by mean latency descending.
		var provList []*ProviderProfile
		for _, pp := range p.Providers {
			provList = append(provList, pp)
		}
		sort.Slice(provList, func(i, j int) bool {
			return provList[i].MeanSec > provList[j].MeanSec
		})

		for _, pp := range provList {
			meanStr := "-"
			p95Str := "-"
			maxStr := "-"
			if len(pp.Latencies) > 0 {
				meanStr = fmt.Sprintf("%.2f", pp.MeanSec)
				p95Str = fmt.Sprintf("%.2f", pp.P95Sec)
				maxStr = fmt.Sprintf("%.2f", pp.MaxSec)
			}
			fmt.Fprintf(w, "%-30s  %6d  %8s  %8s  %8s  %8d  %d\n",
				truncate(pp.Provider, 30),
				pp.TotalCalls, meanStr, p95Str, maxStr,
				pp.TotalInputTokens, pp.TotalOutputTokens)
		}
	}

	// Plan-level summary.
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Plan wall span:      %s\n", fmtDuration(p.TotalWallSpan))
	fmt.Fprintf(w, "Sum of task times:   %s\n", fmtDuration(p.SumTaskDurations))
	if p.ParallelEfficiency > 0 {
		fmt.Fprintf(w, "Parallel efficiency: %.2fx\n", p.ParallelEfficiency)
	}
	if p.MeanQueueDelay > 0 {
		fmt.Fprintf(w, "Mean queue delay:    %s  (total: %s)\n",
			fmtDuration(p.MeanQueueDelay), fmtDuration(p.TotalQueueDelay))
	}
	fmt.Fprintf(w, "Task duration mean:  %s  p95: %s  max: %s\n",
		fmtDuration(p.MeanTaskDuration),
		fmtDuration(p.P95TaskDuration),
		fmtDuration(p.MaxTaskDuration))
}

// RenderHistogram writes an ASCII histogram of task duration distribution to w.
func RenderHistogram(p *Profile, w io.Writer) {
	if len(p.Durations) == 0 {
		fmt.Fprintln(w, "No task duration data available.")
		return
	}

	const buckets = 10
	const barWidth = 40

	sorted := make([]time.Duration, len(p.Durations))
	copy(sorted, p.Durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	minD := sorted[0]
	maxD := sorted[len(sorted)-1]

	if maxD == minD {
		// All tasks took the same time.
		fmt.Fprintf(w, "All %d task(s) completed in %s\n", len(sorted), fmtDuration(minD))
		return
	}

	bucketSize := (maxD - minD) / time.Duration(buckets)
	if bucketSize == 0 {
		bucketSize = 1
	}
	counts := make([]int, buckets)
	for _, d := range sorted {
		idx := int((d - minD) / bucketSize)
		if idx >= buckets {
			idx = buckets - 1
		}
		counts[idx]++
	}

	maxCount := 0
	for _, c := range counts {
		if c > maxCount {
			maxCount = c
		}
	}

	fmt.Fprintf(w, "\nTask Duration Distribution (%d tasks)\n", len(sorted))
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", barWidth+35))

	for i := 0; i < buckets; i++ {
		lo := minD + time.Duration(i)*bucketSize
		hi := lo + bucketSize
		if i == buckets-1 {
			hi = maxD
		}
		barLen := 0
		if maxCount > 0 {
			barLen = counts[i] * barWidth / maxCount
		}
		bar := strings.Repeat("█", barLen)
		fmt.Fprintf(w, "  %8s – %-8s │ %-*s  %d\n",
			fmtDuration(lo), fmtDuration(hi), barWidth, bar, counts[i])
	}
	fmt.Fprintln(w)
}

// fmtDuration renders a duration in a compact human-readable form.
func fmtDuration(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	switch {
	case h > 0:
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	case m > 0:
		return fmt.Sprintf("%dm%ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

// truncate shortens s to at most n runes, appending "…" if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
