// Package metrics provides structured metrics collection and export for cloop runs.
// Metrics are exposed in Prometheus text format via an optional HTTP server, and
// written as a JSON summary to .cloop/metrics.json at plan completion.
package metrics

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// histBuckets are the upper bounds (in seconds) for task_duration_seconds histogram.
var histBuckets = []float64{1, 5, 15, 30, 60, 120, 300, 600}

// histogram tracks a Prometheus-compatible histogram for a single metric.
type histogram struct {
	mu      sync.Mutex
	buckets []float64 // upper bounds
	counts  []int64   // bucket counts (cumulative ≤ bound[i])
	sum     float64
	count   int64
}

func newHistogram(bounds []float64) *histogram {
	b := make([]float64, len(bounds))
	copy(b, bounds)
	return &histogram{buckets: b, counts: make([]int64, len(bounds))}
}

func (h *histogram) observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i]++
		}
	}
	h.sum += v
	h.count++
}

// labeledCounter is a map of label-set → int64 counter.
type labeledCounter struct {
	mu     sync.Mutex
	values map[string]*int64
}

func newLabeledCounter() *labeledCounter {
	return &labeledCounter{values: make(map[string]*int64)}
}

func (c *labeledCounter) inc(labels map[string]string) {
	key := labelKey(labels)
	c.mu.Lock()
	v, ok := c.values[key]
	if !ok {
		zero := int64(0)
		v = &zero
		c.values[key] = v
	}
	c.mu.Unlock()
	atomic.AddInt64(v, 1)
}

func (c *labeledCounter) add(labels map[string]string, n int64) {
	key := labelKey(labels)
	c.mu.Lock()
	v, ok := c.values[key]
	if !ok {
		zero := int64(0)
		v = &zero
		c.values[key] = v
	}
	c.mu.Unlock()
	atomic.AddInt64(v, n)
}

func (c *labeledCounter) snapshot() map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int64, len(c.values))
	for k, v := range c.values {
		out[k] = atomic.LoadInt64(v)
	}
	return out
}

// labeledFloat is a map of label-set → float64 counter.
type labeledFloat struct {
	mu     sync.Mutex
	values map[string]*float64
}

func newLabeledFloat() *labeledFloat {
	return &labeledFloat{values: make(map[string]*float64)}
}

func (c *labeledFloat) add(labels map[string]string, v float64) {
	key := labelKey(labels)
	c.mu.Lock()
	cur, ok := c.values[key]
	if !ok {
		zero := float64(0)
		cur = &zero
		c.values[key] = cur
	}
	*cur += v
	c.mu.Unlock()
}

func (c *labeledFloat) snapshot() map[string]float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]float64, len(c.values))
	for k, v := range c.values {
		out[k] = *v
	}
	return out
}

// labelKey converts a label map to a canonical string key.
func labelKey(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(labels[k])
	}
	return sb.String()
}

// parseLabels reverses labelKey back into a map. Keys and values must not contain '=' or ','.
func parseLabels(key string) map[string]string {
	m := make(map[string]string)
	if key == "" {
		return m
	}
	for _, part := range strings.Split(key, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	return m
}

// Metrics is the central metrics registry for a cloop run.
// All methods are safe for concurrent use.
type Metrics struct {
	// Simple counters
	tasksTotal     int64
	tasksCompleted int64
	tasksFailed    int64
	tasksSkipped   int64
	stepsTotal     int64

	// Histogram
	taskDuration *histogram

	// Labeled counters: tokens_used_total{provider, model, type}
	tokensTotal *labeledCounter

	// Labeled floats: cost_usd_total{provider, model}
	costTotal *labeledFloat

	// Metadata
	startTime  time.Time
	provider   string
	model      string
}

// New creates a new Metrics instance.
func New(provider, model string) *Metrics {
	return &Metrics{
		taskDuration: newHistogram(histBuckets),
		tokensTotal:  newLabeledCounter(),
		costTotal:    newLabeledFloat(),
		startTime:    time.Now(),
		provider:     provider,
		model:        model,
	}
}

// RecordTaskStarted increments tasks_total.
func (m *Metrics) RecordTaskStarted() {
	atomic.AddInt64(&m.tasksTotal, 1)
}

// RecordTaskCompleted increments tasks_completed.
func (m *Metrics) RecordTaskCompleted(durSeconds float64) {
	atomic.AddInt64(&m.tasksCompleted, 1)
	m.taskDuration.observe(durSeconds)
}

// RecordTaskFailed increments tasks_failed.
func (m *Metrics) RecordTaskFailed(durSeconds float64) {
	atomic.AddInt64(&m.tasksFailed, 1)
	if durSeconds > 0 {
		m.taskDuration.observe(durSeconds)
	}
}

// RecordTaskSkipped increments tasks_skipped.
func (m *Metrics) RecordTaskSkipped() {
	atomic.AddInt64(&m.tasksSkipped, 1)
}

// RecordStep increments steps_total.
func (m *Metrics) RecordStep() {
	atomic.AddInt64(&m.stepsTotal, 1)
}

// RecordTokens increments tokens_used_total for the given provider/model.
func (m *Metrics) RecordTokens(provider, model string, inputTokens, outputTokens int) {
	if provider == "" {
		provider = m.provider
	}
	if model == "" {
		model = m.model
	}
	m.tokensTotal.add(map[string]string{"provider": provider, "model": model, "type": "input"}, int64(inputTokens))
	m.tokensTotal.add(map[string]string{"provider": provider, "model": model, "type": "output"}, int64(outputTokens))
}

// RecordCost adds to cost_usd_total for the given provider/model.
func (m *Metrics) RecordCost(provider, model string, usd float64) {
	if provider == "" {
		provider = m.provider
	}
	if model == "" {
		model = m.model
	}
	m.costTotal.add(map[string]string{"provider": provider, "model": model}, usd)
}

// --- Prometheus text format export ---

// Prometheus returns the current metrics in Prometheus text exposition format.
func (m *Metrics) Prometheus() string {
	var sb strings.Builder

	writeCounter := func(name, help string, val int64) {
		fmt.Fprintf(&sb, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, val)
	}

	writeCounter("cloop_tasks_total", "Total number of tasks started.", atomic.LoadInt64(&m.tasksTotal))
	writeCounter("cloop_tasks_completed_total", "Total number of tasks completed successfully.", atomic.LoadInt64(&m.tasksCompleted))
	writeCounter("cloop_tasks_failed_total", "Total number of tasks that failed.", atomic.LoadInt64(&m.tasksFailed))
	writeCounter("cloop_tasks_skipped_total", "Total number of tasks skipped.", atomic.LoadInt64(&m.tasksSkipped))
	writeCounter("cloop_steps_total", "Total number of steps (AI completions) executed.", atomic.LoadInt64(&m.stepsTotal))

	// Histogram
	sb.WriteString("# HELP cloop_task_duration_seconds Duration of individual tasks in seconds.\n")
	sb.WriteString("# TYPE cloop_task_duration_seconds histogram\n")
	m.taskDuration.mu.Lock()
	cumulative := int64(0)
	for i, bound := range m.taskDuration.buckets {
		cumulative += m.taskDuration.counts[i]
		boundStr := formatFloat(bound)
		fmt.Fprintf(&sb, "cloop_task_duration_seconds_bucket{le=\"%s\"} %d\n", boundStr, cumulative)
	}
	fmt.Fprintf(&sb, "cloop_task_duration_seconds_bucket{le=\"+Inf\"} %d\n", m.taskDuration.count)
	fmt.Fprintf(&sb, "cloop_task_duration_seconds_sum %s\n", formatFloat(m.taskDuration.sum))
	fmt.Fprintf(&sb, "cloop_task_duration_seconds_count %d\n", m.taskDuration.count)
	m.taskDuration.mu.Unlock()

	// Labeled counters: tokens
	sb.WriteString("# HELP cloop_tokens_used_total Total tokens consumed, partitioned by provider, model, and type (input/output).\n")
	sb.WriteString("# TYPE cloop_tokens_used_total counter\n")
	for key, val := range m.tokensTotal.snapshot() {
		lbls := parseLabels(key)
		fmt.Fprintf(&sb, "cloop_tokens_used_total{provider=%q,model=%q,type=%q} %d\n",
			lbls["provider"], lbls["model"], lbls["type"], val)
	}

	// Labeled floats: cost
	sb.WriteString("# HELP cloop_cost_usd_total Estimated USD cost, partitioned by provider and model.\n")
	sb.WriteString("# TYPE cloop_cost_usd_total counter\n")
	for key, val := range m.costTotal.snapshot() {
		lbls := parseLabels(key)
		fmt.Fprintf(&sb, "cloop_cost_usd_total{provider=%q,model=%q} %s\n",
			lbls["provider"], lbls["model"], formatFloat(val))
	}

	return sb.String()
}

func formatFloat(f float64) string {
	if f == math.Trunc(f) {
		return fmt.Sprintf("%.1f", f)
	}
	return fmt.Sprintf("%g", f)
}

// --- JSON summary ---

// Summary is a snapshot of all metrics for JSON serialization.
type Summary struct {
	Timestamp      time.Time          `json:"timestamp"`
	Provider       string             `json:"provider"`
	Model          string             `json:"model"`
	DurationSecs   float64            `json:"duration_seconds"`
	TasksTotal     int64              `json:"tasks_total"`
	TasksCompleted int64              `json:"tasks_completed"`
	TasksFailed    int64              `json:"tasks_failed"`
	TasksSkipped   int64              `json:"tasks_skipped"`
	StepsTotal     int64              `json:"steps_total"`
	TaskDuration   DurationSummary    `json:"task_duration_seconds"`
	TokensUsed     map[string]int64   `json:"tokens_used_total"`
	CostUSD        map[string]float64 `json:"cost_usd_total"`
}

// DurationSummary summarizes the task_duration_seconds histogram.
type DurationSummary struct {
	Count   int64              `json:"count"`
	Sum     float64            `json:"sum"`
	Buckets map[string]int64   `json:"buckets"`
}

// Snapshot returns the current state as a Summary.
func (m *Metrics) Snapshot() Summary {
	m.taskDuration.mu.Lock()
	buckets := make(map[string]int64, len(m.taskDuration.buckets)+1)
	cumulative := int64(0)
	for i, b := range m.taskDuration.buckets {
		cumulative += m.taskDuration.counts[i]
		buckets[formatFloat(b)] = cumulative
	}
	buckets["+Inf"] = m.taskDuration.count
	durSnap := DurationSummary{
		Count:   m.taskDuration.count,
		Sum:     m.taskDuration.sum,
		Buckets: buckets,
	}
	m.taskDuration.mu.Unlock()

	return Summary{
		Timestamp:      time.Now().UTC(),
		Provider:       m.provider,
		Model:          m.model,
		DurationSecs:   time.Since(m.startTime).Seconds(),
		TasksTotal:     atomic.LoadInt64(&m.tasksTotal),
		TasksCompleted: atomic.LoadInt64(&m.tasksCompleted),
		TasksFailed:    atomic.LoadInt64(&m.tasksFailed),
		TasksSkipped:   atomic.LoadInt64(&m.tasksSkipped),
		StepsTotal:     atomic.LoadInt64(&m.stepsTotal),
		TaskDuration:   durSnap,
		TokensUsed:     m.tokensTotal.snapshot(),
		CostUSD:        m.costTotal.snapshot(),
	}
}

// metricsFile is the path to the JSON summary relative to workDir.
const metricsFile = ".cloop/metrics.json"

// WriteJSON saves the current metrics snapshot to .cloop/metrics.json.
func (m *Metrics) WriteJSON(workDir string) error {
	path := filepath.Join(workDir, metricsFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m.Snapshot(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadJSON loads a previously written metrics summary from .cloop/metrics.json.
func LoadJSON(workDir string) (*Summary, error) {
	path := filepath.Join(workDir, metricsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Summary
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
