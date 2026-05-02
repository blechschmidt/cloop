// Package alert implements threshold-based monitoring rules for cloop plans.
// Rules are persisted in .cloop/alerts.yaml and evaluated after each task
// completes during PM mode execution.
package alert

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/pm"
	"gopkg.in/yaml.v3"
)

const alertsFile = ".cloop/alerts.yaml"

// Metric identifies which plan value to compare against a threshold.
type Metric string

const (
	// MetricFailureRate is the percentage of tasks in failed status (0-100).
	MetricFailureRate Metric = "failure_rate"
	// MetricTaskDurationMinutes is the actual execution time of the most recently
	// completed task in minutes.
	MetricTaskDurationMinutes Metric = "task_duration_minutes"
	// MetricPendingCount is the number of tasks with status "pending".
	MetricPendingCount Metric = "pending_count"
	// MetricCostUSD is the total estimated session cost in USD from the cost ledger.
	MetricCostUSD Metric = "cost_usd"
)

// Op is a comparison operator used in alert rules.
type Op string

const (
	OpGt Op = "gt" // greater than
	OpLt Op = "lt" // less than
	OpEq Op = "eq" // equal
)

// Rule defines a single monitoring rule.
type Rule struct {
	// Name is a unique identifier for this rule (e.g. "high-failure-rate").
	Name string `yaml:"name"`
	// Metric is the value to monitor (failure_rate, task_duration_minutes, pending_count, cost_usd).
	Metric Metric `yaml:"metric"`
	// Op is the comparison operator: gt, lt, or eq.
	Op Op `yaml:"op"`
	// Threshold is the numeric value to compare against.
	Threshold float64 `yaml:"threshold"`
	// Notify is the notification channel: "desktop", "webhook:<url>", or "slack:<url>".
	Notify string `yaml:"notify"`
}

// Violation records a triggered alert rule along with the observed value.
type Violation struct {
	Rule          Rule
	ObservedValue float64
	// TriggeredAt is the wall-clock time when the violation was detected.
	TriggeredAt time.Time
}

// String returns a human-readable description of the violation.
func (v Violation) String() string {
	return fmt.Sprintf("ALERT %q: %s %s %.4g (observed %.4g) at %s",
		v.Rule.Name, v.Rule.Metric, v.Rule.Op, v.Rule.Threshold,
		v.ObservedValue, v.TriggeredAt.Format(time.RFC3339))
}

// rulesFile holds the on-disk YAML structure.
type rulesFile struct {
	Rules []Rule `yaml:"rules"`
}

// Load reads alert rules from .cloop/alerts.yaml in workDir.
// Returns an empty slice (not an error) when the file does not exist.
func Load(workDir string) ([]Rule, error) {
	path := filepath.Join(workDir, alertsFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rf rulesFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("alert: parse %s: %w", path, err)
	}
	return rf.Rules, nil
}

// Save writes alert rules to .cloop/alerts.yaml in workDir.
func Save(workDir string, rules []Rule) error {
	path := filepath.Join(workDir, alertsFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	rf := rulesFile{Rules: rules}
	data, err := yaml.Marshal(&rf)
	if err != nil {
		return fmt.Errorf("alert: marshal rules: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

// AddRule appends a rule to .cloop/alerts.yaml, replacing any existing rule
// with the same name.
func AddRule(workDir string, rule Rule) error {
	rules, err := Load(workDir)
	if err != nil {
		return err
	}
	// Replace if name matches.
	for i, r := range rules {
		if r.Name == rule.Name {
			rules[i] = rule
			return Save(workDir, rules)
		}
	}
	rules = append(rules, rule)
	return Save(workDir, rules)
}

// RemoveRule removes the rule with the given name from .cloop/alerts.yaml.
// Returns an error if the rule does not exist.
func RemoveRule(workDir string, name string) error {
	rules, err := Load(workDir)
	if err != nil {
		return err
	}
	filtered := rules[:0]
	found := false
	for _, r := range rules {
		if r.Name == name {
			found = true
			continue
		}
		filtered = append(filtered, r)
	}
	if !found {
		return fmt.Errorf("alert: rule %q not found", name)
	}
	return Save(workDir, filtered)
}

// EvalContext holds the pre-computed metric values used for a single evaluation.
// Callers can pass nil for plan or set lastTaskMinutes to 0 when not applicable.
type EvalContext struct {
	// Plan is the current PM plan (may be nil — metrics that require it return 0).
	Plan *pm.Plan
	// LastTaskMinutes is the actual execution time of the most recently completed task.
	// The caller should set this to task.ActualMinutes after each task.
	LastTaskMinutes float64
	// TotalCostUSD is the cumulative session cost read from the cost ledger.
	TotalCostUSD float64
}

// collectMetrics reads the current metric values for workDir.
func collectMetrics(workDir string, ctx EvalContext) map[Metric]float64 {
	vals := make(map[Metric]float64)

	if ctx.Plan != nil {
		total := float64(len(ctx.Plan.Tasks))
		if total > 0 {
			var failed, pending float64
			for _, t := range ctx.Plan.Tasks {
				switch t.Status {
				case pm.TaskFailed:
					failed++
				case pm.TaskPending:
					pending++
				}
			}
			vals[MetricFailureRate] = (failed / total) * 100.0
			vals[MetricPendingCount] = pending
		}
	}

	vals[MetricTaskDurationMinutes] = ctx.LastTaskMinutes
	vals[MetricCostUSD] = ctx.TotalCostUSD

	return vals
}

// compare returns true when observed satisfies the rule's operator and threshold.
func compare(op Op, observed, threshold float64) bool {
	switch op {
	case OpGt:
		return observed > threshold
	case OpLt:
		return observed < threshold
	case OpEq:
		return observed == threshold
	default:
		return false
	}
}

// Evaluate runs all rules loaded from .cloop/alerts.yaml against the current
// plan state and returns any triggered violations. It is safe to call with a
// nil plan; metrics that require plan data will be treated as 0.
func Evaluate(workDir string, rules []Rule, ctx EvalContext) []Violation {
	if len(rules) == 0 {
		return nil
	}
	vals := collectMetrics(workDir, ctx)
	now := time.Now()
	var violations []Violation
	for _, rule := range rules {
		observed, ok := vals[rule.Metric]
		if !ok {
			continue
		}
		if compare(rule.Op, observed, rule.Threshold) {
			violations = append(violations, Violation{
				Rule:          rule,
				ObservedValue: observed,
				TriggeredAt:   now,
			})
		}
	}
	return violations
}

// ValidateRule returns a non-nil error if the rule has an invalid field.
func ValidateRule(r Rule) error {
	if r.Name == "" {
		return fmt.Errorf("alert: name is required")
	}
	switch r.Metric {
	case MetricFailureRate, MetricTaskDurationMinutes, MetricPendingCount, MetricCostUSD:
		// valid
	default:
		return fmt.Errorf("alert: unknown metric %q (valid: failure_rate, task_duration_minutes, pending_count, cost_usd)", r.Metric)
	}
	switch r.Op {
	case OpGt, OpLt, OpEq:
		// valid
	default:
		return fmt.Errorf("alert: unknown op %q (valid: gt, lt, eq)", r.Op)
	}
	return nil
}

// SessionCostUSD returns the cumulative cost for the current session by summing
// the cost ledger. Returns 0 on any error (best-effort).
func SessionCostUSD(workDir string) float64 {
	entries, err := cost.ReadLedger(workDir)
	if err != nil {
		return 0
	}
	var total float64
	for _, e := range entries {
		total += e.EstimatedUSD
	}
	return total
}
