// Package promptopt implements prompt A/B testing and optimization for cloop.
// Variants are named alternatives to role-specific system prompts. Outcomes are
// recorded per variant and the best-performing variant is selected via the lower
// bound of the Wilson score confidence interval (95 %).
package promptopt

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

const (
	variantsFile = ".cloop/prompt-variants.jsonl"
	// z-score for 95 % one-sided confidence interval
	z95 = 1.645
)

// Variant is a named prompt variant for a specific agent role.
type Variant struct {
	// ID is a short unique identifier (e.g. "backend-default", "backend-concise").
	ID string
	// Role is the task role this variant applies to (empty = generic).
	Role pm.AgentRole
	// Name is a human-readable label shown in `cloop perf`.
	Name string
	// SystemPrompt is the text prepended to the task execution prompt in place of
	// the role's default RoleSystemPrompt. Empty strings inherit the default.
	SystemPrompt string
}

// OutcomeRecord is a single A/B outcome entry persisted in the variants JSONL file.
type OutcomeRecord struct {
	VariantID string    `json:"variant_id"`
	Role      string    `json:"role"`
	Success   bool      `json:"success"`
	LatencyMs int       `json:"latency_ms"`
	Ts        time.Time `json:"ts"`
}

// variantStats aggregates outcomes for a single variant ID.
type variantStats struct {
	VariantID string
	Role      pm.AgentRole
	Trials    int
	Successes int
	TotalMs   int64
}

// WinRate returns raw success rate (0.0 – 1.0).
func (s *variantStats) WinRate() float64 {
	if s.Trials == 0 {
		return 0
	}
	return float64(s.Successes) / float64(s.Trials)
}

// WilsonScore returns the lower bound of the Wilson score confidence interval
// at 95 % confidence. Higher is better for ranking.
// Formula: (p + z²/2n - z*sqrt(p(1-p)/n + z²/4n²)) / (1 + z²/n)
func (s *variantStats) WilsonScore() float64 {
	if s.Trials == 0 {
		return 0
	}
	n := float64(s.Trials)
	p := float64(s.Successes) / n
	z := z95
	z2 := z * z
	numerator := p + z2/(2*n) - z*math.Sqrt(p*(1-p)/n+z2/(4*n*n))
	denominator := 1 + z2/n
	return numerator / denominator
}

// AvgLatencyMs returns the average latency in milliseconds.
func (s *variantStats) AvgLatencyMs() int64 {
	if s.Trials == 0 {
		return 0
	}
	return s.TotalMs / int64(s.Trials)
}

// registry holds all known prompt variants, keyed by variant ID.
var registry []Variant

func init() {
	registerDefaults()
}

// registerDefaults populates the global registry with the built-in variants.
func registerDefaults() {
	for _, role := range []pm.AgentRole{
		pm.RoleBackend, pm.RoleFrontend, pm.RoleTesting, pm.RoleSecurity,
		pm.RoleDevOps, pm.RoleData, pm.RoleDocs, pm.RoleReview, "",
	} {
		base := pm.RoleSystemPrompt(role)
		roleStr := string(role)
		if roleStr == "" {
			roleStr = "generic"
		}

		// Variant 0: default — identical to the existing RoleSystemPrompt
		registry = append(registry, Variant{
			ID:           roleStr + "-default",
			Role:         role,
			Name:         "Default",
			SystemPrompt: base,
		})

		// Variant 1: concise — short, action-focused preamble
		registry = append(registry, Variant{
			ID:           roleStr + "-concise",
			Role:         role,
			Name:         "Concise",
			SystemPrompt: buildConciseVariant(role),
		})

		// Variant 2: methodical — step-by-step, explicit verification
		registry = append(registry, Variant{
			ID:           roleStr + "-methodical",
			Role:         role,
			Name:         "Methodical",
			SystemPrompt: buildMethodicalVariant(role),
		})

		// Variant 3: defensive — prioritises correctness, safety, and testing
		registry = append(registry, Variant{
			ID:           roleStr + "-defensive",
			Role:         role,
			Name:         "Defensive",
			SystemPrompt: buildDefensiveVariant(role),
		})
	}
}

// buildConciseVariant returns a short, direct system prompt for the role.
func buildConciseVariant(role pm.AgentRole) string {
	roleDesc := roleDescription(role)
	if roleDesc == "" {
		return "You are an expert engineer. Be concise, direct, and correct. Complete each task fully on the first attempt.\n\n"
	}
	return fmt.Sprintf("You are a %s. Be concise, direct, and correct. Complete each task fully on the first attempt.\n\n", roleDesc)
}

// buildMethodicalVariant returns a step-by-step, verification-oriented prompt.
func buildMethodicalVariant(role pm.AgentRole) string {
	roleDesc := roleDescription(role)
	prefix := "You are an expert engineer"
	if roleDesc != "" {
		prefix = "You are a " + roleDesc
	}
	return prefix + `. Work methodically: (1) read and understand the task requirements,
(2) identify dependencies and edge cases, (3) implement the solution incrementally,
(4) verify each step with tests or builds before proceeding, (5) confirm the result is correct.
Do not skip verification steps.

`
}

// buildDefensiveVariant returns a safety- and testing-focused prompt.
func buildDefensiveVariant(role pm.AgentRole) string {
	roleDesc := roleDescription(role)
	prefix := "You are an expert engineer"
	if roleDesc != "" {
		prefix = "You are a " + roleDesc
	}
	return prefix + `. Prioritise correctness and safety above all else.
Validate all inputs, handle every error explicitly, and never swallow exceptions.
Write or run tests before declaring success. If anything is ambiguous, choose the
conservative, defensive interpretation. When in doubt, fail loudly rather than
silently.

`
}

// roleDescription returns a short human label for a role (for embedding in prompts).
func roleDescription(role pm.AgentRole) string {
	switch role {
	case pm.RoleBackend:
		return "senior backend engineer"
	case pm.RoleFrontend:
		return "senior frontend engineer"
	case pm.RoleTesting:
		return "test engineering expert"
	case pm.RoleSecurity:
		return "security engineer"
	case pm.RoleDevOps:
		return "DevOps/platform engineer"
	case pm.RoleData:
		return "data engineer"
	case pm.RoleDocs:
		return "technical writer and documentation engineer"
	case pm.RoleReview:
		return "code reviewer and refactoring expert"
	default:
		return ""
	}
}

// LoadVariants returns all registered prompt variants for the given role.
// Pass an empty role string to get variants that apply to every task.
func LoadVariants(role pm.AgentRole) []Variant {
	var out []Variant
	for _, v := range registry {
		if v.Role == role {
			out = append(out, v)
		}
	}
	return out
}

// VariantByID returns the variant with the given ID, or the zero Variant if not found.
func VariantByID(id string) (Variant, bool) {
	for _, v := range registry {
		if v.ID == id {
			return v, true
		}
	}
	return Variant{}, false
}

// RecordOutcome appends an outcome for the given variant to the JSONL file.
func RecordOutcome(workDir, variantID string, success bool, latencyMs int) error {
	v, ok := VariantByID(variantID)
	role := ""
	if ok {
		role = string(v.Role)
	}
	rec := OutcomeRecord{
		VariantID: variantID,
		Role:      role,
		Success:   success,
		LatencyMs: latencyMs,
		Ts:        time.Now().UTC(),
	}
	path := filepath.Join(workDir, variantsFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("promptopt mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("promptopt open: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return fmt.Errorf("promptopt encode: %w", err)
	}
	return nil
}

// LoadOutcomes reads all outcome records from the JSONL file.
// Returns nil, nil when the file does not exist yet.
func LoadOutcomes(workDir string) ([]OutcomeRecord, error) {
	path := filepath.Join(workDir, variantsFile)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("promptopt open: %w", err)
	}
	defer f.Close()

	var records []OutcomeRecord
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var rec OutcomeRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		records = append(records, rec)
	}
	return records, scanner.Err()
}

// statsForRole aggregates outcomes per variant for a given role.
func statsForRole(records []OutcomeRecord, role pm.AgentRole) map[string]*variantStats {
	stats := make(map[string]*variantStats)
	roleStr := string(role)
	for _, r := range records {
		if r.Role != roleStr {
			continue
		}
		st, ok := stats[r.VariantID]
		if !ok {
			st = &variantStats{VariantID: r.VariantID, Role: role}
			stats[r.VariantID] = st
		}
		st.Trials++
		st.TotalMs += int64(r.LatencyMs)
		if r.Success {
			st.Successes++
		}
	}
	return stats
}

// BestVariant returns the variant with the highest Wilson lower-bound score for
// the given role, using outcome data recorded in workDir. It falls back to the
// default variant when there is no data yet.
func BestVariant(workDir string, role pm.AgentRole) Variant {
	defaultVariant := defaultVariantFor(role)

	records, err := LoadOutcomes(workDir)
	if err != nil || len(records) == 0 {
		return defaultVariant
	}

	stats := statsForRole(records, role)
	if len(stats) == 0 {
		return defaultVariant
	}

	// Collect stats for all known variants for this role, even those with no data.
	var ranked []*variantStats
	for _, v := range LoadVariants(role) {
		st, ok := stats[v.ID]
		if !ok {
			st = &variantStats{VariantID: v.ID, Role: role}
		}
		ranked = append(ranked, st)
	}

	// Sort descending by Wilson lower bound; ties broken by raw win rate, then ID.
	sort.Slice(ranked, func(i, j int) bool {
		si := ranked[i].WilsonScore()
		sj := ranked[j].WilsonScore()
		if si != sj {
			return si > sj
		}
		wi := ranked[i].WinRate()
		wj := ranked[j].WinRate()
		if wi != wj {
			return wi > wj
		}
		return ranked[i].VariantID < ranked[j].VariantID
	})

	if len(ranked) > 0 {
		if v, ok := VariantByID(ranked[0].VariantID); ok {
			return v
		}
	}
	return defaultVariant
}

// NextBestVariant returns the next best variant that is NOT the currently active
// variantID. Used by the orchestrator when switching on heal attempts.
func NextBestVariant(workDir string, role pm.AgentRole, currentVariantID string) Variant {
	records, _ := LoadOutcomes(workDir)
	stats := statsForRole(records, role)

	var ranked []*variantStats
	for _, v := range LoadVariants(role) {
		if v.ID == currentVariantID {
			continue
		}
		st, ok := stats[v.ID]
		if !ok {
			st = &variantStats{VariantID: v.ID, Role: role}
		}
		ranked = append(ranked, st)
	}

	sort.Slice(ranked, func(i, j int) bool {
		si := ranked[i].WilsonScore()
		sj := ranked[j].WilsonScore()
		if si != sj {
			return si > sj
		}
		wi := ranked[i].WinRate()
		wj := ranked[j].WinRate()
		if wi != wj {
			return wi > wj
		}
		return ranked[i].VariantID < ranked[j].VariantID
	})

	if len(ranked) > 0 {
		if v, ok := VariantByID(ranked[0].VariantID); ok {
			return v
		}
	}
	return defaultVariantFor(role)
}

// defaultVariantFor returns the built-in default variant for a role.
func defaultVariantFor(role pm.AgentRole) Variant {
	roleStr := string(role)
	if roleStr == "" {
		roleStr = "generic"
	}
	if v, ok := VariantByID(roleStr + "-default"); ok {
		return v
	}
	return Variant{ID: roleStr + "-default", Role: role, Name: "Default", SystemPrompt: pm.RoleSystemPrompt(role)}
}

// RoleStats returns per-variant statistics for a single role, sorted by Wilson score.
func RoleStats(workDir string, role pm.AgentRole) ([]*VariantStat, error) {
	records, err := LoadOutcomes(workDir)
	if err != nil {
		return nil, err
	}
	rawStats := statsForRole(records, role)

	var out []*VariantStat
	for _, v := range LoadVariants(role) {
		st, ok := rawStats[v.ID]
		if !ok {
			st = &variantStats{VariantID: v.ID, Role: role}
		}
		out = append(out, &VariantStat{
			Variant:     v,
			Trials:      st.Trials,
			Successes:   st.Successes,
			Failures:    st.Trials - st.Successes,
			AvgLatency:  st.AvgLatencyMs(),
			WinRate:     st.WinRate(),
			Wilson:      st.WilsonScore(),
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Wilson != out[j].Wilson {
			return out[i].Wilson > out[j].Wilson
		}
		return out[i].WinRate > out[j].WinRate
	})
	return out, nil
}

// VariantStat is the public view of aggregated statistics for one variant.
type VariantStat struct {
	Variant    Variant
	Trials     int
	Successes  int
	Failures   int
	AvgLatency int64   // milliseconds
	WinRate    float64 // 0.0 – 1.0
	Wilson     float64 // Wilson lower-bound score (used for ranking)
}

// AllRoles returns the list of roles that have at least one registered variant.
func AllRoles() []pm.AgentRole {
	seen := make(map[pm.AgentRole]bool)
	var roles []pm.AgentRole
	for _, v := range registry {
		if !seen[v.Role] {
			seen[v.Role] = true
			roles = append(roles, v.Role)
		}
	}
	return roles
}
