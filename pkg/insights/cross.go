package insights

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/workspace"
)

// ProjectSnapshot holds the metrics collected from a single project.
type ProjectSnapshot struct {
	Name            string
	Path            string
	Goal            string
	Provider        string
	TotalTasks      int
	DoneTasks       int
	FailedTasks     int
	SkippedTasks    int
	PendingTasks    int
	CompletionPct   float64
	Tags            []string // deduplicated tags from all tasks
	Roles           []string // deduplicated roles from all tasks
	FailureReasons  []string // short failure summaries from task results
	VelocityPerDay  float64
	AvgTaskDuration time.Duration
	LastUpdated     time.Time
	Error           string // non-empty if loading failed
}

// CrossMetrics aggregates metrics across multiple projects.
type CrossMetrics struct {
	Projects []ProjectSnapshot

	TotalProjects     int
	ActiveProjects    int // projects with at least one task
	TotalTasksAcross  int
	TotalDoneAcross   int
	TotalFailedAcross int

	AvgCompletionRate float64 // mean completion % across projects

	TopTags             []TagCount
	TopRoles            []TagCount
	TopFailureKeywords  []TagCount

	ProviderCounts map[string]int

	VelocityMin  float64
	VelocityMax  float64
	VelocityMean float64
}

// TagCount pairs a label with its frequency.
type TagCount struct {
	Label string
	Count int
}

// CrossInsightReport is the full result of a cross-project analysis.
type CrossInsightReport struct {
	Metrics         *CrossMetrics
	VelocityTrends  string
	FailurePatterns string
	ProviderPerf    string
	Recommendations string
	GeneratedAt     time.Time
}

// CollectFromProject reads one project's state and builds a ProjectSnapshot.
// Returns a snapshot with Error set if loading failed (non-fatal).
func CollectFromProject(name, path string) *ProjectSnapshot {
	snap := &ProjectSnapshot{Name: name, Path: path}

	s, err := state.Load(path)
	if err != nil {
		snap.Error = err.Error()
		return snap
	}

	snap.Goal = s.Goal
	snap.Provider = s.Provider
	snap.LastUpdated = s.UpdatedAt

	if s.Plan == nil {
		return snap
	}

	tagSet := make(map[string]struct{})
	roleSet := make(map[string]struct{})

	var completedTimes []time.Time
	var durations []time.Duration

	for _, t := range s.Plan.Tasks {
		snap.TotalTasks++
		for _, tag := range t.Tags {
			if tag != "" {
				tagSet[tag] = struct{}{}
			}
		}
		if t.Role != "" {
			roleSet[string(t.Role)] = struct{}{}
		}

		switch t.Status {
		case pm.TaskDone:
			snap.DoneTasks++
			if t.CompletedAt != nil {
				completedTimes = append(completedTimes, *t.CompletedAt)
			}
			if t.StartedAt != nil && t.CompletedAt != nil {
				durations = append(durations, t.CompletedAt.Sub(*t.StartedAt))
			}
		case pm.TaskFailed:
			snap.FailedTasks++
			if t.Result != "" {
				snap.FailureReasons = append(snap.FailureReasons, crossSummarize(t.Result, 80))
			}
		case pm.TaskSkipped:
			snap.SkippedTasks++
		case pm.TaskPending:
			snap.PendingTasks++
		}
	}

	if snap.TotalTasks > 0 {
		snap.CompletionPct = float64(snap.DoneTasks+snap.SkippedTasks) * 100 / float64(snap.TotalTasks)
	}

	if len(completedTimes) >= 2 {
		sort.Slice(completedTimes, func(i, j int) bool { return completedTimes[i].Before(completedTimes[j]) })
		span := completedTimes[len(completedTimes)-1].Sub(completedTimes[0])
		days := span.Hours() / 24
		if days > 0 {
			snap.VelocityPerDay = float64(len(completedTimes)) / days
		}
	} else if len(completedTimes) == 1 {
		snap.VelocityPerDay = 1.0
	}

	if len(durations) > 0 {
		var total time.Duration
		for _, d := range durations {
			total += d
		}
		snap.AvgTaskDuration = total / time.Duration(len(durations))
	}

	// Supplement failure reasons with diagnosis artifact files.
	snap.FailureReasons = append(snap.FailureReasons, collectDiagnosisArtifacts(path)...)

	for tag := range tagSet {
		snap.Tags = append(snap.Tags, tag)
	}
	sort.Strings(snap.Tags)

	for role := range roleSet {
		snap.Roles = append(snap.Roles, role)
	}
	sort.Strings(snap.Roles)

	return snap
}

// collectDiagnosisArtifacts reads .cloop/tasks/*-diagnosis.md files and
// returns short failure summaries extracted from them.
func collectDiagnosisArtifacts(workDir string) []string {
	dir := filepath.Join(workDir, ".cloop", "tasks")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var reasons []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "-diagnosis.md") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		inFrontmatter := false
		frontmatterDone := false
		lineCount := 0
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "---" {
				if !inFrontmatter {
					inFrontmatter = true
				} else {
					frontmatterDone = true
				}
				continue
			}
			if !frontmatterDone {
				continue
			}
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			reasons = append(reasons, crossSummarize(line, 80))
			lineCount++
			if lineCount >= 2 {
				break
			}
		}
		f.Close()
	}
	return reasons
}

// wsEntry is a simple name/path pair used internally for workspace enumeration.
type wsEntry struct{ Name, Path string }

// CollectFromWorkspaces loads all registered workspaces and returns per-project
// snapshots. Uses wsFile if non-empty, otherwise the global workspace registry.
func CollectFromWorkspaces(wsFile string) ([]*ProjectSnapshot, error) {
	var entries []wsEntry

	if wsFile != "" {
		ws, err := readLocalWorkspaceFile(wsFile)
		if err != nil {
			return nil, fmt.Errorf("reading workspace file %s: %w", wsFile, err)
		}
		entries = ws
	} else {
		list, err := workspace.List()
		if err != nil {
			return nil, fmt.Errorf("listing workspaces: %w", err)
		}
		for _, w := range list {
			entries = append(entries, wsEntry{w.Name, w.Path})
		}
	}

	if len(entries) == 0 {
		return nil, nil
	}

	snaps := make([]*ProjectSnapshot, 0, len(entries))
	for i := range entries {
		snaps = append(snaps, CollectFromProject(entries[i].Name, entries[i].Path))
	}
	return snaps, nil
}

// readLocalWorkspaceFile parses a workspace JSON file.
// Supports both {"workspaces":[...]} (global registry format) and
// a bare array [{"name":"","path":""}] (local format).
func readLocalWorkspaceFile(path string) ([]wsEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	type jsonEntry struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	type registryFmt struct {
		Workspaces []jsonEntry `json:"workspaces"`
	}

	var reg registryFmt
	if err := json.Unmarshal(data, &reg); err == nil && len(reg.Workspaces) > 0 {
		out := make([]wsEntry, len(reg.Workspaces))
		for i, e := range reg.Workspaces {
			out[i] = wsEntry{e.Name, e.Path}
		}
		return out, nil
	}

	var arr []jsonEntry
	if err := json.Unmarshal(data, &arr); err == nil && len(arr) > 0 {
		out := make([]wsEntry, len(arr))
		for i, e := range arr {
			out[i] = wsEntry{e.Name, e.Path}
		}
		return out, nil
	}

	return nil, fmt.Errorf("unrecognised workspace file format (expected object with .workspaces array or bare array)")
}

// AggregateProjects computes cross-project metrics from a list of snapshots.
func AggregateProjects(snaps []*ProjectSnapshot) *CrossMetrics {
	m := &CrossMetrics{
		Projects:       make([]ProjectSnapshot, 0, len(snaps)),
		ProviderCounts: make(map[string]int),
		VelocityMin:    -1,
	}

	tagFreq := make(map[string]int)
	roleFreq := make(map[string]int)
	failureTokenFreq := make(map[string]int)

	var totalCompletionPct float64
	var velocities []float64

	for _, snap := range snaps {
		m.Projects = append(m.Projects, *snap)
		m.TotalProjects++

		if snap.TotalTasks > 0 {
			m.ActiveProjects++
		}
		m.TotalTasksAcross += snap.TotalTasks
		m.TotalDoneAcross += snap.DoneTasks
		m.TotalFailedAcross += snap.FailedTasks
		totalCompletionPct += snap.CompletionPct

		if snap.Provider != "" {
			m.ProviderCounts[snap.Provider]++
		}

		for _, tag := range snap.Tags {
			tagFreq[tag]++
		}
		for _, role := range snap.Roles {
			roleFreq[role]++
		}
		for _, reason := range snap.FailureReasons {
			for _, word := range crossTokenize(reason) {
				failureTokenFreq[word]++
			}
		}

		if snap.VelocityPerDay > 0 {
			velocities = append(velocities, snap.VelocityPerDay)
			if m.VelocityMin < 0 || snap.VelocityPerDay < m.VelocityMin {
				m.VelocityMin = snap.VelocityPerDay
			}
			if snap.VelocityPerDay > m.VelocityMax {
				m.VelocityMax = snap.VelocityPerDay
			}
		}
	}

	if m.TotalProjects > 0 {
		m.AvgCompletionRate = totalCompletionPct / float64(m.TotalProjects)
	}

	if len(velocities) > 0 {
		sum := 0.0
		for _, v := range velocities {
			sum += v
		}
		m.VelocityMean = sum / float64(len(velocities))
	}
	if m.VelocityMin < 0 {
		m.VelocityMin = 0
	}

	m.TopTags = crossTopN(tagFreq, 10)
	m.TopRoles = crossTopN(roleFreq, 8)
	m.TopFailureKeywords = crossTopN(failureTokenFreq, 10)

	return m
}

// CrossInsightPrompt builds the AI prompt for cross-project analysis.
func CrossInsightPrompt(m *CrossMetrics) string {
	var b strings.Builder

	b.WriteString("You are an expert AI engineering advisor analyzing patterns across multiple software projects.\n\n")
	b.WriteString("## AGGREGATE METRICS\n")
	b.WriteString(fmt.Sprintf("- Projects analyzed: %d (%d with tasks)\n", m.TotalProjects, m.ActiveProjects))
	b.WriteString(fmt.Sprintf("- Total tasks: %d\n", m.TotalTasksAcross))
	b.WriteString(fmt.Sprintf("- Total completed: %d\n", m.TotalDoneAcross))
	b.WriteString(fmt.Sprintf("- Total failed: %d\n", m.TotalFailedAcross))
	b.WriteString(fmt.Sprintf("- Average completion rate: %.0f%%\n", m.AvgCompletionRate))
	if m.VelocityMean > 0 {
		b.WriteString(fmt.Sprintf("- Velocity: min=%.1f, mean=%.1f, max=%.1f tasks/day\n",
			m.VelocityMin, m.VelocityMean, m.VelocityMax))
	}

	if len(m.ProviderCounts) > 0 {
		b.WriteString("\n## PROVIDER USAGE\n")
		for prov, cnt := range m.ProviderCounts {
			b.WriteString(fmt.Sprintf("- %s: %d project(s)\n", prov, cnt))
		}
	}

	if len(m.TopTags) > 0 {
		b.WriteString("\n## TOP TASK CATEGORIES (by tag frequency)\n")
		for _, tc := range m.TopTags {
			b.WriteString(fmt.Sprintf("- %s (%d)\n", tc.Label, tc.Count))
		}
	}

	if len(m.TopRoles) > 0 {
		b.WriteString("\n## TOP ROLES\n")
		for _, tc := range m.TopRoles {
			b.WriteString(fmt.Sprintf("- %s (%d)\n", tc.Label, tc.Count))
		}
	}

	if len(m.TopFailureKeywords) > 0 {
		b.WriteString("\n## COMMON FAILURE KEYWORDS\n")
		for _, tc := range m.TopFailureKeywords {
			b.WriteString(fmt.Sprintf("- %s (%d)\n", tc.Label, tc.Count))
		}
	}

	b.WriteString("\n## PER-PROJECT SUMMARY\n")
	for _, p := range m.Projects {
		if p.Error != "" {
			b.WriteString(fmt.Sprintf("- %s: ERROR (%s)\n", p.Name, p.Error))
			continue
		}
		b.WriteString(fmt.Sprintf("- %s: %d/%d done (%.0f%%), %d failed, velocity=%.1f/day",
			p.Name, p.DoneTasks, p.TotalTasks, p.CompletionPct, p.FailedTasks, p.VelocityPerDay))
		if p.Provider != "" {
			b.WriteString(fmt.Sprintf(", provider=%s", p.Provider))
		}
		b.WriteString("\n")
		if p.Goal != "" {
			b.WriteString(fmt.Sprintf("  Goal: %s\n", crossSummarize(p.Goal, 80)))
		}
	}

	b.WriteString(`
## ANALYSIS REQUEST
Produce a cross-project insights report with exactly these four sections:

**1. Velocity Trends**
Compare velocity across projects. Identify which projects are fast/slow and why. Highlight patterns (e.g. smaller plans finish faster, certain task types slow teams down).

**2. Failure Patterns**
Identify common failure themes across projects. Which task types or categories fail most? Are there systemic issues? Provide specific evidence from the data.

**3. Provider Performance**
Compare how different AI providers perform across projects (completion rates, velocity). Recommend provider/model routing strategies if patterns are clear.

**4. Recommendations**
3-5 concrete, cross-cutting recommendations ordered by impact. Be specific — reference actual project names and metrics where helpful.

Keep each section concise (3-6 sentences or bullet points). Focus on actionable patterns, not generic advice.
`)

	return b.String()
}

// GenerateCross runs AI analysis on cross-project metrics and returns a structured report.
func GenerateCross(ctx context.Context, p provider.Provider, model string, timeout time.Duration, snaps []*ProjectSnapshot) (*CrossInsightReport, error) {
	m := AggregateProjects(snaps)

	prompt := CrossInsightPrompt(m)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("cross-project insights: %w", err)
	}

	report := &CrossInsightReport{
		Metrics:     m,
		GeneratedAt: time.Now(),
	}

	raw := result.Output
	report.VelocityTrends = extractSection(raw, "Velocity Trends")
	report.FailurePatterns = extractSection(raw, "Failure Patterns")
	report.ProviderPerf = extractSection(raw, "Provider Performance")
	report.Recommendations = extractSection(raw, "Recommendations")

	// Fallback: put everything in recommendations if section parsing yields nothing.
	if report.VelocityTrends == "" && report.FailurePatterns == "" &&
		report.ProviderPerf == "" && report.Recommendations == "" {
		report.Recommendations = raw
	}

	return report, nil
}

// extractSection pulls the content under a markdown section heading from AI output.
// It matches headings like "**1. Velocity Trends**" or "## Velocity Trends".
func extractSection(text, heading string) string {
	lines := strings.Split(text, "\n")
	var out []string
	inSection := false

	for _, line := range lines {
		// Check if this line is a heading containing our target.
		stripped := strings.TrimLeft(line, "#* \t")
		stripped = strings.TrimRight(stripped, "#* \t")
		// Remove numbering like "1. "
		if len(stripped) > 3 && stripped[1] == '.' && stripped[2] == ' ' {
			stripped = stripped[3:]
		}

		if strings.Contains(stripped, heading) && (strings.HasPrefix(line, "#") || strings.HasPrefix(line, "**")) {
			inSection = true
			continue
		}

		if inSection {
			// A new heading ends the current section.
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "**") {
				isNewHeading := false
				inner := strings.TrimLeft(line, "#* \t")
				inner = strings.TrimRight(inner, "#* \t")
				if len(inner) > 3 && inner[1] == '.' && inner[2] == ' ' {
					inner = inner[3:]
				}
				if len(inner) > 0 && len(inner) < 60 {
					isNewHeading = true
				}
				if isNewHeading && !strings.Contains(inner, heading) {
					break
				}
			}
			out = append(out, line)
		}
	}

	return strings.TrimSpace(strings.Join(out, "\n"))
}

// crossSummarize truncates a string to maxLen characters.
func crossSummarize(s string, maxLen int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// crossTokenize splits a failure string into meaningful keywords (len >= 4, skip stop words).
func crossTokenize(s string) []string {
	stopWords := map[string]bool{
		"the": true, "and": true, "for": true, "with": true, "from": true,
		"this": true, "that": true, "have": true, "been": true, "were": true,
		"task": true, "failed": true, "error": true, "could": true, "would": true,
	}
	words := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return r == ' ' || r == ',' || r == '.' || r == ':' || r == ';' ||
			r == '(' || r == ')' || r == '"' || r == '\''
	})
	var out []string
	seen := make(map[string]bool)
	for _, w := range words {
		if len(w) < 4 || stopWords[w] || seen[w] {
			continue
		}
		seen[w] = true
		out = append(out, w)
	}
	return out
}

// crossTopN returns the top N entries from a frequency map, sorted descending by count.
func crossTopN(freq map[string]int, n int) []TagCount {
	counts := make([]TagCount, 0, len(freq))
	for k, v := range freq {
		counts = append(counts, TagCount{k, v})
	}
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].Count != counts[j].Count {
			return counts[i].Count > counts[j].Count
		}
		return counts[i].Label < counts[j].Label
	})
	if len(counts) > n {
		counts = counts[:n]
	}
	return counts
}
