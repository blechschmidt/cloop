// Package finetune exports completed task I/O pairs as JSONL files suitable
// for LLM fine-tuning. It supports OpenAI and Anthropic fine-tuning formats,
// optional quality filtering via pkg/eval, and prompt anonymization.
package finetune

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/eval"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Format is the JSONL serialization format for fine-tuning data.
type Format string

const (
	FormatOpenAI    Format = "openai"
	FormatAnthropic Format = "anthropic"
)

// ExportConfig holds all parameters for a fine-tune export run.
type ExportConfig struct {
	WorkDir    string
	OutputPath string
	Format     Format

	// MinQuality is a 0-100 quality threshold. Pairs scored below this are skipped.
	// Set to 0 to disable quality filtering.
	MinQuality int

	// Anonymize strips absolute file paths and the project directory name from prompts and outputs.
	Anonymize bool

	// Eval provider settings — required when MinQuality > 0.
	EvalProvider provider.Provider
	EvalModel    string
	EvalTimeout  time.Duration
}

// ExportResult summarises the outcome of an export run.
type ExportResult struct {
	Total      int     // candidate pairs found
	Exported   int     // pairs written to the JSONL file
	Skipped    int     // pairs skipped (low quality or missing output)
	AvgQuality float64 // average quality score (1-10) of exported pairs; 0 if no scoring
	Tokens     int     // estimated total tokens across all exported pairs
}

// openAIPair is the JSONL record format expected by the OpenAI fine-tuning API.
type openAIPair struct {
	Messages []openAIMessage `json:"messages"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// anthropicPair is the JSONL record format expected by the Anthropic fine-tuning API.
type anthropicPair struct {
	Prompt     string `json:"prompt"`
	Completion string `json:"completion"`
}

// Export scans the completed tasks in the plan, reconstructs each I/O pair,
// and writes them as JSONL to cfg.OutputPath. It returns a summary.
func Export(ctx context.Context, plan *pm.Plan, goal, instructions string, cfg ExportConfig) (*ExportResult, error) {
	if plan == nil || len(plan.Tasks) == 0 {
		return nil, fmt.Errorf("no plan found — run 'cloop run --pm' first")
	}

	// Collect done tasks.
	var doneTasks []*pm.Task
	for _, t := range plan.Tasks {
		if t.Status == pm.TaskDone {
			doneTasks = append(doneTasks, t)
		}
	}
	if len(doneTasks) == 0 {
		return &ExportResult{}, nil
	}

	// Open output file.
	outPath := cfg.OutputPath
	if outPath == "" {
		outPath = filepath.Join(cfg.WorkDir, ".cloop", "finetune.jsonl")
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open output file: %w", err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)

	result := &ExportResult{Total: len(doneTasks)}
	var qualitySum float64
	var qualityCount int

	for _, task := range doneTasks {
		// Load task output.
		output := loadOutput(cfg.WorkDir, task)
		if output == "" {
			result.Skipped++
			continue
		}

		// Reconstruct the execution prompt.
		prompt := pm.ExecuteTaskPrompt(goal, instructions, "" /* skip workDir injections */, plan, task, true)

		// Quality filter.
		var qualScore float64
		if cfg.MinQuality > 0 && cfg.EvalProvider != nil {
			rubric := eval.DefaultRubric()
			evalResult, err := eval.Evaluate(ctx, cfg.EvalProvider, cfg.EvalModel, cfg.EvalTimeout, cfg.WorkDir, task, output, rubric)
			if err != nil {
				// Non-fatal: skip this pair with a warning.
				result.Skipped++
				continue
			}
			qualScore = evalResult.Weighted
			threshold := float64(cfg.MinQuality) / 10.0
			if qualScore < threshold {
				result.Skipped++
				continue
			}
			qualitySum += qualScore
			qualityCount++
		}

		// Anonymize if requested.
		if cfg.Anonymize {
			prompt = anonymize(prompt, cfg.WorkDir)
			output = anonymize(output, cfg.WorkDir)
		}

		// Serialize.
		line, err := marshal(cfg.Format, prompt, output)
		if err != nil {
			return nil, fmt.Errorf("serialize pair for task %d: %w", task.ID, err)
		}

		if _, err := fmt.Fprintln(w, string(line)); err != nil {
			return nil, fmt.Errorf("write pair: %w", err)
		}

		result.Exported++
		result.Tokens += estimateTokens(prompt) + estimateTokens(output)
		if qualScore > 0 {
			_ = qualScore // already counted above
		}
	}

	if err := w.Flush(); err != nil {
		return nil, fmt.Errorf("flush output: %w", err)
	}

	if qualityCount > 0 {
		result.AvgQuality = qualitySum / float64(qualityCount)
	}

	return result, nil
}

// marshal encodes a single prompt/output pair in the requested format.
func marshal(format Format, prompt, output string) ([]byte, error) {
	switch format {
	case FormatAnthropic:
		return json.Marshal(anthropicPair{Prompt: prompt, Completion: output})
	default: // FormatOpenAI (default)
		return json.Marshal(openAIPair{Messages: []openAIMessage{
			{Role: "user", Content: prompt},
			{Role: "assistant", Content: output},
		}})
	}
}

// loadOutput returns the full AI output for a done task.
// It prefers the artifact file (stripping YAML frontmatter), then falls back
// to the live streaming artifact, and finally to task.Result.
func loadOutput(workDir string, task *pm.Task) string {
	// 1. Artifact markdown file (.cloop/tasks/<id>-<slug>.md)
	if task.ArtifactPath != "" {
		absPath := task.ArtifactPath
		if !filepath.IsAbs(absPath) {
			absPath = filepath.Join(workDir, absPath)
		}
		if data, err := os.ReadFile(absPath); err == nil {
			return stripFrontmatter(string(data))
		}
	}

	// 2. Live streaming artifact (.cloop/artifacts/<id>_output.txt)
	livePath := filepath.Join(workDir, ".cloop", "artifacts", fmt.Sprintf("%d_output.txt", task.ID))
	if data, err := os.ReadFile(livePath); err == nil && len(data) > 0 {
		return strings.TrimSpace(string(data))
	}

	// 3. In-state result string.
	return task.Result
}

// stripFrontmatter removes YAML frontmatter (--- ... ---\n) from s.
func stripFrontmatter(s string) string {
	if len(s) < 4 || s[:3] != "---" {
		return s
	}
	rest := s[3:]
	for i := 0; i < len(rest)-3; i++ {
		if rest[i] == '\n' && i+4 <= len(rest) && rest[i+1:i+4] == "---" {
			body := rest[i+4:]
			for len(body) > 0 && body[0] == '\n' {
				body = body[1:]
			}
			return body
		}
	}
	return s
}

// pathRe matches Unix absolute paths that are likely file system references.
var pathRe = regexp.MustCompile(`/[a-zA-Z0-9_./-]{3,}`)

// anonymize strips the workDir base path and other absolute file system paths
// from text to reduce project-specific leakage in training data.
func anonymize(text, workDir string) string {
	// Replace the literal workDir prefix.
	if workDir != "" {
		text = strings.ReplaceAll(text, workDir, "<workdir>")
		// Also replace just the project directory name if it appears standalone.
		base := filepath.Base(workDir)
		if base != "" && base != "." && base != "/" {
			text = strings.ReplaceAll(text, base, "<project>")
		}
	}
	// Replace remaining absolute Unix paths with a placeholder.
	text = pathRe.ReplaceAllStringFunc(text, func(m string) string {
		// Keep short tokens like /api, /v1 to preserve API route context.
		if len(m) <= 8 {
			return m
		}
		return "<path>"
	})
	return text
}

// estimateTokens returns a rough token count (ceil(chars/4)).
func estimateTokens(s string) int {
	return (len(s) + 3) / 4
}
