// Package contextgraph builds a directed knowledge graph that links tasks,
// their dependency edges, associated file artifacts, KB entries, task
// annotations, and git commits into a single queryable structure.
//
// Supported output formats:
//   - json     — {nodes:[{id,type,label}], edges:[{from,to,rel}]}
//   - dot      — Graphviz DOT digraph (pipe through dot -Tpng etc.)
//   - mermaid  — Mermaid flowchart TD wrapped in a fenced code block
package contextgraph

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/kb"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/trace"
)

// NodeType identifies what kind of entity a graph node represents.
type NodeType string

const (
	NodeTask       NodeType = "task"
	NodeArtifact   NodeType = "artifact"
	NodeKB         NodeType = "kb"
	NodeAnnotation NodeType = "annotation"
	NodeCommit     NodeType = "commit"
)

// Node is a single vertex in the context graph.
type Node struct {
	ID    string   `json:"id"`
	Type  NodeType `json:"type"`
	Label string   `json:"label"`
	// Extra is format-specific metadata (not included in JSON output but used for rendering).
	Status string `json:"status,omitempty"` // for task nodes: pending/in_progress/done/failed/skipped
}

// EdgeRel names the semantic relationship between two nodes.
type EdgeRel string

const (
	RelDependsOn  EdgeRel = "depends_on"  // task → task
	RelProduced   EdgeRel = "produced"    // task → artifact
	RelAnnotated  EdgeRel = "annotated"   // task → annotation
	RelLinkedKB   EdgeRel = "linked_kb"   // task → kb
	RelCommit     EdgeRel = "commit"      // commit → task
)

// Edge is a directed edge in the context graph.
type Edge struct {
	From string  `json:"from"`
	To   string  `json:"to"`
	Rel  EdgeRel `json:"rel"`
}

// Graph is the full context graph.
type Graph struct {
	Nodes []*Node `json:"nodes"`
	Edges []*Edge `json:"edges"`
}

// Collect builds the context graph from all available project data in workDir.
// Non-fatal sources (artifacts, KB, trace) are silently skipped if unavailable.
func Collect(workDir string) (*Graph, error) {
	g := &Graph{}

	s, err := state.Load(workDir)
	if err != nil || s == nil || !s.PMMode || s.Plan == nil {
		// No active plan — still continue for KB / commit nodes.
		s = nil
	}

	// ── Task nodes & dependency edges ────────────────────────────────────────
	taskByID := map[int]*Node{}
	if s != nil && s.Plan != nil {
		for _, t := range s.Plan.Tasks {
			n := &Node{
				ID:     fmt.Sprintf("task:%d", t.ID),
				Type:   NodeTask,
				Label:  fmt.Sprintf("#%d %s", t.ID, t.Title),
				Status: string(t.Status),
			}
			g.Nodes = append(g.Nodes, n)
			taskByID[t.ID] = n

			// Dependency edges
			for _, depID := range t.DependsOn {
				g.Edges = append(g.Edges, &Edge{
					From: fmt.Sprintf("task:%d", t.ID),
					To:   fmt.Sprintf("task:%d", depID),
					Rel:  RelDependsOn,
				})
			}

			// Annotation nodes
			for i, ann := range t.Annotations {
				annID := fmt.Sprintf("annotation:task%d:%d", t.ID, i)
				short := ann.Text
				if len(short) > 60 {
					short = short[:57] + "..."
				}
				g.Nodes = append(g.Nodes, &Node{
					ID:    annID,
					Type:  NodeAnnotation,
					Label: fmt.Sprintf("[%s] %s", ann.Author, short),
				})
				g.Edges = append(g.Edges, &Edge{
					From: n.ID,
					To:   annID,
					Rel:  RelAnnotated,
				})
			}
		}
	}

	// ── Artifact nodes ────────────────────────────────────────────────────────
	artDirs := []string{
		filepath.Join(workDir, ".cloop", "artifacts"),
		filepath.Join(workDir, ".cloop", "tasks"),
	}
	for _, dir := range artDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			artID := fmt.Sprintf("artifact:%s", name)
			g.Nodes = append(g.Nodes, &Node{
				ID:    artID,
				Type:  NodeArtifact,
				Label: name,
			})
			// Try to link artifact to a task by numeric prefix in the filename.
			// Convention: <taskID>-<slug>-<event>-<ts>.md
			taskID := extractLeadingInt(name)
			if taskID > 0 {
				if tn, ok := taskByID[taskID]; ok {
					g.Edges = append(g.Edges, &Edge{
						From: tn.ID,
						To:   artID,
						Rel:  RelProduced,
					})
				}
			}
		}
	}

	// ── KB entry nodes ────────────────────────────────────────────────────────
	kbStore, _ := kb.Load(workDir)
	if kbStore != nil {
		for _, entry := range kbStore.Entries {
			kbID := fmt.Sprintf("kb:%d", entry.ID)
			g.Nodes = append(g.Nodes, &Node{
				ID:    kbID,
				Type:  NodeKB,
				Label: entry.Title,
			})
			// Link KB entries to tasks whose tags overlap with the KB entry's tags.
			if s != nil && s.Plan != nil {
				for _, t := range s.Plan.Tasks {
					if tagsOverlap(t.Tags, entry.Tags) {
						g.Edges = append(g.Edges, &Edge{
							From: fmt.Sprintf("task:%d", t.ID),
							To:   kbID,
							Rel:  RelLinkedKB,
						})
					}
				}
			}
		}
	}

	// ── Git commit nodes (via cached trace.json) ──────────────────────────────
	tm, _ := trace.LoadTraceJSON(workDir)
	if tm != nil {
		for _, entry := range tm.Entries {
			commitID := fmt.Sprintf("commit:%s", entry.Hash)
			label := entry.Hash
			if len(entry.Subject) > 0 {
				sub := entry.Subject
				if len(sub) > 60 {
					sub = sub[:57] + "..."
				}
				label = fmt.Sprintf("%s %s", entry.Hash, sub)
			}
			g.Nodes = append(g.Nodes, &Node{
				ID:    commitID,
				Type:  NodeCommit,
				Label: label,
			})
			if entry.MatchedTaskID > 0 {
				g.Edges = append(g.Edges, &Edge{
					From: commitID,
					To:   fmt.Sprintf("task:%d", entry.MatchedTaskID),
					Rel:  RelCommit,
				})
			}
		}
	}

	return g, nil
}

// ── Renderers ─────────────────────────────────────────────────────────────────

// RenderJSON serialises the graph as indented JSON.
func RenderJSON(g *Graph) (string, error) {
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// RenderDOT produces a Graphviz DOT digraph.
//
// Node shapes and fill colours by type:
//   - task       → box, colour by status (green/yellow/red/grey)
//   - artifact   → note shape, light blue
//   - kb         → ellipse, lavender
//   - annotation → plaintext box, light yellow
//   - commit     → hexagon, light orange
func RenderDOT(g *Graph) string {
	var sb strings.Builder
	sb.WriteString("digraph context {\n")
	sb.WriteString("  graph [rankdir=LR fontname=\"Helvetica\"];\n")
	sb.WriteString("  node  [fontname=\"Helvetica\" fontsize=11];\n")
	sb.WriteString("  edge  [fontsize=9];\n\n")

	for _, n := range g.Nodes {
		dotID := dotEscape(n.ID)
		label := dotLabelEscape(n.Label)
		attrs := dotNodeAttrs(n)
		sb.WriteString(fmt.Sprintf("  %s [label=%q %s];\n", dotID, label, attrs))
	}
	sb.WriteByte('\n')

	for _, e := range g.Edges {
		from := dotEscape(e.From)
		to := dotEscape(e.To)
		color := edgeDotColor(e.Rel)
		sb.WriteString(fmt.Sprintf("  %s -> %s [label=%q color=%q];\n", from, to, string(e.Rel), color))
	}

	sb.WriteString("}\n")
	return sb.String()
}

// RenderMermaid produces a Mermaid flowchart (TD direction).
func RenderMermaid(g *Graph) string {
	var sb strings.Builder
	sb.WriteString("```mermaid\nflowchart LR\n")

	for _, n := range g.Nodes {
		mID := mermaidID(n.ID)
		label := mermaidLabelEscape(n.Label)
		shape := mermaidShape(n)
		sb.WriteString(fmt.Sprintf("  %s%s\n", mID, shape(label)))
	}
	sb.WriteByte('\n')

	for _, e := range g.Edges {
		from := mermaidID(e.From)
		to := mermaidID(e.To)
		arrow := mermaidArrow(e.Rel)
		sb.WriteString(fmt.Sprintf("  %s%s%s\n", from, arrow, to))
	}

	// Style classes
	sb.WriteString("\n  classDef task    fill:#d4edda,stroke:#28a745,color:#000\n")
	sb.WriteString("  classDef artifact fill:#cce5ff,stroke:#004085,color:#000\n")
	sb.WriteString("  classDef kb       fill:#e2d9f3,stroke:#6f42c1,color:#000\n")
	sb.WriteString("  classDef ann      fill:#fff3cd,stroke:#856404,color:#000\n")
	sb.WriteString("  classDef commit   fill:#fde8d8,stroke:#c04b00,color:#000\n")

	// Apply classes
	for _, n := range g.Nodes {
		mID := mermaidID(n.ID)
		cls := mermaidClass(n.Type)
		if cls != "" {
			sb.WriteString(fmt.Sprintf("  class %s %s\n", mID, cls))
		}
	}

	sb.WriteString("```\n")
	return sb.String()
}

// ── helpers ───────────────────────────────────────────────────────────────────

func dotNodeAttrs(n *Node) string {
	switch n.Type {
	case NodeTask:
		fill := taskDotFill(n.Status)
		return fmt.Sprintf("shape=box style=filled fillcolor=%q", fill)
	case NodeArtifact:
		return `shape=note style=filled fillcolor="#cce5ff"`
	case NodeKB:
		return `shape=ellipse style=filled fillcolor="#e2d9f3"`
	case NodeAnnotation:
		return `shape=box style="filled,dashed" fillcolor="#fff3cd"`
	case NodeCommit:
		return `shape=hexagon style=filled fillcolor="#fde8d8"`
	default:
		return ""
	}
}

func taskDotFill(status string) string {
	switch status {
	case "done":
		return "#d4edda"
	case "in_progress":
		return "#fff3cd"
	case "failed", "timed_out":
		return "#f8d7da"
	case "skipped":
		return "#e2e3e5"
	default:
		return "#ffffff"
	}
}

func edgeDotColor(rel EdgeRel) string {
	switch rel {
	case RelDependsOn:
		return "#6c757d"
	case RelProduced:
		return "#0056b3"
	case RelAnnotated:
		return "#856404"
	case RelLinkedKB:
		return "#6f42c1"
	case RelCommit:
		return "#c04b00"
	default:
		return "#000000"
	}
}

func dotEscape(s string) string {
	// Replace characters that are invalid in DOT node identifiers.
	r := strings.NewReplacer(":", "_", " ", "_", "#", "_", ".", "_", "/", "_", "-", "_")
	return r.Replace(s)
}

func dotLabelEscape(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}

type shapeFunc func(label string) string

func mermaidShape(n *Node) shapeFunc {
	switch n.Type {
	case NodeTask:
		return func(label string) string { return fmt.Sprintf("[%q]", label) }
	case NodeArtifact:
		return func(label string) string { return fmt.Sprintf("[\"%s\"]", label) }
	case NodeKB:
		return func(label string) string { return fmt.Sprintf("((%q))", label) }
	case NodeAnnotation:
		return func(label string) string { return fmt.Sprintf(">%q]", label) }
	case NodeCommit:
		return func(label string) string { return fmt.Sprintf("{{%q}}", label) }
	default:
		return func(label string) string { return fmt.Sprintf("[%q]", label) }
	}
}

func mermaidClass(t NodeType) string {
	switch t {
	case NodeTask:
		return "task"
	case NodeArtifact:
		return "artifact"
	case NodeKB:
		return "kb"
	case NodeAnnotation:
		return "ann"
	case NodeCommit:
		return "commit"
	default:
		return ""
	}
}

func mermaidArrow(rel EdgeRel) string {
	switch rel {
	case RelDependsOn:
		return " --> "
	case RelProduced:
		return " -.-> "
	case RelAnnotated:
		return " -. note .-> "
	case RelLinkedKB:
		return " -- kb --> "
	case RelCommit:
		return " == commit ==> "
	default:
		return " --> "
	}
}

func mermaidID(s string) string {
	// Mermaid node IDs must be alphanumeric + underscores.
	r := strings.NewReplacer(":", "_", " ", "_", "#", "_", ".", "_", "/", "_", "-", "_")
	return r.Replace(s)
}

func mermaidLabelEscape(s string) string {
	return strings.ReplaceAll(s, `"`, `'`)
}

// extractLeadingInt parses the leading integer from a filename like "42-slug.md".
func extractLeadingInt(name string) int {
	var n int
	for _, ch := range name {
		if ch >= '0' && ch <= '9' {
			n = n*10 + int(ch-'0')
		} else {
			break
		}
	}
	return n
}

func tagsOverlap(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, t := range a {
		set[strings.ToLower(t)] = struct{}{}
	}
	for _, t := range b {
		if _, ok := set[strings.ToLower(t)]; ok {
			return true
		}
	}
	return false
}
