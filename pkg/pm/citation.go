package pm

// citation.go: what a task's run read from the project's knowledge sources
// (Task 20472), and the per-project switch for putting it in task prompts.
//
// A run of a project with knowledge sources bound to it is given, before each
// task, the passages of those sources that best match the task — and, during
// the task, a search its agent can call. A citation records one document either
// way: the hub's id for it, where a person reads it and which source it came
// from. Citations are part of the task's outcome: the run writes them, the
// dashboard and the task detail API show them, and a device run brings them
// back with the rest of its result.

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// How a document came to be cited.
const (
	// CitationInjected is a document whose passages the orchestrator put in
	// the task's prompt, as reference material.
	CitationInjected = "injected"
	// CitationFetched is a document the agent read during the task through
	// the hub's knowledge search: the knowledge_search or knowledge_get tool,
	// or `cloop knowledge search` in its sandbox.
	CitationFetched = "fetched"
)

// Bounds on what a task keeps of its citations. A run writes them; a device
// run's come back from a machine the hub does not control.
const (
	// MaxTaskCitations bounds the citations one task keeps.
	MaxTaskCitations = 24
	// MaxCitationTitleRunes, MaxCitationURLBytes and MaxCitationSourceRunes
	// bound one citation's text.
	MaxCitationTitleRunes  = 200
	MaxCitationURLBytes    = 2048
	MaxCitationSourceRunes = 128
)

// Citation is one knowledge-source document a task's run was given or read.
type Citation struct {
	// Kind is CitationInjected or CitationFetched.
	Kind string `json:"kind"`
	// Title is the document's title at the source.
	Title string `json:"title"`
	// URL is where a person reads it: http or https only, else empty.
	URL string `json:"url,omitempty"`
	// Source is the name of the knowledge source it came from; SourceKind its
	// connector (confluence, jira).
	Source     string `json:"source"`
	SourceKind string `json:"source_kind,omitempty"`
	// DocumentID is the hub's id for the document.
	DocumentID int64 `json:"document_id,omitempty"`
	// RunID is the run that cited it.
	RunID string `json:"run_id,omitempty"`
}

// key identifies the document a citation names: its hub id, else its URL,
// else its source and title.
func (c Citation) key() string {
	switch {
	case c.DocumentID > 0:
		return "id:" + strconv.FormatInt(c.DocumentID, 10)
	case c.URL != "":
		return "url:" + c.URL
	}
	return "title:" + c.Source + "\x00" + c.Title
}

// CleanCitation returns c as a task may keep it, and false for one that names
// nothing: its kind one of the two, its text bounded and scrubbed by scrub
// (nil leaves it as it is), and a URL that is not http or https dropped — a
// citation is drawn as a link, and a javascript: or data: one must never be.
func CleanCitation(c Citation, scrub func(string) string) (Citation, bool) {
	if scrub == nil {
		scrub = func(s string) string { return s }
	}
	switch c.Kind {
	case CitationInjected, CitationFetched:
	default:
		return Citation{}, false
	}
	out := Citation{
		Kind:       c.Kind,
		Title:      clipRunes(oneLine(scrub(c.Title)), MaxCitationTitleRunes),
		Source:     clipRunes(oneLine(scrub(c.Source)), MaxCitationSourceRunes),
		SourceKind: clipRunes(oneLine(c.SourceKind), 32),
		RunID:      clipRunes(oneLine(c.RunID), 64),
	}
	if c.DocumentID > 0 {
		out.DocumentID = c.DocumentID
	}
	if u := strings.TrimSpace(c.URL); u != "" && len(u) <= MaxCitationURLBytes {
		if p, err := url.Parse(u); err == nil && (p.Scheme == "https" || p.Scheme == "http") && p.Host != "" {
			out.URL = scrub(u)
		}
	}
	if out.Title == "" && out.URL == "" && out.DocumentID == 0 {
		return Citation{}, false
	}
	return out, true
}

// MergeCitations adds add to have, one per document and at most
// MaxTaskCitations in all, each cleaned by CleanCitation. A document already
// cited keeps its first entry — except that an injected citation replaces a
// fetched one of the same document: the passage was in the prompt either way.
// have's order is kept, new documents follow in add's order.
func MergeCitations(have, add []Citation, scrub func(string) string) []Citation {
	out := make([]Citation, 0, min(len(have)+len(add), MaxTaskCitations))
	at := map[string]int{}
	put := func(c Citation) {
		c, ok := CleanCitation(c, scrub)
		if !ok {
			return
		}
		k := c.key()
		if i, seen := at[k]; seen {
			if out[i].Kind == CitationFetched && c.Kind == CitationInjected {
				out[i] = c
			}
			return
		}
		if len(out) == MaxTaskCitations {
			return
		}
		at[k] = len(out)
		out = append(out, c)
	}
	for _, c := range have {
		put(c)
	}
	for _, c := range add {
		put(c)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// CitationsOfRun returns the citations of have that runID made: those a later
// attempt keeps when it cites more. An earlier run's are left behind — they
// describe work the task no longer stands on.
func CitationsOfRun(have []Citation, runID string) []Citation {
	var out []Citation
	for _, c := range have {
		if c.RunID == runID {
			out = append(out, c)
		}
	}
	return out
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// Knowledge retrieval for a project's runs: on, by default, whenever the
// project has knowledge sources bound to it.
const (
	// DefaultRetrievalK is how many passages a task's prompt is given.
	DefaultRetrievalK = 5
	// MaxRetrievalK bounds it.
	MaxRetrievalK = 20
	// DefaultRetrievalTokens is the token budget of a task's reference
	// material.
	DefaultRetrievalTokens = 2000
	// MinRetrievalTokens and MaxRetrievalTokens bound it.
	MinRetrievalTokens = 200
	MaxRetrievalTokens = 16000
)

// KnowledgeRetrieval configures how a project's runs are given knowledge
// (Task 20472). Nil, or the zero value, means the defaults: on, with
// DefaultRetrievalK passages in at most DefaultRetrievalTokens tokens.
type KnowledgeRetrieval struct {
	// Disabled keeps reference material out of the project's task prompts.
	// The agent can still search the project's knowledge during a run.
	Disabled bool `json:"disabled,omitempty"`
	// K is how many passages a task's prompt is given; 0 takes the default.
	K int `json:"k,omitempty"`
	// TokenBudget bounds the reference material in one prompt, in tokens
	// (about four characters each); 0 takes the default.
	TokenBudget int `json:"token_budget,omitempty"`
}

// Enabled reports whether a run injects reference material.
func (r *KnowledgeRetrieval) Enabled() bool { return r == nil || !r.Disabled }

// Passages is how many passages a task's prompt is given.
func (r *KnowledgeRetrieval) Passages() int {
	if r == nil || r.K <= 0 {
		return DefaultRetrievalK
	}
	return min(r.K, MaxRetrievalK)
}

// Tokens is the token budget of a task's reference material.
func (r *KnowledgeRetrieval) Tokens() int {
	if r == nil || r.TokenBudget <= 0 {
		return DefaultRetrievalTokens
	}
	return max(MinRetrievalTokens, min(r.TokenBudget, MaxRetrievalTokens))
}

// Validate checks values a person set.
func (r *KnowledgeRetrieval) Validate() error {
	if r == nil {
		return nil
	}
	if r.K < 0 || r.K > MaxRetrievalK {
		return fmt.Errorf("knowledge retrieval: k is from 1 to %d, or 0 for the default (%d)", MaxRetrievalK, DefaultRetrievalK)
	}
	if r.TokenBudget != 0 && (r.TokenBudget < MinRetrievalTokens || r.TokenBudget > MaxRetrievalTokens) {
		return fmt.Errorf("knowledge retrieval: the token budget is from %d to %d, or 0 for the default (%d)",
			MinRetrievalTokens, MaxRetrievalTokens, DefaultRetrievalTokens)
	}
	return nil
}

// Clone returns a copy of r.
func (r *KnowledgeRetrieval) Clone() *KnowledgeRetrieval {
	if r == nil {
		return nil
	}
	c := *r
	return &c
}
