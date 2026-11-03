package hubclient

// The knowledge sources' calls (Task 20470): the sources the caller may see,
// a sync of one now, and a project's search — through the routes the
// dashboard uses, so the hub decides who sees and does what, and nothing here
// filters.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// KnowledgeSyncCounts is what a source's last sync did.
type KnowledgeSyncCounts struct {
	Pages     int  `json:"pages"`
	Listed    int  `json:"listed"`
	Created   int  `json:"created"`
	Updated   int  `json:"updated"`
	Unchanged int  `json:"unchanged"`
	Deleted   int  `json:"deleted"`
	Rejected  int  `json:"rejected"`
	Removed   int  `json:"removed"`
	Narrowed  int  `json:"narrowed"`
	Complete  bool `json:"complete"`
	Full      bool `json:"full,omitempty"`
}

// KnowledgeRunning is a sync in progress.
type KnowledgeRunning struct {
	Member string `json:"member"`
	Origin string `json:"origin"`
	Actor  string `json:"actor,omitempty"`
	Since  string `json:"since"`
}

// KnowledgeSync is how a source's syncs are going.
type KnowledgeSync struct {
	// Status is "" (never synced), ok, error or interrupted.
	Status          string               `json:"status"`
	Error           string               `json:"error,omitempty"`
	At              string               `json:"at,omitempty"`
	Resumes         bool                 `json:"resumes"`
	IntervalMinutes int                  `json:"interval_minutes"`
	DefaultInterval bool                 `json:"default_interval"`
	StartedAt       string               `json:"started_at,omitempty"`
	DurationMS      int64                `json:"duration_ms,omitempty"`
	Origin          string               `json:"origin,omitempty"`
	Counts          *KnowledgeSyncCounts `json:"counts,omitempty"`
	More            bool                 `json:"more,omitempty"`
	LastOKAt        string               `json:"last_ok_at,omitempty"`
	NextAt          string               `json:"next_at,omitempty"`
	Running         *KnowledgeRunning    `json:"running,omitempty"`
}

// KnowledgeSource is a knowledge source as the hub shows it: never its
// credential, and its secret reference only to a caller who may manage it.
type KnowledgeSource struct {
	ID            int64         `json:"id"`
	Kind          string        `json:"kind"`
	Name          string        `json:"name"`
	Scope         string        `json:"scope"`
	Owner         string        `json:"owner,omitempty"`
	Mine          bool          `json:"mine"`
	Manageable    bool          `json:"manageable"`
	SecretRef     string        `json:"secret_ref,omitempty"`
	HasCredential bool          `json:"has_credential"`
	Enabled       bool          `json:"enabled"`
	Sync          KnowledgeSync `json:"sync"`
	Documents     int           `json:"documents"`
	Chunks        int           `json:"chunks"`
	Bindings      int           `json:"bindings"`
}

// KnowledgeSources is GET /api/knowledge/sources.
type KnowledgeSources struct {
	Sources           []KnowledgeSource `json:"sources"`
	Connectors        []string          `json:"connectors"`
	CanCreateOrg      bool              `json:"can_create_org"`
	CanCreatePersonal bool              `json:"can_create_personal"`
}

// KnowledgeSources lists the sources the caller may see.
func (c *Client) KnowledgeSources(ctx context.Context) (*KnowledgeSources, error) {
	var out KnowledgeSources
	if err := c.Do(ctx, http.MethodGet, "/api/knowledge/sources", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// KnowledgeSource reads one source.
func (c *Client) KnowledgeSource(ctx context.Context, id int64) (*KnowledgeSource, error) {
	var out struct {
		Source KnowledgeSource `json:"source"`
	}
	if err := c.Do(ctx, http.MethodGet, fmt.Sprintf("/api/knowledge/sources/%d", id), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out.Source, nil
}

// ResolveKnowledgeSource finds the source ref names: its id, or its name —
// exactly, or else ignoring case when that matches one source alone.
func (c *Client) ResolveKnowledgeSource(ctx context.Context, ref string) (*KnowledgeSource, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, errors.New("name a knowledge source: its id or its name (see `cloop knowledge sources`)")
	}
	list, err := c.KnowledgeSources(ctx)
	if err != nil {
		return nil, err
	}
	if id, err := strconv.ParseInt(ref, 10, 64); err == nil {
		for i := range list.Sources {
			if list.Sources[i].ID == id {
				return &list.Sources[i], nil
			}
		}
		return nil, fmt.Errorf("you can see no knowledge source %d here (see `cloop knowledge sources`)", id)
	}
	var exact, folded []*KnowledgeSource
	for i := range list.Sources {
		s := &list.Sources[i]
		switch {
		case s.Name == ref:
			exact = append(exact, s)
		case strings.EqualFold(s.Name, ref):
			folded = append(folded, s)
		}
	}
	for _, match := range [][]*KnowledgeSource{exact, folded} {
		switch len(match) {
		case 0:
			continue
		case 1:
			return match[0], nil
		}
		ids := make([]string, len(match))
		for i, s := range match {
			ids[i] = strconv.FormatInt(s.ID, 10)
		}
		return nil, fmt.Errorf("%d knowledge sources are named %q — yours and the organisation's, say: name one by its id (%s)",
			len(match), ref, strings.Join(ids, ", "))
	}
	return nil, fmt.Errorf("you can see no knowledge source named %q here (see `cloop knowledge sources`)", ref)
}

// SyncKnowledgeSource asks the hub to sync source id now. The sync runs on
// the hub in the background; the answer says it started, or — an APIError
// with status 409 — that another sync of the source is running, naming it.
func (c *Client) SyncKnowledgeSource(ctx context.Context, id int64) (*KnowledgeSource, *KnowledgeRunning, error) {
	var out struct {
		Source KnowledgeSource   `json:"source"`
		Sync   *KnowledgeRunning `json:"sync"`
	}
	if err := c.Do(ctx, http.MethodPost, fmt.Sprintf("/api/knowledge/sources/%d/sync", id), nil,
		map[string]any{}, &out); err != nil {
		return nil, nil, err
	}
	return &out.Source, out.Sync, nil
}

// KnowledgeSourceRef names a source in a search hit.
type KnowledgeSourceRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// KnowledgeHit is one chunk a search found.
type KnowledgeHit struct {
	ChunkID    int64              `json:"chunk_id"`
	DocumentID int64              `json:"document_id"`
	Source     KnowledgeSourceRef `json:"source"`
	Title      string             `json:"title"`
	URL        string             `json:"url,omitempty"`
	Space      string             `json:"space,omitempty"`
	ExternalID string             `json:"external_id"`
	Heading    string             `json:"heading,omitempty"`
	Ancestors  []string           `json:"ancestors,omitempty"`
	// Snippet is the chunk's best-matching passage, terms marked « and ».
	Snippet string `json:"snippet"`
	Rank    int    `json:"rank"`
	// FoundBy says what found the hit: "lexical" (its words), "semantic"
	// (its meaning, with the hub's knowledge.embeddings on), or both.
	FoundBy []string `json:"found_by,omitempty"`
}

// KnowledgeRetrieval is how a search ranked: "hybrid" — words and meaning,
// fused — or "lexical", with Warning saying why a search that would have been
// hybrid was not.
type KnowledgeRetrieval struct {
	Mode       string `json:"mode"`
	Model      string `json:"model,omitempty"`
	Candidates int    `json:"candidates,omitempty"`
	Capped     bool   `json:"capped,omitempty"`
	Warning    string `json:"warning,omitempty"`
}

// SearchKnowledge searches the knowledge bound to the project at index idx
// for query, returning at most k hits (the hub's default for k <= 0).
func (c *Client) SearchKnowledge(ctx context.Context, idx int, query string, k int) ([]KnowledgeHit, error) {
	hits, _, err := c.SearchKnowledgeRetrieval(ctx, idx, query, k)
	return hits, err
}

// SearchKnowledgeRetrieval is SearchKnowledge with how the hub ranked the
// hits; an older hub, which ranks by words alone and does not say, answers a
// zero KnowledgeRetrieval.
func (c *Client) SearchKnowledgeRetrieval(ctx context.Context, idx int, query string, k int) ([]KnowledgeHit, KnowledgeRetrieval, error) {
	q := url.Values{"q": {query}}
	if k > 0 {
		q.Set("k", strconv.Itoa(k))
	}
	var out struct {
		Hits      []KnowledgeHit     `json:"hits"`
		Retrieval KnowledgeRetrieval `json:"retrieval"`
	}
	if err := c.Do(ctx, http.MethodGet, fmt.Sprintf("/api/projects/%d/knowledge/search", idx), q, nil, &out); err != nil {
		return nil, KnowledgeRetrieval{}, err
	}
	return out.Hits, out.Retrieval, nil
}

// KnowledgeRunSetting is how a project's runs are given its knowledge (Task
// 20472), as GET /api/projects/{idx}/knowledge/retrieval answers.
type KnowledgeRunSetting struct {
	// Enabled says whether each task's prompt gets reference material.
	Enabled bool `json:"enabled"`
	// K is how many passages a prompt is given; TokenBudget bounds them.
	K           int `json:"k"`
	TokenBudget int `json:"token_budget"`
	// Default reports a project that never set it.
	Default bool `json:"default"`
	// Sources counts the knowledge sources bound to the project.
	Sources int `json:"sources"`
}

// KnowledgeRunSettingChange is a change to it: nil fields are left alone; 0
// for K or TokenBudget returns it to the default.
type KnowledgeRunSettingChange struct {
	Enabled     *bool `json:"enabled,omitempty"`
	K           *int  `json:"k,omitempty"`
	TokenBudget *int  `json:"token_budget,omitempty"`
}

// KnowledgeRunSetting reads project idx's knowledge retrieval setting.
func (c *Client) KnowledgeRunSetting(ctx context.Context, idx int) (*KnowledgeRunSetting, error) {
	var out struct {
		Retrieval KnowledgeRunSetting `json:"retrieval"`
	}
	if err := c.Do(ctx, http.MethodGet, fmt.Sprintf("/api/projects/%d/knowledge/retrieval", idx), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out.Retrieval, nil
}

// SetKnowledgeRunSetting changes project idx's knowledge retrieval setting.
func (c *Client) SetKnowledgeRunSetting(ctx context.Context, idx int, change KnowledgeRunSettingChange) (*KnowledgeRunSetting, error) {
	var out struct {
		Retrieval KnowledgeRunSetting `json:"retrieval"`
	}
	if err := c.Do(ctx, http.MethodPut, fmt.Sprintf("/api/projects/%d/knowledge/retrieval", idx), nil, change, &out); err != nil {
		return nil, err
	}
	return &out.Retrieval, nil
}
