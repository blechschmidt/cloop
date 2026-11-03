// Package knowledgerun is how a run reaches its project's knowledge (Task
// 20472): the wire between the hub's run-scoped knowledge search and the three
// things in a run that use it — the orchestrator, which puts the passages that
// best match a task into the task's prompt; cloop's MCP server, which gives the
// agent knowledge_search and knowledge_get tools; and `cloop knowledge search`
// in the run's sandbox.
//
// A run of a project with knowledge sources bound to it is dispatched with two
// variables: EnvURL, where the hub serves the search, and EnvToken, the run's
// knowledge session token. The token is good for that project's knowledge and
// nothing else, for as long as the run lives; the hub refuses it once the run
// has ended, and it never carries — or opens — the credentials the hub reads
// the sources with. A run without them has no knowledge to reach: every
// function here then does nothing.
//
// Everything the hub returns is the sources' text, which anyone who can edit a
// wiki page wrote. ReferenceSection fences it in a prompt as untrusted data,
// and the hub has scrubbed it of anything shaped like a credential before it
// left (pkg/redact).
package knowledgerun

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// The variables a run is dispatched with.
const (
	// EnvURL is the base URL of the hub's run-scoped knowledge search.
	EnvURL = "CLOOP_KNOWLEDGE_URL"
	// EnvToken is the run's knowledge session token.
	EnvToken = "CLOOP_KNOWLEDGE_TOKEN"
	// EnvTask names the task an agent works on, as attachments.EnvTaskID
	// does: what the hub records a read for.
	EnvTask = "CLOOP_TASK_ID"
)

// TokenPrefix starts every knowledge session token: cloop_know1_<id>.<secret>.
// pkg/redact knows it, so a token printed or committed is found.
const TokenPrefix = "cloop_know1_"

// Endpoints, under EnvURL.
const (
	PathSearch    = "/search"
	PathGet       = "/get"
	PathCitations = "/citations"
)

// MountPath is where the hub serves the endpoints: EnvURL is the hub's URL
// with this path.
const MountPath = "/api/run/knowledge"

// Bounds the hub holds a request and its answer to.
const (
	// DefaultK and MaxK bound how many passages a search returns.
	DefaultK = 5
	MaxK     = 20
	// MaxQueryBytes bounds a query, as the index does.
	MaxQueryBytes = 512
	// MaxHitTextBytes bounds one passage's text in a search answer.
	MaxHitTextBytes = 4 << 10
	// DefaultGetBytes and MaxGetBytes bound a document's text in a get.
	DefaultGetBytes = 32 << 10
	MaxGetBytes     = 64 << 10
	// MaxRequestBytes bounds a request body.
	MaxRequestBytes = 16 << 10
	// MaxResponseBytes bounds what a client reads of an answer.
	MaxResponseBytes = 1 << 20
)

// PurposeInject marks a request the orchestrator makes to assemble a task's
// prompt. Its documents are cited by the orchestrator itself, as injected, so
// the hub does not also record them as the agent's reads.
const PurposeInject = "inject"

// SourceRef names a knowledge source.
type SourceRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// SearchRequest asks for the passages of the run's project's knowledge that
// best match Query.
type SearchRequest struct {
	Query string `json:"query"`
	// K is how many passages to return: 0 for DefaultK, at most MaxK.
	K int `json:"k,omitempty"`
	// Task is the task the agent works on, for its citations.
	Task    int    `json:"task,omitempty"`
	Purpose string `json:"purpose,omitempty"`
}

// Hit is one passage a search found.
type Hit struct {
	DocumentID int64     `json:"document_id"`
	ChunkID    int64     `json:"chunk_id"`
	Title      string    `json:"title"`
	URL        string    `json:"url,omitempty"`
	Source     SourceRef `json:"source"`
	Space      string    `json:"space,omitempty"`
	// Heading is the passage's heading path within its document.
	Heading string `json:"heading,omitempty"`
	// Ancestors place the document at its source, outermost first.
	Ancestors []string `json:"ancestors,omitempty"`
	// Text is the passage, at most MaxHitTextBytes, scrubbed of anything
	// shaped like a credential.
	Text string `json:"text"`
	// Truncated reports a passage cut at MaxHitTextBytes or by the answer's
	// own bound.
	Truncated bool `json:"truncated,omitempty"`
	Rank      int  `json:"rank"`
}

// Retrieval says how the hub ranked a search.
type Retrieval struct {
	// Mode is "hybrid" or "lexical".
	Mode string `json:"mode"`
	// Warning says why a search that would have been hybrid was not.
	Warning string `json:"warning,omitempty"`
}

// SearchResponse is a search's answer.
type SearchResponse struct {
	Hits      []Hit     `json:"hits"`
	Retrieval Retrieval `json:"retrieval"`
}

// GetRequest asks for one document of the run's project's knowledge: by the
// hub's id, the URL a person reads it at, or its key at the source (a Jira
// issue key such as ENG-42). Exactly one of the three.
type GetRequest struct {
	DocumentID int64  `json:"document_id,omitempty"`
	URL        string `json:"url,omitempty"`
	Key        string `json:"key,omitempty"`
	// MaxBytes bounds the text returned: 0 for DefaultGetBytes, at most
	// MaxGetBytes.
	MaxBytes int    `json:"max_bytes,omitempty"`
	Task     int    `json:"task,omitempty"`
	Purpose  string `json:"purpose,omitempty"`
}

// Document is one document as a get returns it.
type Document struct {
	ID        int64     `json:"id"`
	Title     string    `json:"title"`
	URL       string    `json:"url,omitempty"`
	Source    SourceRef `json:"source"`
	Space     string    `json:"space,omitempty"`
	Ancestors []string  `json:"ancestors,omitempty"`
	UpdatedAt string    `json:"updated_at,omitempty"`
	// Text is the document's indexed text, its sections' headings marked,
	// scrubbed of anything shaped like a credential.
	Text string `json:"text"`
	// Truncated reports text cut at the request's bound, or a document the
	// index itself holds only in part.
	Truncated bool `json:"truncated,omitempty"`
}

// GetResponse is a get's answer: the documents that match — none when the
// project's knowledge has nothing by that name; more than one when a URL or a
// key names the same page in two sources.
type GetResponse struct {
	Documents []Document `json:"documents"`
}

// CitationsRequest asks which documents the hub served the run's agent for
// Task, and forgets them: the run keeps them on the task from then on.
type CitationsRequest struct {
	Task int `json:"task"`
}

// CitationsResponse is what the agent read for a task, as citations of kind
// pm.CitationFetched.
type CitationsResponse struct {
	Citations []pm.Citation `json:"citations"`
}

// APIError is the hub's refusal of a request.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("knowledge search: the hub answered %d", e.Status)
	}
	return fmt.Sprintf("knowledge search: the hub answered %d: %s", e.Status, e.Message)
}

// ErrNotConfigured reports a process with no knowledge to reach: it was not
// dispatched as a run of a project with knowledge sources bound to it.
var ErrNotConfigured = errors.New("knowledge search: this run has no knowledge sources to search " +
	"(" + EnvURL + " and " + EnvToken + " are set only for a run of a project with knowledge sources bound to it)")

// Client calls the hub's run-scoped knowledge search with a run's token.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// requestTimeout bounds one request.
const requestTimeout = 15 * time.Second

// New returns a client for the endpoints under base, presenting token. It
// refuses a base that is not an http or https URL, and a token that is not a
// knowledge session's.
func New(base, token string) (*Client, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	token = strings.TrimSpace(token)
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("knowledge search: %s is not an http or https URL without credentials, query or fragment", EnvURL)
	}
	if !strings.HasPrefix(token, TokenPrefix) || len(token) > 512 {
		return nil, fmt.Errorf("knowledge search: %s is not a knowledge session token", EnvToken)
	}
	return &Client{
		base:  base,
		token: token,
		http: &http.Client{
			Timeout: requestTimeout,
			// The hub is reached where it said it is, and the token goes
			// nowhere else: no redirect is followed, and no proxy from the
			// environment is used — a sandbox's HTTPS_PROXY is for the
			// Internet, not for the hub.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				Proxy:                 nil,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: requestTimeout,
				MaxIdleConns:          2,
				IdleConnTimeout:       30 * time.Second,
			},
		},
	}, nil
}

// FromEnv returns the client a run's environment describes: nil and
// ErrNotConfigured when it describes none, and an error naming the variable
// when one is malformed.
func FromEnv(getenv func(string) string) (*Client, error) {
	base, token := strings.TrimSpace(getenv(EnvURL)), strings.TrimSpace(getenv(EnvToken))
	if base == "" || token == "" {
		return nil, ErrNotConfigured
	}
	return New(base, token)
}

// TaskFromEnv is the task the environment says an agent works on, 0 for none.
func TaskFromEnv(getenv func(string) string) int {
	n, err := strconv.Atoi(strings.TrimSpace(getenv(EnvTask)))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// Base returns the URL the client calls under.
func (c *Client) Base() string { return c.base }

// Search runs a search.
func (c *Client) Search(ctx context.Context, req SearchRequest) (*SearchResponse, error) {
	var out SearchResponse
	if err := c.call(ctx, PathSearch, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Get reads one document.
func (c *Client) Get(ctx context.Context, req GetRequest) (*GetResponse, error) {
	var out GetResponse
	if err := c.call(ctx, PathGet, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Citations collects what the hub served the run's agent for task.
func (c *Client) Citations(ctx context.Context, task int) ([]pm.Citation, error) {
	var out CitationsResponse
	if err := c.call(ctx, PathCitations, CitationsRequest{Task: task}, &out); err != nil {
		return nil, err
	}
	return out.Citations, nil
}

// call POSTs body as JSON to path and decodes the answer into out.
func (c *Client) call(ctx context.Context, path string, body, out any) error {
	if c == nil {
		return ErrNotConfigured
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("knowledge search: encode the request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("knowledge search: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("knowledge search: reach the hub at %s: %w", c.base, scrubToken(err, c.token))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("knowledge search: read the hub's answer: %w", err)
	}
	if len(data) > MaxResponseBytes {
		return fmt.Errorf("knowledge search: the hub's answer is larger than %d bytes", MaxResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return &APIError{Status: resp.StatusCode, Message: errorMessage(data)}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("knowledge search: the hub's answer is not what was asked for: %w", err)
	}
	return nil
}

// errorMessage reads the message of a hub error body, {"error": …} or the
// structured {"error": {"message": …}}.
func errorMessage(data []byte) string {
	var flat struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &flat) == nil && flat.Error != "" {
		return clipBytes(flat.Error, 512)
	}
	var nested struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(data, &nested) == nil {
		if nested.Error.Message != "" {
			return clipBytes(nested.Error.Message, 512)
		}
		return clipBytes(nested.Message, 512)
	}
	return ""
}

// scrubToken keeps the token out of an error: a transport error quotes the
// request, never its headers, but nothing is lost by making sure.
func scrubToken(err error, token string) error {
	if err == nil || token == "" || !strings.Contains(err.Error(), token) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), token, "[redacted]"))
}

// clipBytes cuts s to at most n bytes, on a rune boundary.
func clipBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
