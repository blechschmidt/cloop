package knowledgerun

// results.go: the files a seeded run attaches, sent to the hub as they are
// attached (Task 20513).
//
// A run whose project was seeded into its sandbox — an edge device, a
// Kubernetes Pod, a containerised feature — attaches files in its own copy of
// the project. Its result, read back once the run is over, carries only as
// many of them as fit beside the plan, the steps and the journal in one
// transport frame. So the hub dispatches every such run that has a
// network with its run session under EnvResultsURL and EnvResultsToken, and the
// run sends each file it attaches as soon as the attempt that made it ends:
//
//	POST /api/run/knowledge/results?id=&task=&title_sha256=&name=&size=&sha256=&created_at=
//	     Content-Type: application/octet-stream, the file as the body
//
// The hub checks the bytes against the size and SHA-256 sent with them, and
// then either attaches the file to the hub's task — when the task the run names
// by its id and its title's digest is one the hub has under that title, and the
// hub process holding the run can scrub the file with what the run was leased —
// or holds it until the run's result says which task it belongs to (a task the
// run created itself has an id the hub may have given to another). Either way
// the file is recorded under the id the run gave it, so a file that also
// arrives in the run's result is one attachment, not two.
//
// The session sends the run's own project's files and nothing else, for as
// long as the run lives, and each is on the hub's audit trail
// (run.result_upload).

import (
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
)

// The variables a seeded run is dispatched with to send the files it attaches:
// the same session and URL as its input files.
const (
	EnvResultsURL   = "CLOOP_TASK_RESULTS_URL"
	EnvResultsToken = "CLOOP_TASK_RESULTS_TOKEN"
)

// PathResults is where a run sends a file it attached, under EnvResultsURL.
const PathResults = "/results"

// What the hub did with a file a run sent.
const (
	// ResultAttached: the file is attached to the hub's task.
	ResultAttached = "attached"
	// ResultHeld: the hub holds the file until the run's result says which of
	// its tasks it belongs to.
	ResultHeld = "held"
)

// ResultUpload describes one file a run sends.
type ResultUpload struct {
	// ID is the id the run gave the attachment: 32 lower-case hex characters.
	ID string
	// Task is the task's id in the run's plan, and TitleSHA256 TitleDigest of
	// its title there.
	Task        int
	TitleSHA256 string
	// Name is the name the file is attached under.
	Name string
	// Size and SHA256 describe the bytes sent.
	Size   int64
	SHA256 string
	// CreatedAt is when the run attached the file.
	CreatedAt time.Time
	// Created says the task is one the run created, or one whose title it
	// changed, rather than one it was sent: the hub then holds the file for
	// the run's result to place, whatever task of the hub's has the id.
	Created bool
}

// Query is the upload's description as a request's query.
func (u ResultUpload) Query() url.Values {
	q := url.Values{}
	q.Set("id", u.ID)
	q.Set("task", strconv.Itoa(u.Task))
	q.Set("title_sha256", u.TitleSHA256)
	q.Set("name", u.Name)
	q.Set("size", strconv.FormatInt(u.Size, 10))
	q.Set("sha256", u.SHA256)
	if !u.CreatedAt.IsZero() {
		q.Set("created_at", u.CreatedAt.UTC().Format(time.RFC3339Nano))
	}
	if u.Created {
		q.Set("created", "1")
	}
	return q
}

// ParseResultUpload reads an upload's description back from a request's
// query. It checks the shape of each value, not what the hub makes of it.
func ParseResultUpload(q url.Values) (ResultUpload, error) {
	u := ResultUpload{
		ID:          strings.TrimSpace(q.Get("id")),
		TitleSHA256: strings.ToLower(strings.TrimSpace(q.Get("title_sha256"))),
		Name:        strings.TrimSpace(q.Get("name")),
		SHA256:      strings.ToLower(strings.TrimSpace(q.Get("sha256"))),
	}
	var err error
	if u.Task, err = strconv.Atoi(strings.TrimSpace(q.Get("task"))); err != nil || u.Task <= 0 {
		return u, errors.New("task must be the id of the task in the run's plan")
	}
	if u.Size, err = strconv.ParseInt(strings.TrimSpace(q.Get("size")), 10, 64); err != nil || u.Size < 0 {
		return u, errors.New("size must be the file's length in bytes")
	}
	if !validHexID(u.ID) {
		return u, errors.New("id must be the attachment's id in the run's project: 32 lower-case hex characters")
	}
	if !ValidTitleDigest(u.TitleSHA256) {
		return u, errors.New("title_sha256 must be the hex SHA-256 of the task's title as the run has it")
	}
	if !ValidTitleDigest(u.SHA256) {
		return u, errors.New("sha256 must be the hex SHA-256 of the file")
	}
	if u.Name == "" || len(u.Name) > 1024 {
		return u, errors.New("name must be the name the file is attached under, at most 1024 bytes")
	}
	u.Created = q.Get("created") == "1"
	if raw := strings.TrimSpace(q.Get("created_at")); raw != "" {
		if u.CreatedAt, err = time.Parse(time.RFC3339Nano, raw); err != nil {
			return u, errors.New("created_at must be an RFC 3339 time")
		}
	}
	return u, nil
}

// validHexID reports whether s is 32 lower-case hex characters: an
// attachment's id.
func validHexID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ResultResponse is the hub's answer to a file a run sent.
type ResultResponse struct {
	// Outcome is ResultAttached or ResultHeld.
	Outcome string `json:"outcome"`
	// ID is the attachment's id: the one the run gave it.
	ID string `json:"id"`
	// Task is the hub's task the file was attached to, for ResultAttached.
	Task int `json:"task,omitempty"`
	// Message says, for a person reading the run's log, what happened.
	Message string `json:"message,omitempty"`
}

// ResultsFromEnv is FromEnv for the session a seeded run sends the files it
// attaches with (EnvResultsURL, EnvResultsToken): nil and ErrNotConfigured for
// a run that was not given one — whose files go into the project's own store,
// or back in its result.
func ResultsFromEnv(getenv func(string) string) (*Client, error) {
	base, token := strings.TrimSpace(getenv(EnvResultsURL)), strings.TrimSpace(getenv(EnvResultsToken))
	if base == "" || token == "" {
		return nil, ErrNotConfigured
	}
	return New(base, token)
}

// resultSendTime is how long sending one file of size bytes may take: what the
// hub allows it (a minute, and what it needs at 64 KiB a second), and a minute
// more for the answer.
func resultSendTime(size int64) time.Duration {
	return 2*time.Minute + time.Duration(size/(64<<10))*time.Second
}

// SendResult sends one file the run attached: body is read for u.Size bytes.
// A refusal is an *APIError; whether it is worth trying again is the caller's
// call (Retryable).
func (c *Client) SendResult(ctx context.Context, u ResultUpload, body io.Reader) (*ResultResponse, error) {
	if c == nil {
		return nil, ErrNotConfigured
	}
	ctx, cancel := context.WithTimeout(ctx, resultSendTime(u.Size))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+PathResults+"?"+u.Query().Encode(),
		io.LimitReader(body, u.Size))
	if err != nil {
		return nil, fmt.Errorf("task result file: %w", err)
	}
	req.ContentLength = u.Size
	if u.Size == 0 {
		req.Body = http.NoBody
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	// A file takes longer than a search: bounded by the context rather than
	// by the client's whole-request timeout. The same transport otherwise —
	// no proxy, no redirect.
	hc := &http.Client{CheckRedirect: c.http.CheckRedirect, Transport: c.http.Transport}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("task result file: reach the hub at %s: %w", c.base, scrubToken(err, c.token))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("task result file: read the hub's answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, &APIError{Status: resp.StatusCode, Message: errorMessage(data)}
	}
	var out ResultResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("task result file: the hub's answer is not what was asked for: %w", err)
	}
	if out.Outcome != ResultAttached && out.Outcome != ResultHeld {
		return nil, fmt.Errorf("task result file: the hub answered with outcome %q", clipBytes(out.Outcome, 64))
	}
	return &out, nil
}

// Retryable reports whether a failure to send a file may go away by itself:
// the hub could not be reached or answered that it is busy or failing, as
// opposed to refusing the file.
func Retryable(err error) bool {
	if err == nil {
		return false
	}
	var api *APIError
	if errors.As(err, &api) {
		return api.Status == http.StatusTooManyRequests || api.Status == http.StatusRequestTimeout || api.Status >= 500
	}
	return !errors.Is(err, ErrNotConfigured)
}
