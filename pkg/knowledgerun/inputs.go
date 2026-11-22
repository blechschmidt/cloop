package knowledgerun

// inputs.go: the input files of a seeded run's tasks (Task 20511).
//
// A person can attach files to a task for its agent to work with, and every
// attempt at the task is given a copy of each (pkg/attachments, inbox.go). A
// run whose project is the hub's own reads them from the store beside the
// project's database. A run whose project was seeded into its sandbox — an
// edge device, a Kubernetes Pod, a containerised feature — has a database of
// its own, which holds no input file, so the hub dispatches it with the run's
// session under EnvInputsURL and EnvInputsToken, and the run asks the hub for
// them at the start of every attempt:
//
//	POST /api/run/knowledge/inputs       {"task", "title_sha256"}       the task's input files
//	POST /api/run/knowledge/inputs/file  {"task", "title_sha256", "id"} one file's bytes
//
// The session opens the input files of the run's own project and of nothing
// else, for as long as the run lives. Each request names the task by the title
// it has in the run's plan too, as a SHA-256 (TitleDigest) so a title of any
// length fits a request: a seeded run numbers the tasks it creates itself, and
// a task the run created as 57 is not the hub's task 57, which a person may
// have added meanwhile — the hub answers for a task only while its title is
// the one the run has.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// The variables a seeded run is dispatched with for its tasks' input files:
// the same session as EnvURL and EnvToken, and the same URL.
const (
	EnvInputsURL   = "CLOOP_TASK_INPUTS_URL"
	EnvInputsToken = "CLOOP_TASK_INPUTS_TOKEN"
)

// Endpoints, under EnvInputsURL.
const (
	PathInputs    = "/inputs"
	PathInputFile = "/inputs/file"
)

// inputFileTimeout bounds one file's transfer: up to 32 MiB from a hub that
// may be far from the device.
const inputFileTimeout = 10 * time.Minute

// InputsRequest asks for the input files of one task of the run's project.
type InputsRequest struct {
	Task int `json:"task"`
	// TitleSHA256 is TitleDigest of the task's title in the run's plan; see
	// the package note.
	TitleSHA256 string `json:"title_sha256"`
}

// TitleDigest is what a request names a task's title by: the hex SHA-256 of
// the title without the space around it.
func TitleDigest(title string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(title)))
	return hex.EncodeToString(sum[:])
}

// ValidTitleDigest reports whether s has the shape of a TitleDigest.
func ValidTitleDigest(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// InputFile is one input file as the hub lists it.
type InputFile struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256,omitempty"`
	MediaType string `json:"media_type,omitempty"`
	Note      string `json:"note,omitempty"`
}

// InputsResponse is the hub's answer to PathInputs.
type InputsResponse struct {
	Task  int         `json:"task"`
	Files []InputFile `json:"files"`
	// Mismatch says, for a task the hub has under another title and with
	// input files, why none are given: the run's copy of the task was renamed
	// or replaced on the hub while the run was going.
	Mismatch string `json:"mismatch,omitempty"`
}

// InputFileRequest asks for the bytes of one input file of a task.
type InputFileRequest struct {
	Task        int    `json:"task"`
	TitleSHA256 string `json:"title_sha256"`
	ID          string `json:"id"`
}

// InputsFromEnv is FromEnv for the session a seeded run reaches its tasks'
// input files with (EnvInputsURL, EnvInputsToken): nil and ErrNotConfigured
// for a run that was not given one — whose input files are in its own store.
func InputsFromEnv(getenv func(string) string) (*Client, error) {
	base, token := strings.TrimSpace(getenv(EnvInputsURL)), strings.TrimSpace(getenv(EnvInputsToken))
	if base == "" || token == "" {
		return nil, ErrNotConfigured
	}
	return New(base, token)
}

// Inputs lists the input files of a task.
func (c *Client) Inputs(ctx context.Context, req InputsRequest) (*InputsResponse, error) {
	var out InputsResponse
	if err := c.call(ctx, PathInputs, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// OpenInputFile asks for the bytes of one input file and returns the answer's
// body for the caller to read and close. At most limit bytes and one more are
// read from it, so a caller that reads to the end learns when the hub sent
// more than the file it listed. The caller checks the size and digest.
func (c *Client) OpenInputFile(ctx context.Context, req InputFileRequest, limit int64) (io.ReadCloser, error) {
	if c == nil {
		return nil, ErrNotConfigured
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("task input file: encode the request: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, inputFileTimeout)
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+PathInputFile, bytes.NewReader(raw))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("task input file: %w", err)
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("Accept", "application/octet-stream")
	hreq.Header.Set("Authorization", "Bearer "+c.token)
	// A file takes longer than a search: bounded by the context rather than
	// by the client's whole-request timeout. The same transport otherwise —
	// no proxy, no redirect.
	hc := &http.Client{CheckRedirect: c.http.CheckRedirect, Transport: c.http.Transport}
	resp, err := hc.Do(hreq)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("task input file: reach the hub at %s: %w", c.base, scrubToken(err, c.token))
	}
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		cancel()
		return nil, &APIError{Status: resp.StatusCode, Message: errorMessage(data)}
	}
	return &cancelOnClose{
		ReadCloser: struct {
			io.Reader
			io.Closer
		}{io.LimitReader(resp.Body, max(limit, 0)+1), resp.Body},
		cancel: cancel,
	}, nil
}
