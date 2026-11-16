package knowledgerun

// readonly.go: the run's questions about the other projects it was given to
// read (Task 20501), asked with its knowledge session — the run's credential
// for what it reads through the hub.
//
//	POST <EnvURL>/readonly            {}            which may it still read?
//	POST <EnvURL>/readonly/snapshot   {"slug": …}   a snapshot of one of them
//
// The hub answers both from the readers lists as they are at that request, so
// a project taken off a list is no longer readable at the next boundary check
// and is not served again at all.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Endpoints for read-only projects, under EnvURL.
const (
	PathReadOnly         = "/readonly"
	PathReadOnlySnapshot = "/readonly/snapshot"
)

// ReadOnlyStatus is one project the run was given to read, as the hub sees it
// now.
type ReadOnlyStatus struct {
	Slug    string `json:"slug"`
	Project string `json:"project"`
	// Readable is whether the project's readers list still names the run's
	// project.
	Readable bool `json:"readable"`
}

// ReadOnlyResponse is the hub's answer to PathReadOnly: every project the run
// was given, in the order it was given them.
type ReadOnlyResponse struct {
	Projects []ReadOnlyStatus `json:"projects"`
}

// SnapshotRequest asks for a snapshot of the project the run was given under
// Slug.
type SnapshotRequest struct {
	Slug string `json:"slug"`
}

// snapshotTimeout bounds one snapshot's request: building one on the hub and
// carrying tens of megabytes takes longer than a search.
const snapshotTimeout = 10 * time.Minute

// ReadOnly asks which of the projects the run was given it may still read.
func (c *Client) ReadOnly(ctx context.Context) (*ReadOnlyResponse, error) {
	var out ReadOnlyResponse
	if err := c.call(ctx, PathReadOnly, struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// OpenSnapshot asks endpoint — a ReadOnlySnapshotRef's URL, the hub's
// PathReadOnlySnapshot — for the snapshot of the project a run was given under
// slug, presenting the run's session token, and returns the answer's body for
// the caller to read and close: a gzip-compressed tar, which
// readonlysnap.Extract unpacks. The hub refuses one the run may no longer read
// (an *APIError).
func OpenSnapshot(ctx context.Context, endpoint, token, slug string) (io.ReadCloser, error) {
	endpoint, token = strings.TrimSpace(endpoint), strings.TrimSpace(token)
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("read-only project: %q is not an http or https URL without credentials", endpoint)
	}
	if !strings.HasPrefix(token, TokenPrefix) || len(token) > 512 {
		return nil, fmt.Errorf("read-only project: the run's session token is missing or malformed")
	}
	raw, err := json.Marshal(SnapshotRequest{Slug: slug})
	if err != nil {
		return nil, fmt.Errorf("read-only project: encode the request: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, snapshotTimeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("read-only project: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/gzip")
	req.Header.Set("Authorization", "Bearer "+token)
	// The hub builds the snapshot before it answers, so its headers may take
	// minutes: bounded by the context, not by a search's timeouts. No proxy
	// and no redirect, as for every request with the token.
	hc := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy:                 nil,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: snapshotTimeout,
			MaxIdleConns:          1,
			IdleConnTimeout:       30 * time.Second,
		},
	}
	resp, err := hc.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("read-only project: reach the hub: %w", scrubToken(err, token))
	}
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		cancel()
		return nil, &APIError{Status: resp.StatusCode, Message: errorMessage(data)}
	}
	return &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}, nil
}

// cancelOnClose releases a request's context with its body.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}
