package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// fakeConnector serves documents from memory, a page at a time, recording
// what it was handed.
type fakeConnector struct {
	kind string

	mu sync.Mutex
	// docs is the source's content, in listing order.
	docs []Document
	// pageSize is how many documents a page holds.
	pageSize int
	// failAfter, when > 0, makes the List call after that many succeed fail.
	failAfter int
	lists     int
	// partial makes List return documents without bodies.
	partial bool
	fetches int
	// matches answers Narrow: query -> external ids; narrowFails makes
	// Narrow fail for a query.
	matches     map[string][]string
	narrowFails map[string]bool
	// creds records every credential value the connector was handed.
	creds []string
	// errWith, when set, is the error List returns, with the credential in it.
	leakCredentialInError bool
}

func (f *fakeConnector) Kind() string { return f.kind }

func (f *fakeConnector) Validate(config json.RawMessage) error {
	var c struct {
		BaseURL string `json:"base_url"`
	}
	if err := json.Unmarshal(config, &c); err != nil {
		return err
	}
	if !strings.HasPrefix(c.BaseURL, "https://") {
		return errors.New("base_url must be an https URL")
	}
	return nil
}

func (f *fakeConnector) List(_ context.Context, req ListRequest) (Page, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creds = append(f.creds, string(req.Credential.Value()))
	f.lists++
	if f.failAfter > 0 && f.lists > f.failAfter {
		if f.leakCredentialInError {
			return Page{}, fmt.Errorf("GET https://wiki.example/rest?token=%s: 503", req.Credential.Value())
		}
		return Page{}, errors.New("503 service unavailable")
	}
	start := 0
	if req.Cursor != "" {
		n, err := strconv.Atoi(req.Cursor)
		if err != nil {
			return Page{}, err
		}
		start = n
	}
	size := f.pageSize
	if size <= 0 {
		size = 2
	}
	// The cursor is a position in the listing; a remote that shrank since
	// leaves it past the end, where a real watermark would find nothing new.
	start = min(start, len(f.docs))
	end := min(start+size, len(f.docs))
	page := Page{Cursor: strconv.Itoa(end), More: end < len(f.docs)}
	for _, d := range f.docs[start:end] {
		if f.partial && !d.Deleted {
			d = Document{ExternalID: d.ExternalID, Partial: true}
		}
		page.Documents = append(page.Documents, d)
	}
	return page, nil
}

func (f *fakeConnector) Fetch(_ context.Context, req FetchRequest) (Document, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetches++
	for _, d := range f.docs {
		if d.ExternalID == req.ExternalID {
			return d, nil
		}
	}
	return Document{}, fmt.Errorf("no document %q", req.ExternalID)
}

func (f *fakeConnector) ValidateQuery(_ json.RawMessage, query string) error {
	if strings.Contains(query, "ORDER BY") {
		return errors.New("ORDER BY is not a filter")
	}
	return nil
}

func (f *fakeConnector) Narrow(_ context.Context, req NarrowRequest) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.narrowFails[req.Query] {
		return nil, errors.New("JQL rejected by the server")
	}
	return f.matches[req.Query], nil
}

// plainConnector is a connector without query narrowing: it forwards the
// Connector methods alone, so it does not pick up fakeConnector's Narrow.
type plainConnector struct{ inner *fakeConnector }

func (p *plainConnector) Kind() string                          { return p.inner.kind }
func (p *plainConnector) Validate(config json.RawMessage) error { return p.inner.Validate(config) }
func (p *plainConnector) List(ctx context.Context, req ListRequest) (Page, error) {
	return p.inner.List(ctx, req)
}
func (p *plainConnector) Fetch(ctx context.Context, req FetchRequest) (Document, error) {
	return p.inner.Fetch(ctx, req)
}

// fakeSecrets is a secret store holding name -> (owner, value).
type fakeSecrets map[string]struct{ owner, value string }

func (s fakeSecrets) lookup(ref, owner string) (string, error) {
	name, _, _ := strings.Cut(ref, "#")
	sec, ok := s[name]
	if !ok {
		return "", secretbroker.ErrSecretNotFound
	}
	owner = secretbroker.NormalizeOwner(owner)
	switch {
	case owner == "" && sec.owner != "":
		return "", secretbroker.ErrNotOwner
	case owner != "" && sec.owner == "":
		return "", secretbroker.ErrNotOwner
	case owner != "" && sec.owner != owner:
		return "", secretbroker.ErrSecretNotFound
	}
	return sec.value, nil
}

func (s fakeSecrets) CheckSourceCredential(ref, owner string) error {
	_, err := s.lookup(ref, owner)
	return err
}

func (s fakeSecrets) SourceCredential(ref, owner string) ([]byte, error) {
	v, err := s.lookup(ref, owner)
	if err != nil {
		return nil, err
	}
	return []byte(v), nil
}

// fixture is a Service over a fresh database with a fake connector.
type fixture struct {
	db    *statedb.DB
	svc   *Service
	conn  *fakeConnector
	plain *plainConnector
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := statedbtest.Open(t).AsControlPlane()
	reg := NewRegistry()
	conn := &fakeConnector{kind: "fake", matches: map[string][]string{}}
	plain := &plainConnector{inner: &fakeConnector{kind: "plain"}}
	if err := reg.Register(conn); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(plain); err != nil {
		t.Fatal(err)
	}
	secrets := fakeSecrets{
		"wiki-bot":   {"", "org-token-value-123"},
		"alice-wiki": {"alice@corp.example", "alice-token-value-456"},
		"bob-wiki":   {"bob@corp.example", "bob-token-value-789"},
	}
	svc := New(db, WithRegistry(reg), WithCredentials(secrets), WithChunking(ChunkOptions{MaxTokens: 64, OverlapTokens: 8}))
	return &fixture{db: db, svc: svc, conn: conn, plain: plain}
}

// The RBAC policy every principal below is resolved with: groups map to
// roles hub-wide, and "proj-a-maintainers" are maintainers of project A only.
var (
	projectA = Project{Path: "/srv/projects/a", Name: "a"}
	projectB = Project{Path: "/srv/projects/b", Name: "b"}
)

func testResolver(t *testing.T) *authz.Resolver {
	t.Helper()
	r, err := authz.New(authz.Config{
		DefaultRole: authz.RoleNone,
		Bindings: []authz.Binding{
			{Claim: authz.ClaimGroup, Value: "admins", Role: authz.RoleAdmin},
			{Claim: authz.ClaimGroup, Value: "operators", Role: authz.RoleOperator},
			{Claim: authz.ClaimGroup, Value: "viewers", Role: authz.RoleViewer},
			{Claim: authz.ClaimGroup, Value: "proj-a-maintainers", Role: authz.RoleMaintainer, Project: "a"},
			{Claim: authz.ClaimGroup, Value: "proj-b-viewers", Role: authz.RoleViewer, Project: "b"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// as returns the principal for an SSO identity in groups, under the test
// policy.
func as(t *testing.T, email string, groups ...string) Principal {
	t.Helper()
	subject := &authz.Subject{Sub: email, Email: email, Groups: groups}
	return PrincipalFor(true, testResolver(t), subject, email, email)
}

func mustCreate(t *testing.T, a *Access, in SourceInput) Source {
	t.Helper()
	src, err := a.CreateSource(context.Background(), in)
	if err != nil {
		t.Fatalf("create %q: %v", in.Name, err)
	}
	return src
}

func wantErr(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s = %v, want %v", what, err, want)
	}
}
