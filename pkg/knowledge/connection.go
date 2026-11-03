package knowledge

// connection.go: trying a source's connection before it is saved, or after it
// was (Task 20473) — the dashboard's "Test connection".
//
// A test is a sync's first step and nothing more: the connector lists one
// small page with the source's configuration and credential, and the answer is
// how many documents came back and the first few titles, or why none did.
// Nothing is indexed and no cursor moves. The credential is opened on the hub
// for the one call and wiped after it, as a sync's is; what a failure says is
// scrubbed of it, and of anything else shaped like a credential, before it
// goes anywhere — the audit trail included.
//
// A test sends the credential to the address the configuration names, so who
// may run one is who may make that configuration the source's: anyone may try
// a source they could connect, and only a source's manager may try an existing
// one, with or without changes — an administrator may delete someone's
// personal source but never point it, and so their credential, elsewhere.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Connection test bounds.
const (
	// ConnectionTestTimeout bounds one test: long enough for a slow Data
	// Center install to answer a first page, short enough for a person to
	// wait on.
	ConnectionTestTimeout = 30 * time.Second
	// connectionTestPage is the page a test asks for: enough to see that the
	// scope matches something, not a listing.
	connectionTestPage = 5
	// connectionTestTitles is how many listed titles a test reports.
	connectionTestTitles = 3
	// maxTestTitleBytes cuts each reported title.
	maxTestTitleBytes = 200
)

// Why a connection test failed: ConnectionResult.Reason.
const (
	// TestFailedCredential: the source's secret could not be opened.
	TestFailedCredential = "credential"
	// TestFailedConnector: the remote refused the request, could not be
	// reached, or answered with something the connector could not read.
	TestFailedConnector = "connector"
)

// ConnectionTest is a connection to try: an existing source's (SourceID),
// with whatever of its configuration and credential reference a form is about
// to change, or a new source's (Kind, Scope, Config, SecretRef).
type ConnectionTest struct {
	SourceID int64
	// Kind and Scope describe a new source; an existing source keeps its
	// own. An empty Scope is personal for a caller with an identity to own
	// it, as CreateSource takes it.
	Kind  string
	Scope string
	// Config is the configuration to try; nil tries an existing source's
	// own.
	Config json.RawMessage
	// SecretRef is the credential reference to try; nil tries an existing
	// source's own, and a new source's empty one — none at all.
	SecretRef *string
	// Name labels a new source in the audit trail.
	Name string
}

// ConnectionResult is how a test went.
type ConnectionResult struct {
	OK bool
	// Documents counts what the first page listed that a sync would index;
	// Withheld what it would not — a restricted page, a secured issue, a
	// deleted document. More says the listing goes on past the page.
	Documents int
	Withheld  int
	More      bool
	// Titles are the first few listed documents' titles, as the remote
	// stores them.
	Titles   []string
	Duration time.Duration
	// Error says why the test failed, scrubbed of the credential and of
	// anything else shaped like one; Reason is TestFailedCredential or
	// TestFailedConnector.
	Error  string
	Reason string
}

// TestConnection tries a connection: it lists one small page with the
// configuration and credential in. A configuration or reference the hub would
// refuse to store is an error, as it would be from CreateSource or
// UpdateSource; a remote that refuses or cannot be reached is a result whose
// OK is false. Every test is recorded on the audit trail as
// knowledge.source.test.
func (a *Access) TestConnection(ctx context.Context, in ConnectionTest) (ConnectionResult, error) {
	t, err := a.connectionUnderTest(in)
	if err != nil {
		return ConnectionResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return ConnectionResult{}, err
	}
	res := a.s.tryConnection(ctx, t)
	a.auditConnectionTest(t, res)
	return res, nil
}

// connectionTarget is a test resolved: what to list, as whom, and where the
// row it came from is.
type connectionTarget struct {
	sourceID int64
	name     string
	kind     string
	scope    string
	owner    string
	config   json.RawMessage
	ref      string
	conn     Connector
}

// connectionUnderTest applies the rules CreateSource and UpdateSource apply to
// what in names, and returns it ready to try.
func (a *Access) connectionUnderTest(in ConnectionTest) (connectionTarget, error) {
	var t connectionTarget
	var config json.RawMessage
	ref := ""
	if in.SourceID > 0 {
		if err := a.requireListing(); err != nil {
			return t, err
		}
		row, err := a.visible(in.SourceID)
		if err != nil {
			return t, err
		}
		if !a.canManage(row) {
			return t, a.manageDenied(row, "test")
		}
		t.sourceID, t.name, t.kind, t.scope, t.owner = row.ID, row.Name, row.Kind, row.Scope, row.Owner
		config, ref = json.RawMessage(row.Config), row.SecretRef
	} else {
		scope := strings.TrimSpace(in.Scope)
		if scope == "" {
			scope = ScopeOrg
			if a.p.Identity != "" {
				scope = ScopePersonal
			}
		}
		switch scope {
		case ScopeOrg:
			if !a.isAdmin() {
				return t, forbidden(authz.PermKnowledgeAdmin, "only an administrator may connect an organisation source")
			}
		case ScopePersonal:
			if a.p.Identity == "" {
				return t, invalid("a personal source needs a signed-in person to own it; this request has none, " +
					"so test an organisation source instead")
			}
			if !a.mayOwn() {
				return t, forbidden(authz.PermSecretOwn, "connecting a personal source needs secret.own")
			}
			t.owner = a.p.Identity
		default:
			return t, invalid("a source's scope is %q or %q", ScopeOrg, ScopePersonal)
		}
		t.scope, t.kind = scope, strings.TrimSpace(in.Kind)
		// The name labels the audit row; a form still being filled in may
		// have none, or one CreateSource would refuse.
		if name, err := cleanName(in.Name); err == nil {
			t.name = name
		}
	}
	if in.Config != nil {
		config = in.Config
	}
	if in.SecretRef != nil {
		ref = *in.SecretRef
	}
	conn, ok := a.s.registry.Lookup(t.kind)
	if !ok {
		return t, a.unknownKind(t.kind)
	}
	t.conn = conn
	cfg, err := a.s.validateConfig(conn, t.scope, config)
	if err != nil {
		return t, err
	}
	t.config = cfg
	if t.ref, err = a.s.checkSecretRef(ref, t.owner); err != nil {
		return t, err
	}
	return t, nil
}

// tryConnection lists one page of t, with its credential opened for the call
// and wiped after it.
func (s *Service) tryConnection(ctx context.Context, t connectionTarget) (res ConnectionResult) {
	started := s.now()
	defer func() { res.Duration = s.now().Sub(started) }()
	var cred Credential
	if t.ref != "" {
		if s.credentials == nil {
			return ConnectionResult{Reason: TestFailedCredential,
				Error: "this hub has no secret store to open " + t.ref + " with"}
		}
		b, err := s.credentials.SourceCredential(t.ref, t.owner)
		if err != nil {
			return ConnectionResult{Reason: TestFailedCredential,
				Error: clip(redact.Scrub(fmt.Sprintf("credential %q: %v", t.ref, err)), MaxSyncErrorBytes)}
		}
		cred = NewCredential(b)
	}
	defer cred.wipe()
	scrub := func(text string) string {
		if !cred.IsZero() {
			text = strings.ReplaceAll(text, string(cred.Value()), redact.Marker)
		}
		return clip(redact.Scrub(text), MaxSyncErrorBytes)
	}

	ctx, cancel := context.WithTimeout(ctx, ConnectionTestTimeout)
	defer cancel()
	page, err := func() (page Page, err error) {
		// A connector's panic is its own test's failure, as it is its own
		// sync's, scrubbed while the credential is still at hand.
		defer func() {
			if v := recover(); v != nil {
				err = &PanicError{Kind: t.kind, Op: "list", Value: scrub(fmt.Sprint(v)), Stack: debug.Stack()}
			}
		}()
		return t.conn.List(ctx, ListRequest{Config: t.config, Credential: cred, Scope: t.scope,
			PageSize: connectionTestPage})
	}()
	if err != nil {
		msg := err.Error()
		var pe *PanicError
		if errors.As(err, &pe) {
			msg = "the " + t.kind + " connector failed: " + pe.Value
		}
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil {
			msg = fmt.Sprintf("the remote did not answer within %s: %s", ConnectionTestTimeout, msg)
		}
		return ConnectionResult{Reason: TestFailedConnector, Error: scrub(msg)}
	}
	res = ConnectionResult{OK: true, More: page.More}
	for _, doc := range page.Documents {
		if doc.Deleted {
			res.Withheld++
			continue
		}
		res.Documents++
		if title := strings.TrimSpace(doc.Title); title != "" && len(res.Titles) < connectionTestTitles {
			res.Titles = append(res.Titles, scrub(clip(title, maxTestTitleBytes)))
		}
	}
	return res
}

// auditConnectionTest records a test: what was tried, as whom, and how it
// went. A failure to append is the trail's own to count (statedb records the
// gap); the test's answer stands.
func (a *Access) auditConnectionTest(t connectionTarget, res ConnectionResult) {
	payload := map[string]any{
		"kind": t.kind, "name": t.name, "scope": t.scope, "owner": t.owner,
		"config": configValue(t.config), "signs_in_with": t.ref,
		"outcome": "ok", "documents": res.Documents, "withheld": res.Withheld,
	}
	entity := ""
	if t.sourceID > 0 {
		payload["id"] = t.sourceID
		entity = fmt.Sprint(t.sourceID)
	}
	if !res.OK {
		payload["outcome"], payload["reason"], payload["error"] = "failed", res.Reason, res.Error
	}
	actor := a.p.Actor
	if actor == "" {
		actor = "system"
	}
	_ = a.s.db.AppendAuditEvent(&statedb.AuditEvent{
		Actor: actor, EventType: string(auditaction.ActionKnowledgeSourceTest), EntityType: "knowledge_source",
		EntityID: entity, Payload: statedb.MarshalAuditPayload(payload),
	})
}

// configValue is a configuration as a JSON value for an audit payload.
func configValue(raw json.RawMessage) any {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	return v
}
