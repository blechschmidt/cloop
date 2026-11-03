package ui

// Test connection (Task 20473): POST /api/knowledge/test-connection tries a
// knowledge source's configuration and credential — a source being connected,
// or an existing one with the changes its form holds — by listing one small
// page, and says what came back or why nothing did. Nothing is stored.
//
// A test sends the credential the reference names to the address the
// configuration names, which is what saving that configuration would do, so it
// is held to the same rules (knowledge.Access.TestConnection) and, on an SSO
// hub, to the same recent sign-in (Sudo). Each person may run a few tests in a
// row and then one every few seconds: every test is a request from inside the
// hub's network, and a form is not a scanner.

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/knowledge"
)

// knowledgeTestRequest is the body of POST /api/knowledge/test-connection.
// source_id tries an existing source, with config and secret_ref — when
// present — in place of its own; without it, kind, scope and config describe
// a new source, and name labels its audit row.
type knowledgeTestRequest struct {
	SourceID  int64           `json:"source_id"`
	Kind      string          `json:"kind"`
	Scope     string          `json:"scope"`
	Name      string          `json:"name"`
	Config    json.RawMessage `json:"config"`
	SecretRef *string         `json:"secret_ref"`
}

// knowledgeTestView is how a test went, as the dashboard shows it.
type knowledgeTestView struct {
	OK         bool     `json:"ok"`
	Documents  int      `json:"documents"`
	Withheld   int      `json:"withheld"`
	More       bool     `json:"more"`
	Titles     []string `json:"titles"`
	DurationMS int64    `json:"duration_ms"`
	// Failure says why the test failed, scrubbed of credentials; Reason is
	// credential or connector.
	Failure string `json:"failure,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// Each person's test rate: a few in a row while a form is being got right,
// then one every connectionTestEvery.
var (
	connectionTestBurst = 6.0
	connectionTestEvery = 10 * time.Second
)

// connectionTests holds each person's bucket in this process; a cluster
// member holds its own.
var connectionTests = struct {
	mu      sync.Mutex
	buckets map[string]*runKnowledgeBucket
}{buckets: map[string]*runKnowledgeBucket{}}

// allowConnectionTest takes a test from who's bucket.
func allowConnectionTest(who string, now time.Time) bool {
	connectionTests.mu.Lock()
	defer connectionTests.mu.Unlock()
	if len(connectionTests.buckets) > 4096 {
		for k, b := range connectionTests.buckets {
			if now.Sub(b.last) > time.Duration(connectionTestBurst)*connectionTestEvery {
				delete(connectionTests.buckets, k)
			}
		}
	}
	b := connectionTests.buckets[who]
	if b == nil {
		b = &runKnowledgeBucket{tokens: connectionTestBurst, last: now}
		connectionTests.buckets[who] = b
	}
	b.tokens = min(connectionTestBurst, b.tokens+now.Sub(b.last).Seconds()/connectionTestEvery.Seconds())
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// handleKnowledgeTestConnection serves POST /api/knowledge/test-connection.
func (s *Server) handleKnowledgeTestConnection(w http.ResponseWriter, r *http.Request) {
	var req knowledgeTestRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	who := s.knowledgePrincipal(r, nil).Identity
	if who == "" {
		who = s.auditActor(r)
	}
	if !allowConnectionTest(who, time.Now()) {
		apierror.WriteError(w, apierror.New(apierror.CodeRateLimited,
			"too many connection tests in a row; wait a few seconds and test again"))
		return
	}
	g := s.grantFor(r)
	switch {
	case req.SourceID > 0:
		acc, done, ok := s.knowledgeAccess(w, r, nil)
		if !ok {
			return
		}
		src, _, err := acc.Source(r.Context(), req.SourceID)
		done()
		if err != nil {
			s.writeKnowledgeError(w, err, "test the knowledge source")
			return
		}
		if g, ok = s.knowledgeAdminGrant(w, r, src); !ok {
			return
		}
	case strings.TrimSpace(req.Scope) == knowledge.ScopeOrg:
		var ok bool
		if g, ok = s.authorize(w, r, authz.PermKnowledgeAdmin, authz.GlobalScope); !ok {
			return
		}
	}
	acc, done, ok := s.knowledgeAccessWithSecrets(w, r, g)
	if !ok {
		return
	}
	defer done()
	res, err := acc.TestConnection(r.Context(), knowledge.ConnectionTest{
		SourceID: req.SourceID, Kind: req.Kind, Scope: req.Scope, Name: req.Name, Config: req.Config,
		SecretRef: req.SecretRef,
	})
	if err != nil {
		s.writeKnowledgeError(w, err, "test the knowledge source")
		return
	}
	s.broadcastAuditAppend(string(auditaction.ActionKnowledgeSourceTest))
	titles := res.Titles
	if titles == nil {
		titles = []string{}
	}
	jsonOK(w, map[string]any{"result": knowledgeTestView{
		OK: res.OK, Documents: res.Documents, Withheld: res.Withheld, More: res.More, Titles: titles,
		DurationMS: res.Duration.Milliseconds(), Failure: res.Error, Reason: res.Reason,
	}})
}
