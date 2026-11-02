package ui

// The knowledge source routes (Task 20467): who reaches what, over HTTP, on an
// SSO hub with a role policy — and the origin, JSON and sudo guards on them.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// uiTestConnector stands in for a real connector, registered the way a
// connector package registers itself.
type uiTestConnector struct{}

func (uiTestConnector) Kind() string { return "uitest" }

func (uiTestConnector) Validate(config json.RawMessage) error {
	if strings.Contains(string(config), "refuse") {
		return errors.New("refused by the connector")
	}
	return nil
}

func (uiTestConnector) List(context.Context, knowledge.ListRequest) (knowledge.Page, error) {
	return knowledge.Page{}, nil
}

func (uiTestConnector) Fetch(context.Context, knowledge.FetchRequest) (knowledge.Document, error) {
	return knowledge.Document{}, errors.New("not here")
}

var registerUITestConnector sync.Once

// knowledgeHub is a sudo hub whose policy has all four roles: readers view,
// engineers operate, leads maintain, owners administer.
func knowledgeHub(t *testing.T) *sudoHub {
	t.Helper()
	registerUITestConnector.Do(func() { knowledge.MustRegister(uiTestConnector{}) })
	h := newSudoHub(t, false)
	resolver, err := authz.New(authz.Config{Bindings: []authz.Binding{
		{Claim: authz.ClaimGroup, Value: "readers", Role: authz.RoleViewer},
		{Claim: authz.ClaimGroup, Value: "engineers", Role: authz.RoleOperator},
		{Claim: authz.ClaimGroup, Value: "leads", Role: authz.RoleMaintainer},
		{Claim: authz.ClaimGroup, Value: "owners", Role: authz.RoleAdmin},
	}})
	if err != nil {
		t.Fatal(err)
	}
	h.srv.Authz = resolver
	return h
}

func decodeBody(t *testing.T, raw []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
}

func requiredPermission(raw []byte) string {
	var env struct {
		Error struct {
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &env)
	p, _ := env.Error.Details["required_permission"].(string)
	return p
}

// TestKnowledgeAPIEnforcesRoles walks the ladder through every route: who may
// list, create, change, delete, bind, unbind and search, and what each denial
// names.
func TestKnowledgeAPIEnforcesRoles(t *testing.T) {
	h := knowledgeHub(t)
	viewer := h.signIn(t, "vic@example.com", false, "readers")
	engineer := h.signIn(t, "eng@example.com", false, "engineers")
	lead := h.signIn(t, "lead@example.com", false, "leads")
	admin := h.signIn(t, "ada@example.com", false, "owners")

	expect := func(c *http.Client, method, path string, body any, want int) []byte {
		t.Helper()
		resp, raw := h.call(t, c, method, path, body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s = %d %s, want %d", method, path, resp.StatusCode, raw, want)
		}
		return raw
	}

	// Listing is for the people who connect sources.
	expect(viewer, "GET", "/api/knowledge/sources", nil, http.StatusForbidden)
	var list struct {
		Sources           []knowledgeSourceView `json:"sources"`
		Connectors        []string              `json:"connectors"`
		CanCreateOrg      bool                  `json:"can_create_org"`
		CanCreatePersonal bool                  `json:"can_create_personal"`
	}
	decodeBody(t, expect(engineer, "GET", "/api/knowledge/sources", nil, http.StatusOK), &list)
	if list.CanCreateOrg || !list.CanCreatePersonal || !strings.Contains(strings.Join(list.Connectors, ","), "uitest") {
		t.Fatalf("an engineer's listing = %+v", list)
	}

	// An organisation source takes knowledge.admin.
	raw := expect(engineer, "POST", "/api/knowledge/sources",
		map[string]any{"kind": "uitest", "name": "Eng wiki", "scope": "org", "config": map[string]any{}}, http.StatusForbidden)
	if requiredPermission(raw) != string(authz.PermKnowledgeAdmin) {
		t.Fatalf("the refusal names %q: %s", requiredPermission(raw), raw)
	}
	var created struct {
		Source knowledgeSourceView `json:"source"`
	}
	decodeBody(t, expect(admin, "POST", "/api/knowledge/sources",
		map[string]any{"kind": "uitest", "name": "Eng wiki", "scope": "org", "config": map[string]any{"base": "x"}},
		http.StatusCreated), &created)
	org := created.Source
	if org.Scope != "org" || org.Owner != "" || !org.Manageable {
		t.Fatalf("the org source = %+v", org)
	}
	// A personal source is the default for a signed-in person.
	decodeBody(t, expect(engineer, "POST", "/api/knowledge/sources",
		map[string]any{"kind": "uitest", "name": "My notes", "config": map[string]any{}}, http.StatusCreated), &created)
	mine := created.Source
	if mine.Scope != "personal" || mine.Owner != "eng@example.com" || !mine.Mine || !mine.Manageable {
		t.Fatalf("the engineer's source = %+v", mine)
	}
	// Bad input is the caller's to fix.
	expect(admin, "POST", "/api/knowledge/sources",
		map[string]any{"kind": "uitest", "name": "x", "scope": "org", "config": map[string]any{"api_token": "abc"}}, http.StatusBadRequest)
	expect(admin, "POST", "/api/knowledge/sources",
		map[string]any{"kind": "uitest", "name": "x", "scope": "org", "config": map[string]any{"refuse": true}}, http.StatusBadRequest)
	expect(admin, "POST", "/api/knowledge/sources",
		map[string]any{"kind": "uitest", "name": "Eng wiki", "scope": "org"}, http.StatusConflict)

	// What each one sees.
	decodeBody(t, expect(engineer, "GET", "/api/knowledge/sources", nil, http.StatusOK), &list)
	if len(list.Sources) != 2 {
		t.Fatalf("the engineer sees %d sources, want the org source and their own", len(list.Sources))
	}
	for _, s := range list.Sources {
		if s.ID == org.ID && s.Manageable {
			t.Fatal("the engineer may manage the org source")
		}
	}
	decodeBody(t, expect(lead, "GET", "/api/knowledge/sources", nil, http.StatusOK), &list)
	if len(list.Sources) != 1 || list.Sources[0].ID != org.ID {
		t.Fatalf("the lead sees %+v; the engineer's personal source is theirs alone", list.Sources)
	}
	expect(lead, "GET", "/api/knowledge/sources/"+itoa64(mine.ID), nil, http.StatusNotFound)
	expect(lead, "PATCH", "/api/knowledge/sources/"+itoa64(org.ID), map[string]any{"enabled": false}, http.StatusForbidden)
	expect(engineer, "PATCH", "/api/knowledge/sources/"+itoa64(mine.ID), map[string]any{"name": "Notes"}, http.StatusOK)
	expect(engineer, "PATCH", "/api/knowledge/sources/"+itoa64(mine.ID), map[string]any{"kind": "other"}, http.StatusBadRequest)
	expect(engineer, "GET", "/api/knowledge/sources/abc", nil, http.StatusBadRequest)
	expect(engineer, "GET", "/api/knowledge/sources/999", nil, http.StatusNotFound)

	// Binding: project.write on the project, and the source is the
	// organisation's with knowledge.admin or the caller's own.
	raw = expect(lead, "POST", "/api/projects/0/knowledge/bindings", map[string]any{"source_id": org.ID}, http.StatusForbidden)
	if requiredPermission(raw) != string(authz.PermKnowledgeAdmin) {
		t.Fatalf("a lead binding the org source: refusal names %q", requiredPermission(raw))
	}
	raw = expect(engineer, "POST", "/api/projects/0/knowledge/bindings", map[string]any{"source_id": mine.ID}, http.StatusForbidden)
	if requiredPermission(raw) != string(authz.PermProjectWrite) {
		t.Fatalf("an engineer binding to a project they cannot write: refusal names %q", requiredPermission(raw))
	}
	var bound struct {
		Binding knowledgeBindingView `json:"binding"`
		Created bool                 `json:"created"`
	}
	decodeBody(t, expect(admin, "POST", "/api/projects/0/knowledge/bindings",
		map[string]any{"source_id": org.ID, "spaces": []string{"ENG"}}, http.StatusCreated), &bound)
	if !bound.Created || strings.Join(bound.Binding.Spaces, ",") != "ENG" {
		t.Fatalf("the admin's binding = %+v", bound)
	}
	// The admin sees the engineer's source, and still may not bind it: only
	// its owner decides who reads with their credential.
	expect(admin, "POST", "/api/projects/0/knowledge/bindings", map[string]any{"source_id": mine.ID}, http.StatusForbidden)
	// The lead cannot see it at all.
	expect(lead, "POST", "/api/projects/0/knowledge/bindings", map[string]any{"source_id": mine.ID}, http.StatusNotFound)

	// Index two documents into the org source, one outside the binding's space.
	db, err := h.srv.controlPlaneDB()
	if err != nil {
		t.Fatal(err)
	}
	svc := knowledge.New(db)
	for _, doc := range []knowledge.Document{
		{ExternalID: "eng", Title: "Rollback runbook", Space: "ENG", Body: "How to roll back a deploy: rollback steps."},
		{ExternalID: "hr", Title: "Rollback of payroll", Space: "HR", Body: "Payroll rollback is HR's."},
	} {
		if _, err := svc.Index(org.ID, doc); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	// A viewer searches; only the bound, narrowed knowledge comes back.
	var found struct {
		Hits []knowledgeHitView `json:"hits"`
	}
	decodeBody(t, expect(viewer, "GET", "/api/projects/0/knowledge/search?q=rollback&k=5", nil, http.StatusOK), &found)
	if len(found.Hits) != 1 || found.Hits[0].ExternalID != "eng" || found.Hits[0].Source.Name != "Eng wiki" {
		t.Fatalf("the viewer's search = %+v", found.Hits)
	}
	if !strings.Contains(found.Hits[0].Snippet, knowledge.SnippetOpen) || found.Hits[0].Rank != 1 {
		t.Fatalf("hit %+v has no marked snippet or rank", found.Hits[0])
	}
	if strings.Contains(string(expect(viewer, "GET", "/api/projects/0/knowledge/search?q=rollback", nil, http.StatusOK)), "score") {
		t.Fatal("a search result carries a BM25 score, which is weighed across every project's sources")
	}
	expect(viewer, "GET", "/api/projects/0/knowledge/search?q=", nil, http.StatusBadRequest)
	expect(viewer, "GET", "/api/projects/0/knowledge/search?q=x&k=0", nil, http.StatusBadRequest)
	expect(viewer, "GET", "/api/projects/7/knowledge/search?q=rollback", nil, http.StatusNotFound)

	var projectSources struct {
		Sources []knowledgeBoundView `json:"sources"`
	}
	decodeBody(t, expect(viewer, "GET", "/api/projects/0/knowledge/sources", nil, http.StatusOK), &projectSources)
	if len(projectSources.Sources) != 1 || projectSources.Sources[0].Source.Config != nil || projectSources.Sources[0].Source.Documents != 2 {
		t.Fatalf("the project's sources as a viewer sees them = %+v", projectSources.Sources)
	}

	// Unbinding takes project.write and nothing more.
	path := "/api/projects/0/knowledge/bindings/" + itoa64(bound.Binding.ID)
	expect(engineer, "DELETE", path, nil, http.StatusForbidden)
	expect(lead, "DELETE", path, nil, http.StatusOK)
	expect(lead, "DELETE", path, nil, http.StatusNotFound)
	decodeBody(t, expect(viewer, "GET", "/api/projects/0/knowledge/search?q=rollback", nil, http.StatusOK), &found)
	if len(found.Hits) != 0 {
		t.Fatalf("an unbound source is still searched: %+v", found.Hits)
	}

	// Deleting: an admin, for an org source; its documents go with it.
	expect(engineer, "DELETE", "/api/knowledge/sources/"+itoa64(org.ID), nil, http.StatusForbidden)
	var deleted struct {
		Removed map[string]int `json:"removed"`
	}
	decodeBody(t, expect(admin, "DELETE", "/api/knowledge/sources/"+itoa64(org.ID), nil, http.StatusOK), &deleted)
	if deleted.Removed["documents"] != 2 {
		t.Fatalf("deleting the org source removed %+v", deleted.Removed)
	}
	// The admin may delete the engineer's personal source, never change it.
	expect(admin, "PATCH", "/api/knowledge/sources/"+itoa64(mine.ID), map[string]any{"config": map[string]any{"base": "elsewhere"}}, http.StatusForbidden)
	expect(admin, "DELETE", "/api/knowledge/sources/"+itoa64(mine.ID), nil, http.StatusOK)
}

// TestKnowledgeAPIAsksForARecentSignIn: a session whose sign-in is stale
// reads, unbinds, and is asked to sign in again before it creates, changes,
// deletes or binds a source.
func TestKnowledgeAPIAsksForARecentSignIn(t *testing.T) {
	h := knowledgeHub(t)
	fresh := h.signIn(t, "ada@example.com", false, "owners")
	resp, raw := h.call(t, fresh, "POST", "/api/knowledge/sources", map[string]any{"kind": "uitest", "name": "Wiki", "scope": "org"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", resp.StatusCode, raw)
	}
	var created struct {
		Source knowledgeSourceView `json:"source"`
	}
	decodeBody(t, raw, &created)
	resp, raw = h.call(t, fresh, "POST", "/api/projects/0/knowledge/bindings", map[string]any{"source_id": created.Source.ID})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("bind = %d %s", resp.StatusCode, raw)
	}
	var bound struct {
		Binding knowledgeBindingView `json:"binding"`
	}
	decodeBody(t, raw, &bound)

	stale := h.signIn(t, "ada@example.com", true, "owners")
	id := itoa64(created.Source.ID)
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/knowledge/sources", map[string]any{"kind": "uitest", "name": "Other", "scope": "org"}},
		{"PATCH", "/api/knowledge/sources/" + id, map[string]any{"enabled": false}},
		{"DELETE", "/api/knowledge/sources/" + id, nil},
		{"POST", "/api/projects/0/knowledge/bindings", map[string]any{"source_id": created.Source.ID}},
	} {
		resp, raw := h.call(t, stale, c.method, c.path, c.body)
		if resp.StatusCode != http.StatusUnauthorized || reauthCode(raw) != "REAUTH_REQUIRED" {
			t.Errorf("stale %s %s = %d %s, want 401 REAUTH_REQUIRED", c.method, c.path, resp.StatusCode, raw)
		}
	}
	for _, path := range []string{"/api/knowledge/sources", "/api/knowledge/sources/" + id, "/api/projects/0/knowledge/search?q=x"} {
		if resp, raw := h.call(t, stale, "GET", path, nil); resp.StatusCode != http.StatusOK {
			t.Errorf("stale GET %s = %d %s; reads never ask", path, resp.StatusCode, raw)
		}
	}
	if resp, raw := h.call(t, stale, "DELETE", "/api/projects/0/knowledge/bindings/"+itoa64(bound.Binding.ID), nil); resp.StatusCode != http.StatusOK {
		t.Errorf("stale unbind = %d %s; taking access away does not ask", resp.StatusCode, raw)
	}
}

// TestKnowledgeAPIGuardsOriginAndMediaType: a state-changing request from
// another origin, or with a body that is not JSON, never reaches the handler.
func TestKnowledgeAPIGuardsOriginAndMediaType(t *testing.T) {
	h := knowledgeHub(t)
	admin := h.signIn(t, "ada@example.com", false, "owners")
	body := []byte(`{"kind":"uitest","name":"Wiki","scope":"org"}`)

	req, _ := http.NewRequest("POST", h.ts.URL+"/api/knowledge/sources", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://attacker.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a cross-origin create = %d, want 403", resp.StatusCode)
	}

	req, _ = http.NewRequest("POST", h.ts.URL+"/api/knowledge/sources", bytes.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	resp, err = admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("a text/plain create = %d, want 415", resp.StatusCode)
	}

	// Neither created anything.
	resp, raw := h.call(t, admin, "GET", "/api/knowledge/sources", nil)
	var list struct {
		Sources []knowledgeSourceView `json:"sources"`
	}
	decodeBody(t, raw, &list)
	if resp.StatusCode != http.StatusOK || len(list.Sources) != 0 {
		t.Fatalf("after the refused requests: %d %s", resp.StatusCode, raw)
	}
}

// TestRemovingAProjectDropsItsKnowledgeBindings: bindings are keyed by the
// project's path, so a project removed from the hub takes them with it, each
// audited, and one registered at the same path afterwards searches nothing.
func TestRemovingAProjectDropsItsKnowledgeBindings(t *testing.T) {
	f := newMemberFixture(t, true)
	db, err := f.srv.controlPlaneDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	src, err := db.CreateKnowledgeSource(statedb.KnowledgeSourceRow{Kind: "uitest", Name: "Wiki", Scope: "org", Enabled: true}, "root")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.PutKnowledgeBinding(statedb.KnowledgeBindingRow{SourceID: src.ID, ProjectPath: f.project}, "root"); err != nil {
		t.Fatal(err)
	}
	other := "/srv/elsewhere"
	if _, _, err := db.PutKnowledgeBinding(statedb.KnowledgeBindingRow{SourceID: src.ID, ProjectPath: other}, "root"); err != nil {
		t.Fatal(err)
	}

	i := f.idx(t, f.alice, f.project)
	if code, body := f.call(t, f.alice, http.MethodDelete, "/api/projects/"+itoa(i), nil); code != http.StatusOK {
		t.Fatalf("alice removes the project: %d %v", code, body)
	}
	if left, err := db.ListKnowledgeBindings(statedb.KnowledgeBindingFilter{ProjectPath: f.project}); err != nil || len(left) != 0 {
		t.Fatalf("the removed project still has knowledge bindings: %+v, %v", left, err)
	}
	if kept, err := db.ListKnowledgeBindings(statedb.KnowledgeBindingFilter{ProjectPath: other}); err != nil || len(kept) != 1 {
		t.Fatalf("another project's binding went with it: %+v, %v", kept, err)
	}
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionKnowledgeSourceUnbind)})
	if err != nil || len(rows) != 1 || !strings.Contains(rows[0].Payload, "removed from the hub") {
		t.Fatalf("the unbind is not on the trail with its reason: %+v, %v", rows, err)
	}
}
