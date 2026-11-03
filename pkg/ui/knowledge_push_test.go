package ui

// Knowledge sources pushed to dashboards (Task 20473): each socket hears of
// the sources its person may see — as their own GET would show them — and of
// nothing else, not even that someone else's personal source changed; a sync
// is followed live, start to end, without a poll.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// knowledgeFrames returns the knowledge_source messages a socket received.
func knowledgeFrames(s *healthSocket) []knowledgePush {
	var out []knowledgePush
	for _, raw := range s.frames() {
		var m struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal([]byte(raw), &m) != nil || m.Type != "knowledge_source" {
			continue
		}
		var p knowledgePush
		if json.Unmarshal(m.Data, &p) == nil {
			out = append(out, p)
		}
	}
	return out
}

// waitKnowledge waits up to 30 s for a push on s that ok accepts.
func waitKnowledge(t *testing.T, s *healthSocket, what string, ok func(knowledgePush) bool) knowledgePush {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		for _, p := range knowledgeFrames(s) {
			if ok(p) {
				return p
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s; the socket heard %d knowledge pushes", what, len(knowledgeFrames(s)))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func pushedSource(id int64, pred func(*knowledgeSourceView) bool) func(knowledgePush) bool {
	return func(p knowledgePush) bool {
		return p.Source != nil && p.Source.ID == id && (pred == nil || pred(p.Source))
	}
}

func TestKnowledgeSourcesArePushedToWhoMaySeeThem(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "knowledge-push-test-passphrase")
	registerUIGated.Do(func() { knowledge.MustRegister(uiGated) })
	h := knowledgeHub(t)
	old := knowledgePushGap.Swap(int64(50 * time.Millisecond))
	t.Cleanup(func() { knowledgePushGap.Store(old) })

	admin := h.signIn(t, "ada@example.com", false, "owners")
	lead := h.signIn(t, "lead@example.com", false, "leads")
	bob := h.signIn(t, "bob@example.com", false, "engineers")
	adminWS := dialHealthSocket(t, h.ts.URL, admin)
	leadWS := dialHealthSocket(t, h.ts.URL, lead)
	bobWS := dialHealthSocket(t, h.ts.URL, bob)

	create := func(c *http.Client, name, scope, gate string) int64 {
		t.Helper()
		resp, raw := h.call(t, c, http.MethodPost, "/api/knowledge/sources", map[string]any{
			"kind": "uigated", "name": name, "scope": scope, "config": map[string]any{"gate": gate}})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %s = %d %s", name, resp.StatusCode, raw)
		}
		var d struct {
			Source knowledgeSourceView `json:"source"`
		}
		decodeBody(t, raw, &d)
		return d.Source.ID
	}
	gate := uniqueGate("push")
	org := create(admin, "push-org-wiki", "org", gate+"-org")
	leads := create(lead, "push-lead-notes", "personal", gate+"-lead")
	bobs := create(bob, "push-bob-private", "personal", gate+"-bob")

	// Everyone who may list sources hears of the organisation's; each owner of
	// their own, and the administrator of everything.
	for _, s := range []*healthSocket{adminWS, leadWS, bobWS} {
		waitKnowledge(t, s, "the organisation source", pushedSource(org, nil))
	}
	waitKnowledge(t, leadWS, "the lead's own source", pushedSource(leads, func(v *knowledgeSourceView) bool { return v.Mine && v.Manageable }))
	waitKnowledge(t, adminWS, "the lead's source, to the admin", pushedSource(leads, func(v *knowledgeSourceView) bool { return !v.Mine && !v.Manageable }))
	waitKnowledge(t, bobWS, "bob's own source", pushedSource(bobs, nil))
	waitKnowledge(t, adminWS, "bob's source, to the admin", pushedSource(bobs, nil))

	// A sync, followed live: running, then done with what it indexed.
	if resp, raw := h.call(t, lead, http.MethodPost, fmt.Sprintf("/api/knowledge/sources/%d/sync", leads), map[string]any{}); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("sync = %d %s", resp.StatusCode, raw)
	}
	waitKnowledge(t, leadWS, "the sync to end ok, with its documents", pushedSource(leads, func(v *knowledgeSourceView) bool {
		return v.Sync.Status == "ok" && v.Sync.Running == nil && v.Documents == 2 && v.Sync.Counts != nil && v.Sync.Counts.Created == 2
	}))
	waitKnowledge(t, adminWS, "the admin to see the sync end", pushedSource(leads, func(v *knowledgeSourceView) bool { return v.Documents == 2 }))

	// The organisation's source renamed, and bob's deleted.
	if resp, raw := h.call(t, admin, http.MethodPatch, fmt.Sprintf("/api/knowledge/sources/%d", org), map[string]any{"name": "push-org-wiki-renamed"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("rename = %d %s", resp.StatusCode, raw)
	}
	for _, s := range []*healthSocket{adminWS, leadWS, bobWS} {
		waitKnowledge(t, s, "the rename", pushedSource(org, func(v *knowledgeSourceView) bool { return v.Name == "push-org-wiki-renamed" }))
	}
	if resp, raw := h.call(t, bob, http.MethodDelete, fmt.Sprintf("/api/knowledge/sources/%d", bobs), nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete = %d %s", resp.StatusCode, raw)
	}
	for _, s := range []*healthSocket{adminWS, bobWS} {
		waitKnowledge(t, s, "the deletion", func(p knowledgePush) bool { return p.Deleted && p.ID == bobs && p.Source == nil })
	}

	// What a socket must never have heard: another person's source — its
	// name, its id, that it changed or went.
	time.Sleep(4 * time.Duration(knowledgePushGap.Load()))
	never := func(s *healthSocket, who, name string, id int64) {
		t.Helper()
		for _, raw := range s.frames() {
			if strings.Contains(raw, name) {
				t.Errorf("%s's socket heard of %s: %.300s", who, name, raw)
			}
		}
		for _, p := range knowledgeFrames(s) {
			if p.ID == id || (p.Source != nil && p.Source.ID == id) {
				t.Errorf("%s's socket was pushed source %d, someone else's: %+v", who, id, p)
			}
		}
	}
	never(leadWS, "the lead", "push-bob-private", bobs)
	never(bobWS, "bob", "push-lead-notes", leads)
	// And a push is the source as that person's own GET shows it: the
	// secret reference to a manager alone.
	resp, raw := h.call(t, bob, http.MethodGet, fmt.Sprintf("/api/knowledge/sources/%d", org), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bob's GET = %d %s", resp.StatusCode, raw)
	}
	var got struct {
		Source knowledgeSourceView `json:"source"`
	}
	decodeBody(t, raw, &got)
	frames := knowledgeFrames(bobWS)
	var last *knowledgeSourceView
	for i := range frames {
		if frames[i].Source != nil && frames[i].Source.ID == org {
			last = frames[i].Source
		}
	}
	if last == nil || last.Manageable || last.SecretRef != "" || last.Name != got.Source.Name ||
		string(last.Config) != string(got.Source.Config) || last.Manageable != got.Source.Manageable {
		t.Errorf("bob was last pushed %+v; his GET says %+v", last, got.Source)
	}
}

// TestKnowledgePushReachesAViewerNothing: a person who may not list sources
// at all hears of none of them.
func TestKnowledgePushReachesAViewerNothing(t *testing.T) {
	registerUIGated.Do(func() { knowledge.MustRegister(uiGated) })
	h := knowledgeHub(t)
	old := knowledgePushGap.Swap(int64(50 * time.Millisecond))
	t.Cleanup(func() { knowledgePushGap.Store(old) })
	admin := h.signIn(t, "ada@example.com", false, "owners")
	viewer := h.signIn(t, "vic@example.com", false, "readers")
	adminWS := dialHealthSocket(t, h.ts.URL, admin)
	viewerWS := dialHealthSocket(t, h.ts.URL, viewer)
	resp, raw := h.call(t, admin, http.MethodPost, "/api/knowledge/sources", map[string]any{
		"kind": "uigated", "name": "viewer-push-org", "scope": "org", "config": map[string]any{"gate": uniqueGate("viewer")}})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", resp.StatusCode, raw)
	}
	waitKnowledge(t, adminWS, "the admin's push", func(p knowledgePush) bool { return p.Source != nil && p.Source.Name == "viewer-push-org" })
	time.Sleep(4 * time.Duration(knowledgePushGap.Load()))
	if got := knowledgeFrames(viewerWS); len(got) != 0 {
		t.Errorf("a viewer was pushed %d knowledge sources: %+v", len(got), got)
	}
}
