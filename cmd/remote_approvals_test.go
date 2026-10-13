package cmd

// `cloop remote approvals` (Task 20427): an approver lists what waits on them
// and decides it from a terminal; the requester never sees their own request
// as theirs to decide, a viewer has nothing to decide, and the requester reads
// the answers in `cloop remote grants list`.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/pkg/hubclient"
)

func TestRemoteApprovalsListApproveDeny(t *testing.T) {
	w := newRemoteWorld(t)
	path := rootProject(t, w)
	storeSecret(t, w, "org-token", "github_pat", patPayload, false)
	share(t, w, path, oliveEmail, "operator")

	// An operator asks, twice.
	w.as(t, oliveEmail, ssohubtest.GroupOperators)
	var ids []string
	for _, repo := range []string{"acme/widgets", "acme/docs"} {
		out, err := runRemoteCLI(t, "grants", "request", "org-token", "--project", "widgets", "--repo", repo,
			"--justification", "Work on "+repo+" (API-412)", "--json")
		if err != nil {
			t.Fatalf("grants request: %v\n%s", err, out)
		}
		var req hubclient.GrantRequest
		if err := json.Unmarshal([]byte(out), &req); err != nil || req.ID == "" {
			t.Fatalf("grants request --json = %q (%v)", out, err)
		}
		ids = append(ids, req.ID)
	}

	// Their own requests are not theirs to decide — and an operator may not
	// approve anything, which the hub says, not this terminal.
	out, err := runRemoteCLI(t, "approvals", "list")
	if err != nil || !strings.Contains(out, "Nothing is waiting on you.") ||
		!strings.Contains(out, "2 request(s) of your own are waiting on somebody else") {
		t.Fatalf("the requester's approvals list = %v\n%s", err, out)
	}
	if _, err := runRemoteCLI(t, "approvals", "approve", ids[0]); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("a requester approving their own request = %v, want the hub's refusal", err)
	}

	// A maintainer sees both, soonest deadline first, with the reason given.
	w.as(t, alexEmail, ssohubtest.GroupMaintainers)
	out, err = runRemoteCLI(t, "approvals", "list", "--json")
	if err != nil {
		t.Fatalf("approvals list --json: %v\n%s", err, out)
	}
	var inbox hubclient.Approvals
	if err := json.Unmarshal([]byte(out), &inbox); err != nil || inbox.Count != 2 || len(inbox.Items) != 2 {
		t.Fatalf("the maintainer's inbox = %+v (%v)", inbox, err)
	}
	for _, it := range inbox.Items {
		if it.Kind != "grant_request" || it.Request == nil || it.Request.RequestedBy != oliveEmail || it.Deadline == "" {
			t.Fatalf("inbox item = %+v", it)
		}
	}
	out, err = runRemoteCLI(t, "approvals", "list")
	if err != nil || !strings.Contains(out, "request") || !strings.Contains(out, "org-token (github_pat)") ||
		!strings.Contains(out, "lapses in") || !strings.Contains(out, "Work on acme/widgets (API-412)") {
		t.Fatalf("approvals list (table) = %v\n%s", err, out)
	}

	// A prefix is refused — it could name another request once the one it
	// named is decided — and so is a --ttl that would round to none.
	if _, err := runRemoteCLI(t, "approvals", "approve", ids[0][:12]); err == nil || !strings.Contains(err.Error(), "whole") {
		t.Fatalf("approving by a prefix = %v, want a refusal asking for the whole id", err)
	}
	if _, err := runRemoteCLI(t, "approvals", "approve", ids[0], "--ttl", "30s"); err == nil || !strings.Contains(err.Error(), "minute") {
		t.Fatalf("approving with --ttl 30s = %v, want a refusal", err)
	}
	// Approve one, narrowed; deny the other with a reason.
	out, err = runRemoteCLI(t, "approvals", "approve", ids[0], "--ttl", "1h", "--note", "for the release")
	if err != nil || !strings.Contains(out, "Approved request "+ids[0]) || !strings.Contains(out, "grant ") ||
		!strings.Contains(out, ", until ") {
		t.Fatalf("approvals approve = %v\n%s", err, out)
	}
	if _, err := runRemoteCLI(t, "approvals", "deny", ids[1]); err == nil || !strings.Contains(err.Error(), "--note") {
		t.Fatalf("a denial with no reason = %v", err)
	}
	out, err = runRemoteCLI(t, "approvals", "deny", ids[1], "--note", "docs are public; clone them")
	if err != nil || !strings.Contains(out, "Denied request "+ids[1]) {
		t.Fatalf("approvals deny = %v\n%s", err, out)
	}
	out, err = runRemoteCLI(t, "approvals", "list")
	if err != nil || !strings.Contains(out, "Nothing is waiting on you.") {
		t.Fatalf("after deciding both = %v\n%s", err, out)
	}
	if _, err := runRemoteCLI(t, "approvals", "approve", "0123456789"); err == nil ||
		!strings.Contains(err.Error(), "nothing waiting on you") {
		t.Fatalf("approving an id that names nothing = %v", err)
	}

	// A viewer has nothing to decide.
	w.as(t, vicEmail, ssohubtest.GroupViewers)
	if out, err := runRemoteCLI(t, "approvals", "list"); err != nil || !strings.Contains(out, "Nothing is waiting on you.") {
		t.Fatalf("a viewer's approvals list = %v\n%s", err, out)
	}

	// The requester reads the answers.
	w.as(t, oliveEmail, ssohubtest.GroupOperators)
	out, err = runRemoteCLI(t, "grants", "list")
	if err != nil || !strings.Contains(out, ids[0]+" was approved by "+alexEmail) ||
		!strings.Contains(out, ids[1]+" was denied by "+alexEmail+": docs are public; clone them") {
		t.Fatalf("the requester's grants list = %v\n%s", err, out)
	}
}

// TestRemoteApprovalsPrintNoTerminalControls: what a requester typed reaches an
// approver's terminal without an escape sequence or a bidirectional override
// that could repaint or reorder the line.
func TestRemoteApprovalsPrintNoTerminalControls(t *testing.T) {
	inbox := &hubclient.Approvals{Items: []hubclient.ApprovalItem{{
		Kind: "grant_request", ID: "req_1", Deadline: "2026-10-16T12:00:00Z",
		Request: &hubclient.GrantRequest{
			RequestedBy: "dev@example.com", SecretName: "org-token", Kind: "github_pat",
			Subject:       "project:/srv/\x1b[2J\x1b[Happroved",
			Justification: "please \x1b]8;;https://evil.example\x07click\x1b]8;;\x07 \u202eevil\u202c\r\noverwrite",
		},
	}}}
	var b strings.Builder
	printApprovals(&b, inbox, time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC))
	for _, c := range []string{"\x1b", "\x07", "\r", "\u202e", "\u202c"} {
		if strings.Contains(b.String(), c) {
			t.Fatalf("the listing carries %q:\n%q", c, b.String())
		}
	}
	if !strings.Contains(b.String(), "org-token (github_pat)") {
		t.Fatalf("the listing lost the request:\n%s", b.String())
	}
}
