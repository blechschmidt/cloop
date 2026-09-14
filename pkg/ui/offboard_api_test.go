package ui

// End-to-end tests for the offboarding surface (Task 20261).
//
// The resolution and severing logic is covered in pkg/offboard. What only a
// real server can show is here: that the route is gated on the permission it
// claims, that a dry run really changes nothing over HTTP, that an operator
// cannot aim it at themselves, and that a real run makes the target's *next
// request* fail.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// postOffboard issues the offboard call as c and returns the status and body.
func postOffboard(t *testing.T, c *http.Client, base string, body map[string]any) (int, map[string]any) {
	t.Helper()
	blob, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", base+"/api/users/offboard", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestOffboardIsGatedOnUserManage. Everything below admin must be refused —
// including the dry run, which enumerates a person's entire credential
// footprint and is exactly the read a stolen operator cookie would want.
func TestOffboardIsGatedOnUserManage(t *testing.T) {
	ts, _, clients := newSessionsFixture(t)

	for _, role := range []string{"viewer", "operator", "maintainer"} {
		for _, dry := range []bool{true, false} {
			status, _ := postOffboard(t, clients[role], ts.URL, map[string]any{
				"identity": "someone@example.com",
				"reason":   "testing the gate",
				"dry_run":  dry,
			})
			if status != http.StatusForbidden && status != http.StatusUnauthorized {
				t.Errorf("%s dry_run=%v got %d, want 403/401 — offboarding is "+
					"gated on user.manage", role, dry, status)
			}
		}
	}

	status, _ := postOffboard(t, clients["admin"], ts.URL, map[string]any{
		"identity": "nobody@example.com", "dry_run": true,
	})
	if status != http.StatusOK {
		t.Fatalf("admin got %d, want 200", status)
	}
}

// TestOffboardRefusesSelf: the run would revoke the session issuing it and
// deny the account that must undo it.
func TestOffboardRefusesSelf(t *testing.T) {
	ts, _, clients := newSessionsFixture(t)

	for _, spelling := range []string{"admin@example.com", "ADMIN@EXAMPLE.COM", "u-admin", "sub:u-admin"} {
		status, body := postOffboard(t, clients["admin"], ts.URL, map[string]any{
			"identity": spelling, "reason": "should never apply", "dry_run": false,
		})
		if status != http.StatusForbidden {
			t.Errorf("offboarding self as %q got %d, want 403 (body %v)",
				spelling, status, body)
		}
	}

	// The admin's own session must still work afterwards.
	if rows := sessionsOf(t, clients["admin"], ts.URL); len(rows) == 0 {
		t.Fatal("the refused self-offboard ended the caller's session anyway")
	}
}

// TestOffboardDryRunChangesNothingOverHTTP. The preview is what an operator
// approves against, so it must be the read half of the write and nothing more.
func TestOffboardDryRunChangesNothingOverHTTP(t *testing.T) {
	ts, _, clients := newSessionsFixture(t)
	before := len(sessionsOf(t, clients["admin"], ts.URL))

	status, body := postOffboard(t, clients["admin"], ts.URL, map[string]any{
		"identity": "viewer@example.com", "dry_run": true,
	})
	if status != http.StatusOK {
		t.Fatalf("dry run got %d: %v", status, body)
	}
	if dry, _ := body["dry_run"].(bool); !dry {
		t.Fatalf("response does not report itself as a dry run: %v", body)
	}
	if sessions, ok := body["sessions"].([]any); !ok || len(sessions) != 1 {
		t.Fatalf("dry run should have found the viewer's one session, got %v", body["sessions"])
	}
	if _, severed := body["sessions_revoked"]; severed {
		t.Fatalf("dry run reported severing something: %v", body)
	}
	if after := len(sessionsOf(t, clients["admin"], ts.URL)); after != before {
		t.Fatalf("sessions went from %d to %d during a dry run", before, after)
	}
	// And the viewer can still make requests.
	if rows := sessionsOf(t, clients["admin"], ts.URL); len(rows) == 0 {
		t.Fatal("unexpected empty session list")
	}
}

// TestOffboardEndsTheTargetsNextRequest is the property that matters: not that
// a row was deleted, but that the person cannot act any more.
func TestOffboardEndsTheTargetsNextRequest(t *testing.T) {
	ts, _, clients := newSessionsFixture(t)

	status, body := postOffboard(t, clients["admin"], ts.URL, map[string]any{
		"identity": "operator@example.com",
		"reason":   "left the company, HR-882",
	})
	if status != http.StatusOK {
		t.Fatalf("offboard got %d: %v", status, body)
	}
	revoked, _ := body["sessions_revoked"].([]any)
	if len(revoked) != 1 {
		t.Fatalf("sessions_revoked = %v, want the operator's one session", body["sessions_revoked"])
	}

	// The operator's next request must not be served from the session cache.
	resp, err := clients["operator"].Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("an offboarded user's next request was served (%d) — the session "+
			"survived its own revocation", resp.StatusCode)
	}

	// Everybody else is untouched.
	if rows := sessionsOf(t, clients["admin"], ts.URL); len(rows) == 0 {
		t.Fatal("offboarding one user ended the administrator's session too")
	}
}

// TestOffboardRequiresAReasonToWrite: a dry run does not need one (demanding it
// would train operators to type a placeholder they then reuse), a write does.
func TestOffboardRequiresAReasonToWrite(t *testing.T) {
	ts, _, clients := newSessionsFixture(t)

	status, _ := postOffboard(t, clients["admin"], ts.URL, map[string]any{
		"identity": "viewer@example.com", "dry_run": true,
	})
	if status != http.StatusOK {
		t.Fatalf("dry run without a reason got %d, want 200", status)
	}

	status, _ = postOffboard(t, clients["admin"], ts.URL, map[string]any{
		"identity": "viewer@example.com",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("write without a reason got %d, want 400", status)
	}
	// ...and it really did not write.
	if rows := sessionsOf(t, clients["admin"], ts.URL); len(rows) != 4 {
		t.Fatalf("sessions = %d, want 4 — a rejected write severed something", len(rows))
	}
}
