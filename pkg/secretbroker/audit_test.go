package secretbroker

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestRedactStringScrubsCredentials covers the token formats most likely to
// end up spliced into an error message by a well-meaning fmt.Errorf three
// packages down.
func TestRedactStringScrubsCredentials(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		secret string
	}{
		{"github classic pat", `failed for ghp_abcdefghijklmnop1234, retrying`, "ghp_abcdefghijklmnop1234"},
		{"github app token", `token ghs_zzzzzzzzzzzzzzzzzzzz expired`, "ghs_zzzzzzzzzzzzzzzzzzzz"},
		{"github fine grained", `bad github_pat_11ABCDEFG0abcdefghij here`, "github_pat_11ABCDEFG0abcdefghij"},
		{"github oauth", `gho_0123456789abcdef rejected`, "gho_0123456789abcdef"},
		{"anthropic", `key sk-ant-api03-abcdef123456 invalid`, "sk-ant-api03-abcdef123456"},
		{"openai project", `sk-proj-abcdefghijklmnop failed`, "sk-proj-abcdefghijklmnop"},
		{"openai legacy", `sk-abcdefghijklmnopqrst bad`, "sk-abcdefghijklmnopqrst"},
		{"aws access key", `AKIAIOSFODNN7EXAMPLE denied`, "AKIAIOSFODNN7EXAMPLE"},
		{"google", `AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz01234 nope`, "AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz01234"},
		{"slack bot", `xoxb-123456-abcdef rejected`, "xoxb-123456-abcdef"},
		{"jwt", `bearer eyJhbGciOiJIUzI1NiJ9.payload.sig failed`, "eyJhbGciOiJIUzI1NiJ9"},
		{"private key header", `-----BEGIN RSA PRIVATE KEY----- oops`, "BEGIN RSA PRIVATE KEY"},
		// Quoted and punctuated contexts, because that is how errors are
		// actually formatted.
		{"quoted", `bad token "ghp_abcdefghijklmnop1234" seen`, "ghp_abcdefghijklmnop1234"},
		{"trailing comma", `tokens: ghp_abcdefghijklmnop1234, ghs_zzzzzzzzzzzzzzzzzzzz`, "ghp_abcdefghijklmnop1234"},
		{"parenthesised", `(ghp_abcdefghijklmnop1234)`, "ghp_abcdefghijklmnop1234"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactString(tc.in)
			if strings.Contains(got, tc.secret) {
				t.Errorf("RedactString(%q) = %q — still contains %q", tc.in, got, tc.secret)
			}
			if !strings.Contains(got, redactionMarker) {
				t.Errorf("RedactString(%q) = %q — no redaction marker", tc.in, got)
			}
		})
	}
}

// TestRedactStringScrubsURLCredentials: an egress_proxy payload is a URL
// with credentials in the authority, which is exactly the shape that would
// leak through a "could not connect to %s" error.
func TestRedactStringScrubsURLCredentials(t *testing.T) {
	tests := []struct {
		in       string
		mustHide []string
		mustKeep string
	}{
		{
			in:       "dial https://proxyuser:hunter2@proxy.example.com:8080/ failed",
			mustHide: []string{"hunter2", "proxyuser"},
			mustKeep: "proxy.example.com",
		},
		{
			in:       "http://admin:s3cr3t@10.0.0.1/path",
			mustHide: []string{"s3cr3t", "admin"},
			mustKeep: "10.0.0.1",
		},
		{
			// No credentials: the URL must survive intact, or the audit log
			// becomes useless for diagnosing anything.
			in:       "dial https://proxy.example.com:8080/ failed",
			mustHide: nil,
			mustKeep: "https://proxy.example.com:8080/",
		},
	}

	for _, tc := range tests {
		got := RedactString(tc.in)
		for _, hidden := range tc.mustHide {
			if strings.Contains(got, hidden) {
				t.Errorf("RedactString(%q) = %q — still contains %q", tc.in, got, hidden)
			}
		}
		if !strings.Contains(got, tc.mustKeep) {
			t.Errorf("RedactString(%q) = %q — lost the diagnostic part %q", tc.in, got, tc.mustKeep)
		}
	}
}

// TestRedactStringPreservesOrdinaryText: over-eager redaction would make the
// audit log unreadable, so ordinary reasons must pass through untouched.
func TestRedactStringPreservesOrdinaryText(t *testing.T) {
	for _, s := range []string{
		"grant expired at 2026-03-01T12:00:00Z",
		"repository org/tool is not in the grant's repository allowlist (org/*)",
		"issued 2 material(s): deploy-pat,prod-kube",
		"",
	} {
		if got := RedactString(s); got != s {
			t.Errorf("RedactString(%q) = %q — must be unchanged", s, got)
		}
	}
}

// TestRedactEventScrubsReason proves Redact reaches the field that carries
// free text.
func TestRedactEventScrubsReason(t *testing.T) {
	ev := Redact(Event{
		Action:   ActionLease,
		Decision: DecisionDeny,
		Reason:   "upstream rejected ghp_abcdefghijklmnop1234 for org/tool",
	})
	if strings.Contains(ev.Reason, "ghp_abcdefghijklmnop1234") {
		t.Fatalf("Redact left the token in Reason: %q", ev.Reason)
	}
	if !strings.Contains(ev.Reason, "org/tool") {
		t.Errorf("Redact destroyed the diagnostic context: %q", ev.Reason)
	}
}

// TestAuditedEventsNeverContainPayloads is the end-to-end version: run a
// full mint→grant→lease→revoke→lease cycle with recognisable credentials and
// assert none of them appears in any recorded event, in any field.
func TestAuditedEventsNeverContainPayloads(t *testing.T) {
	b, _, auditor, _ := newTestBroker(t)
	ctx := context.Background()

	const (
		patToken  = "ghp_auditleakcanary01234"
		envValue  = "envleakcanary56789"
		proxyURL  = "https://puser:proxyleakcanary@proxy.example.com:8080"
		kubeToken = "kubeleakcanary01234"
	)

	pat := mintGitHub(t, b, "pat", patToken)
	grantTo(t, b, pat.ID, "project:/srv/app", Constraints{Repos: []string{"org/*"}}, time.Hour)

	envSec, err := b.Mint(ctx, MintRequest{
		Name: "envsec", Kind: KindEnv,
		Payload: []byte(`{"CANARY":"` + envValue + `"}`), Actor: "test",
	})
	if err != nil {
		t.Fatalf("mint env: %v", err)
	}
	grantTo(t, b, envSec.ID, "project:/srv/app", Constraints{EnvKeys: []string{"CANARY"}}, time.Hour)

	proxySec, err := b.Mint(ctx, MintRequest{
		Name: "proxy", Kind: KindEgressProxy, Payload: []byte(proxyURL), Actor: "test",
	})
	if err != nil {
		t.Fatalf("mint proxy: %v", err)
	}
	grantTo(t, b, proxySec.ID, "project:/srv/app",
		Constraints{Hosts: []string{"*.example.com"}}, time.Hour)

	kubeSec, err := b.Mint(ctx, MintRequest{
		Name: "kube", Kind: KindKubeconfig, Payload: []byte(testKubeconfig(kubeToken)), Actor: "test",
	})
	if err != nil {
		t.Fatalf("mint kube: %v", err)
	}
	kubeGrant := grantTo(t, b, kubeSec.ID, "project:/srv/app",
		Constraints{Contexts: []string{"prod"}, Namespaces: []string{"team-a"}}, time.Hour)

	lease, err := b.Lease(ctx, "e1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if len(lease.Materials) != 4 {
		t.Fatalf("got %d materials, want 4: %v", len(lease.Materials), lease.SecretNames())
	}

	if err := b.Revoke(ctx, kubeGrant.ID, "test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := b.Lease(ctx, "e1", "/srv/app"); err != nil {
		t.Fatalf("second lease: %v", err)
	}
	b.Release(lease.ID)

	canaries := []string{patToken, envValue, "proxyleakcanary", kubeToken}
	events := auditor.all()
	if len(events) == 0 {
		t.Fatal("no audit events recorded — the trail is the deliverable")
	}
	for _, ev := range events {
		// Fields() renders every field, so scanning it covers any field
		// added later without this test needing an update.
		rendered := ev.Fields()
		for _, canary := range canaries {
			if strings.Contains(rendered, canary) {
				t.Errorf("audit event %s/%s leaked %q: %s",
					ev.Action, ev.Decision, canary, rendered)
			}
		}
	}
}

// TestAuditCoversEveryOperation: the task's requirement is that mint, lease,
// renew, revoke, and denial all reach the log. A silent operation is an
// operation nobody can review.
func TestAuditCoversEveryOperation(t *testing.T) {
	b, _, auditor, clock := newTestBroker(t)
	ctx := context.Background()

	s := mintGitHub(t, b, "tok", "ghp_abcdefghij")
	g := grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"org/*"}}, time.Hour)

	lease, err := b.Lease(ctx, "e1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if _, err := b.Renew(ctx, lease.ID); err != nil {
		t.Fatalf("renew: %v", err)
	}
	if err := b.Revoke(ctx, g.ID, "test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// Produce a denial.
	clock.advance(time.Minute)
	if _, err := b.Lease(ctx, "e1", "/srv/app"); err != nil {
		t.Fatalf("lease after revoke: %v", err)
	}

	for _, action := range []Action{ActionMint, ActionGrant, ActionLease, ActionRenew, ActionRevoke} {
		if len(auditor.byAction(action)) == 0 {
			t.Errorf("no audit event recorded for %s", action)
		}
	}

	var denials int
	for _, ev := range auditor.all() {
		if ev.Decision == DecisionDeny {
			denials++
			if ev.Reason == "" {
				t.Errorf("denial %s has no reason", ev.Action)
			}
		}
	}
	if denials == 0 {
		t.Error("expected at least one audited denial")
	}
}

// TestAuditEventsCarryIdentity: an audit row without the subject and secret
// ID cannot answer the question it exists for.
func TestAuditEventsCarryIdentity(t *testing.T) {
	b, _, auditor, _ := newTestBroker(t)
	s := mintGitHub(t, b, "identified", "ghp_abcdefghij")
	grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"org/*"}}, time.Hour)

	if _, err := b.Lease(context.Background(), "edge-01", "/srv/app"); err != nil {
		t.Fatalf("lease: %v", err)
	}

	var checked bool
	for _, ev := range auditor.byAction(ActionLease) {
		if ev.SecretID == "" {
			continue // the per-lease summary row carries no single secret
		}
		checked = true
		if ev.Subject != "project:/srv/app" {
			t.Errorf("event subject = %q, want project:/srv/app", ev.Subject)
		}
		if ev.SecretName != "identified" {
			t.Errorf("event secret name = %q", ev.SecretName)
		}
		if ev.ExecutorID != "edge-01" {
			t.Errorf("event executor = %q", ev.ExecutorID)
		}
		if ev.Constraints == "" || ev.Constraints == "none" {
			t.Errorf("event constraints = %q, want the allowlist summary", ev.Constraints)
		}
	}
	if !checked {
		t.Fatal("no per-grant lease event was recorded")
	}
}

// testKubeconfig builds a two-context kubeconfig whose staging user holds
// the given token, used to check it does not survive minimization.
func testKubeconfig(token string) string {
	return `apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod-cluster
  cluster:
    server: https://prod.example.com
- name: staging-cluster
  cluster:
    server: https://staging.example.com
contexts:
- name: prod
  context:
    cluster: prod-cluster
    user: prod-user
    namespace: default
- name: staging
  context:
    cluster: staging-cluster
    user: staging-user
    namespace: staging
users:
- name: prod-user
  user:
    token: prod-token-value
- name: staging-user
  user:
    token: ` + token + `
`
}
