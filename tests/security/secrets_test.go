package security

// Guarantee 3: brokered credential material is never disclosed by the
// surfaces that describe it.
//
// A credential broker's whole value is that the credential exists in exactly
// two places — sealed at rest, and in the workload that was granted it. Every
// other surface (an audit record, a list API, an error message, a panic
// backtrace, the container command line) describes the credential without
// containing it. Those descriptive surfaces are where disclosure actually
// happens in practice, because each one is written by someone who is thinking
// about observability rather than about secrecy, and a leak there is
// permanent: audit logs are shipped off-box, error strings land in tickets.
//
// Scope, stated honestly. This asserts non-disclosure by *cloop's* surfaces.
// It cannot and does not assert that a workload never prints its own
// credential to stdout — the workload holds the plaintext by design, and no
// broker can stop it echoing. That is precisely why material is delivered as
// files and named environment variables rather than as argv, which is asserted
// in TestContainerSecretsNeverEnterArgv.
//
// Encoded forms are checked as well as raw. A leak that survives one
// base64 round-trip is still a leak, and it is the form a credential most
// often takes on the way into a log line (JSON body, HTTP basic auth header,
// a URL query parameter).

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// ---------------------------------------------------------------------------
// Leak detection
// ---------------------------------------------------------------------------

// encodingsOf returns the representations a secret might take on its way into
// a log, keyed by a name that makes a failure legible.
//
// Short encodings are skipped: hex of a 40-character token is 80 characters
// and unmistakable, but a 4-character secret's hex form would collide with
// ordinary text and produce false positives that erode trust in the check.
func encodingsOf(secret string) map[string]string {
	if len(secret) < 8 {
		return map[string]string{"raw": secret}
	}
	out := map[string]string{
		"raw":              secret,
		"base64-std":       base64.StdEncoding.EncodeToString([]byte(secret)),
		"base64-url":       base64.URLEncoding.EncodeToString([]byte(secret)),
		"base64-raw-std":   base64.RawStdEncoding.EncodeToString([]byte(secret)),
		"hex":              hex.EncodeToString([]byte(secret)),
		"url-query-escape": url.QueryEscape(secret),
		"url-path-escape":  url.PathEscape(secret),
	}
	// A JSON-encoded string differs from raw only when the secret contains
	// characters needing escapes; include it only then, so the map does not
	// carry a duplicate of "raw" under another name.
	if b, err := json.Marshal(secret); err == nil {
		if s := strings.Trim(string(b), `"`); s != secret {
			out["json-escaped"] = s
		}
	}
	// url.QueryEscape and PathEscape are frequently identical to raw for
	// token charsets; drop the duplicates for the same reason.
	for k, v := range out {
		if k != "raw" && v == secret {
			delete(out, k)
		}
	}
	return out
}

// assertNoSecretLeak fails if haystack contains secret in any encoding.
func assertNoSecretLeak(t *testing.T, haystack, secret, sink string) {
	t.Helper()
	if secret == "" {
		t.Fatal("assertNoSecretLeak called with an empty secret — the check would be vacuous")
	}
	for encoding, needle := range encodingsOf(secret) {
		if strings.Contains(haystack, needle) {
			t.Errorf("%s discloses the credential (%s form).\n"+
				"  needle: %s\n  sink content: %s",
				sink, encoding, preview(needle), preview(haystack))
		}
	}
}

func preview(s string) string {
	const max = 400
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// TestLeakDetectorCatchesEncodedForms is the meta-test: a detector that only
// finds the raw string would pass every test below while base64-encoded
// credentials streamed past it.
func TestLeakDetectorCatchesEncodedForms(t *testing.T) {
	const secret = "ghp_averyRealLookingPersonalAccessToken01"
	for name, encoded := range encodingsOf(secret) {
		t.Run(name, func(t *testing.T) {
			inner := &testing.T{}
			// Wrap in surrounding text: real leaks are embedded, not standalone.
			assertNoSecretLeakInto(inner, "prefix "+encoded+" suffix", secret)
			if !inner.Failed() {
				t.Errorf("detector missed the %s encoding of the secret", name)
			}
		})
	}
	// And it must not fire on unrelated text, or every test becomes noise.
	inner := &testing.T{}
	assertNoSecretLeakInto(inner, "this log line mentions no credential at all", secret)
	if inner.Failed() {
		t.Error("detector reported a leak in text that contains no credential")
	}
}

// assertNoSecretLeakInto is assertNoSecretLeak against an arbitrary *testing.T,
// used by the meta-test to observe failures without failing the real test.
func assertNoSecretLeakInto(t *testing.T, haystack, secret string) {
	for _, needle := range encodingsOf(secret) {
		if strings.Contains(haystack, needle) {
			t.Errorf("leak")
		}
	}
}

// ---------------------------------------------------------------------------
// In-memory Store
// ---------------------------------------------------------------------------

// memStore is a minimal secretbroker.Store. pkg/secretbroker has one too, but
// it lives in a _test.go file and so cannot be imported; reimplementing it
// here is the price of auditing the package from outside, and is worth paying
// because an external test can only reach the exported surface — the same
// surface an embedder and an attacker see.
type memStore struct {
	mu      sync.Mutex
	secrets map[string]secretbroker.Secret
	grants  map[string]secretbroker.Grant
	meta    map[string]string
}

func newMemStore() *memStore {
	return &memStore{
		secrets: map[string]secretbroker.Secret{},
		grants:  map[string]secretbroker.Grant{},
		meta:    map[string]string{},
	}
}

func (m *memStore) PutSecret(s secretbroker.Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[s.ID] = s
	return nil
}

func (m *memStore) GetSecret(id string) (secretbroker.Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.secrets[id]
	if !ok {
		return secretbroker.Secret{}, fmt.Errorf("%w: %s", secretbroker.ErrSecretNotFound, id)
	}
	return s, nil
}

func (m *memStore) ListSecrets() ([]secretbroker.Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]secretbroker.Secret, 0, len(m.secrets))
	for _, s := range m.secrets {
		out = append(out, s)
	}
	return out, nil
}

func (m *memStore) DeleteSecret(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.secrets[id]; !ok {
		return fmt.Errorf("%w: %s", secretbroker.ErrSecretNotFound, id)
	}
	delete(m.secrets, id)
	return nil
}

func (m *memStore) PutGrant(g secretbroker.Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.grants[g.ID] = g
	return nil
}

func (m *memStore) GetGrant(id string) (secretbroker.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	if !ok {
		return secretbroker.Grant{}, fmt.Errorf("%w: %s", secretbroker.ErrGrantNotFound, id)
	}
	return g, nil
}

func (m *memStore) ListGrants() ([]secretbroker.Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]secretbroker.Grant, 0, len(m.grants))
	for _, g := range m.grants {
		out = append(out, g)
	}
	return out, nil
}

func (m *memStore) RevokeGrant(id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	if !ok {
		return fmt.Errorf("%w: %s", secretbroker.ErrGrantNotFound, id)
	}
	if g.RevokedAt.IsZero() {
		g.RevokedAt = at
		m.grants[id] = g
	}
	return nil
}

func (m *memStore) Meta(key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.meta[key]
	return v, ok, nil
}

func (m *memStore) SetMeta(key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.meta[key] = value
	return nil
}

// recordingAuditor captures every audit event the broker emits, which is the
// most dangerous sink in the system: audit logs are long-lived, widely read,
// and routinely shipped off the box.
type recordingAuditor struct {
	mu     sync.Mutex
	events []secretbroker.Event
}

func (a *recordingAuditor) Audit(ev secretbroker.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
}

func (a *recordingAuditor) dump(t *testing.T) string {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	var b strings.Builder
	for _, ev := range a.events {
		// Both the structured form (what a JSON sink writes) and the Go
		// rendering (what a text logger writes) are checked: a field with a
		// json:"-" tag is invisible to one and printed by the other.
		if j, err := json.Marshal(ev); err == nil {
			b.Write(j)
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "%+v\n", ev)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// The credential shapes under test
// ---------------------------------------------------------------------------

// credentialCase is one shape of brokered material. The table exists because
// each kind travels a different delivery path — a PAT becomes a git credential
// helper, a kubeconfig becomes a YAML file, an egress credential becomes a
// proxy URL — and a redaction rule that covers one may not cover another.
type credentialCase struct {
	name    string
	kind    secretbroker.Kind
	payload string
	// canary is the substring that must never surface. For structured
	// payloads it is the sensitive field rather than the whole document.
	canary      string
	constraints secretbroker.Constraints
}

func credentialCases() []credentialCase {
	return []credentialCase{
		{
			name:        "github classic PAT",
			kind:        secretbroker.KindGitHubPAT,
			payload:     "ghp_conformance0123456789abcdefghijklmnop",
			canary:      "ghp_conformance0123456789abcdefghijklmnop",
			constraints: secretbroker.Constraints{Repos: []string{"acme/*"}},
		},
		{
			name:        "github fine-grained PAT",
			kind:        secretbroker.KindGitHubPAT,
			payload:     "github_pat_11ABCDEFG0conformanceSuiteCanaryTokenValue",
			canary:      "github_pat_11ABCDEFG0conformanceSuiteCanaryTokenValue",
			constraints: secretbroker.Constraints{Repos: []string{"acme/widgets"}},
		},
		{
			name: "kubeconfig client certificate",
			kind: secretbroker.KindKubeconfig,
			payload: `apiVersion: v1
kind: Config
clusters:
- name: prod
  cluster:
    server: https://k8s.example.com
contexts:
- name: prod
  context:
    cluster: prod
    user: deployer
    namespace: apps
current-context: prod
users:
- name: deployer
  user:
    token: kubeCanary0123456789abcdefghijklmnopqrstuvwxyz
`,
			canary:      "kubeCanary0123456789abcdefghijklmnopqrstuvwxyz",
			constraints: secretbroker.Constraints{Namespaces: []string{"apps"}, Contexts: []string{"prod"}},
		},
		{
			name:        "registry credential",
			kind:        secretbroker.KindRegistry,
			payload:     `{"auths":{"registry.example.com":{"auth":"cmVnQ2FuYXJ5U2VjcmV0VmFsdWU="}}}`,
			canary:      "cmVnQ2FuYXJ5U2VjcmV0VmFsdWU=",
			constraints: secretbroker.Constraints{Registries: []string{"registry.example.com"}},
		},
		{
			name:        "environment secret",
			kind:        secretbroker.KindEnv,
			payload:     `{"ANTHROPIC_API_KEY":"sk-ant-conformanceCanary0123456789abcdef"}`,
			canary:      "sk-ant-conformanceCanary0123456789abcdef",
			constraints: secretbroker.Constraints{EnvKeys: []string{"ANTHROPIC_API_KEY"}},
		},
	}
}

// newBroker builds a broker over a fresh in-memory store, with an auditor
// capturing everything it emits.
func newBroker(t *testing.T) (*secretbroker.Broker, *memStore, *recordingAuditor) {
	t.Helper()
	// The broker refuses to construct without a sealing passphrase, which is
	// itself a guarantee worth having: there is no "unencrypted fallback"
	// mode that a misconfigured deployment could land in.
	t.Setenv(secretbroker.EnvPassphraseKey, "conformance-suite-passphrase")
	store := newMemStore()
	auditor := &recordingAuditor{}
	b, err := secretbroker.New(store, secretbroker.WithAuditor(auditor))
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}
	return b, store, auditor
}

// TestBrokeredMaterialIsNeverDisclosed is the table-driven sweep. For each
// credential shape it runs the full mint → grant → lease lifecycle and then
// checks every surface that describes the credential.
func TestBrokeredMaterialIsNeverDisclosed(t *testing.T) {
	ctx := context.Background()

	for _, tc := range credentialCases() {
		t.Run(tc.name, func(t *testing.T) {
			broker, store, auditor := newBroker(t)

			// Mint takes ownership of the payload slice and zeroes it, so the
			// canary must be captured before the call.
			secret, err := broker.Mint(ctx, secretbroker.MintRequest{
				Name:    "conformance-secret",
				Kind:    tc.kind,
				Payload: []byte(tc.payload),
				Actor:   "conformance-suite",
			})
			if err != nil {
				t.Fatalf("Mint: %v", err)
			}

			grant, err := broker.Grant(ctx, secretbroker.GrantRequest{
				SecretRef:   secret.ID,
				Subject:     secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: "edge-01"},
				Constraints: tc.constraints,
				TTL:         time.Hour,
				Actor:       "conformance-suite",
			})
			if err != nil {
				t.Fatalf("Grant: %v", err)
			}

			lease, err := broker.Lease(ctx, "edge-01", "/srv/project")
			if err != nil {
				t.Fatalf("Lease: %v", err)
			}
			defer broker.Release(lease.ID)

			// --- Surface 1: the stored record ---------------------------
			// At rest the payload must be sealed, not merely tagged
			// json:"-". A json tag hides it from one encoder; it does
			// nothing about the bytes on disk.
			stored, err := store.GetSecret(secret.ID)
			if err != nil {
				t.Fatalf("GetSecret: %v", err)
			}
			assertNoSecretLeak(t, string(stored.Sealed), tc.canary, "the sealed payload at rest")

			// --- Surface 2: JSON serialization --------------------------
			// This is the /api response shape: the UI's secrets and grants
			// panels marshal exactly these types.
			for name, v := range map[string]any{
				"Secret JSON (GET /api/secrets)": secret,
				"Grant JSON (GET /api/grants)":   grant,
				"Lease JSON":                     lease,
				"stored Secret JSON":             stored,
			} {
				blob, err := json.Marshal(v)
				if err != nil {
					t.Fatalf("marshal %s: %v", name, err)
				}
				assertNoSecretLeak(t, string(blob), tc.canary, name)
			}

			// --- Surface 3: Go-syntax rendering -------------------------
			// A text logger writing %+v sees fields a JSON encoder skips.
			// This is how json:"-" gives false confidence.
			assertNoSecretLeak(t, fmt.Sprintf("%+v", secret), tc.canary, "Secret rendered with %+v")
			assertNoSecretLeak(t, fmt.Sprintf("%+v", grant), tc.canary, "Grant rendered with %+v")

			// --- Surface 4: audit records -------------------------------
			assertNoSecretLeak(t, auditor.dump(t), tc.canary, "the audit event stream")

			// --- Surface 5: list APIs -----------------------------------
			secrets, err := broker.ListSecrets()
			if err != nil {
				t.Fatalf("ListSecrets: %v", err)
			}
			blob, _ := json.Marshal(secrets)
			assertNoSecretLeak(t, string(blob), tc.canary, "ListSecrets response")

			grants, err := broker.ListGrants(secretbroker.GrantFilter{})
			if err != nil {
				t.Fatalf("ListGrants: %v", err)
			}
			blob, _ = json.Marshal(grants)
			assertNoSecretLeak(t, string(blob), tc.canary, "ListGrants response")

			// --- Surface 6: the lease's own description -----------------
			// Materials carry plaintext in Env/Files by design. Their
			// *description* — what a UI renders, what an audit row records —
			// must not.
			for _, m := range lease.Materials {
				blob, err := json.Marshal(m)
				if err != nil {
					t.Fatalf("marshal Material: %v", err)
				}
				assertNoSecretLeak(t, string(blob), tc.canary, "Material JSON")
				assertNoSecretLeak(t, m.Summary, tc.canary, "Material.Summary")
			}
		})
	}
}

// TestBrokerErrorsDoNotEchoCredentials covers the sink that leaks most often
// in practice. An error message is written by someone debugging, gets wrapped
// three times, and ends up in a ticket, a Sentry event, and an HTTP response
// body — all before anyone notices it interpolated the payload.
func TestBrokerErrorsDoNotEchoCredentials(t *testing.T) {
	ctx := context.Background()

	for _, tc := range credentialCases() {
		t.Run(tc.name, func(t *testing.T) {
			broker, _, auditor := newBroker(t)
			canary := tc.canary

			// Drive a series of failures, each with the credential in play.
			var errs []string
			collect := func(err error) {
				if err != nil {
					errs = append(errs, err.Error())
				}
			}

			// An invalid name, with the payload present.
			_, err := broker.Mint(ctx, secretbroker.MintRequest{
				Name: "not a valid name!!", Kind: tc.kind,
				Payload: []byte(tc.payload), Actor: "suite",
			})
			collect(err)

			// An unknown kind, with the payload present.
			_, err = broker.Mint(ctx, secretbroker.MintRequest{
				Name: "conformance", Kind: secretbroker.Kind("nonsense"),
				Payload: []byte(tc.payload), Actor: "suite",
			})
			collect(err)

			// A grant against a secret that does not exist.
			_, err = broker.Grant(ctx, secretbroker.GrantRequest{
				SecretRef: canary, // operator pastes the token instead of the ID
				Subject:   secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: "edge-01"},
				TTL:       time.Hour, Actor: "suite",
			})
			collect(err)

			// A lease for a requester with no grants.
			_, err = broker.Lease(ctx, "unknown-executor", "/srv/nope")
			collect(err)

			if len(errs) == 0 {
				t.Fatal("no errors were produced — this test would pass vacuously")
			}
			assertNoSecretLeak(t, strings.Join(errs, "\n"), canary, "broker error strings")
			assertNoSecretLeak(t, auditor.dump(t), canary, "audit events for failed operations")
		})
	}
}

// TestRedactStringRemovesKnownCredentialShapes pins the redactor's contract
// for each shape the broker deals in.
func TestRedactStringRemovesKnownCredentialShapes(t *testing.T) {
	for _, tc := range []struct{ name, in, mustNotContain string }{
		{"classic PAT", "failed to auth with ghp_abcdefghij0123456789 when cloning", "ghp_abcdefghij0123456789"},
		{"fine-grained PAT", "token github_pat_11ABC_secretbody rejected", "github_pat_11ABC_secretbody"},
		{"anthropic key", "key sk-ant-api03-abcdef was refused", "sk-ant-api03-abcdef"},
		{"aws access key", "using AKIAIOSFODNN7EXAMPLE for s3", "AKIAIOSFODNN7EXAMPLE"},
		{"slack bot token", "posting with xoxb-1234-5678-abcdef failed", "xoxb-1234-5678-abcdef"},
		{"jwt", "bearer eyJhbGciOiJIUzI1NiJ9.body.sig expired", "eyJhbGciOiJIUzI1NiJ9.body.sig"},
		{"pem block", "parsing -----BEGIN RSA PRIVATE KEY----- failed", "-----BEGIN RSA PRIVATE KEY-----"},
		{"url userinfo", "proxy https://user:hunter2@proxy.example.com/ unreachable", "hunter2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := secretbroker.RedactString(tc.in)
			if strings.Contains(got, tc.mustNotContain) {
				t.Errorf("RedactString did not remove the credential.\n in: %s\nout: %s", tc.in, got)
			}
		})
	}
}

// FuzzRedactStringNeverEmitsACredentialBody fuzzes the redactor with arbitrary
// surrounding text.
//
// The property under test is narrow on purpose: whatever the surrounding
// noise, a credential body that follows a known prefix and is terminated by a
// delimiter must not survive. Fuzzing matters here because redactPrefixed is a
// hand-rolled scanner over attacker-influenced text — error strings from
// remote services — and its loop has exactly the shape (index, slice, repeat)
// where an off-by-one silently emits the tail it meant to drop.
func FuzzRedactStringNeverEmitsACredentialBody(f *testing.F) {
	seeds := []string{
		"",
		"no credentials here",
		"ghp_bodybodybody ",
		"prefix ghp_secret, suffix",
		"a ghp_one b ghp_two c",
		"https://user:pw@host/path",
		"nested https://a:b@h ghp_x sk-ant-y\n",
		"ghp_unterminated",
		"\x00ghp_nul\x00 ",
		strings.Repeat("ghp_x ", 50),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, noise string) {
		const body = "CANARYBODY0123456789"
		// Build an input where the credential is unambiguously terminated,
		// which is the case the redactor promises to handle.
		in := noise + " ghp_" + body + " " + noise
		out := secretbroker.RedactString(in)
		if strings.Contains(out, body) {
			t.Fatalf("credential body survived redaction.\n in: %q\nout: %q", in, out)
		}
		// Redaction must also terminate and not grow without bound; an
		// scanner bug that re-emits its input would show up as blowup.
		if len(out) > 4*len(in)+64 {
			t.Fatalf("redaction grew the string from %d to %d bytes", len(in), len(out))
		}
	})
}

// TestRedactEventScrubsTheReasonField covers the structured path: the broker
// stamps denial reasons into Event.Reason, and those reasons are built from
// wrapped errors that may have travelled through a remote service.
func TestRedactEventScrubsTheReasonField(t *testing.T) {
	const canary = "ghp_reasonFieldCanary0123456789"
	ev := secretbroker.Event{
		Action: secretbroker.ActionLease,
		Reason: "upstream rejected credential " + canary + " with 401",
	}
	got := secretbroker.Redact(ev)
	blob, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	assertNoSecretLeak(t, string(blob), canary, "Redact(Event) output")
	assertNoSecretLeak(t, fmt.Sprintf("%+v", got), canary, "Redact(Event) rendered with %+v")
}
