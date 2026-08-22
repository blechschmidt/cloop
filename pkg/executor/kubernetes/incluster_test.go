package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeSA lays down a fake projected ServiceAccount directory.
func writeSA(t *testing.T, token, ca, namespace string) string {
	t.Helper()
	dir := t.TempDir()
	if token != "" {
		if err := os.WriteFile(filepath.Join(dir, saTokenFile), []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if ca != "" {
		if err := os.WriteFile(filepath.Join(dir, saCAFile), []byte(ca), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if namespace != "" {
		if err := os.WriteFile(filepath.Join(dir, saNamespaceFile), []byte(namespace), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// fakeToken builds an unsigned JWT with the given exp. Unsigned on purpose:
// the source must never verify it, and a test that supplied a valid signature
// would hide a regression that started requiring one.
func fakeToken(exp time.Time) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload, _ := json.Marshal(map[string]any{"exp": exp.Unix(), "sub": "system:serviceaccount:cloop:hub"})
	return hdr + "." + base64.RawURLEncoding.EncodeToString(payload) + ".not-a-signature"
}

func TestInClusterSource_LoadsProjectedCredential(t *testing.T) {
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	dir := writeSA(t, fakeToken(exp), "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n", "cloop")

	s := &InClusterSource{Dir: dir, Host: "10.96.0.1", Port: "443"}
	creds, err := s.Acquire(context.Background(), "proj")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	if got, want := creds.Rest.Server, "https://10.96.0.1:443"; got != want {
		t.Errorf("Server = %q, want %q", got, want)
	}
	if !strings.HasPrefix(creds.Rest.BearerToken, "eyJ") && creds.Rest.BearerToken == "" {
		t.Error("BearerToken is empty")
	}
	if len(creds.Rest.CAData) == 0 {
		t.Error("CAData is empty; the projected cluster CA was not loaded")
	}
	if got, want := creds.Rest.Namespace, "cloop"; got != want {
		t.Errorf("Namespace = %q, want %q", got, want)
	}
	if !creds.ExpiresAt.Equal(exp) {
		t.Errorf("ExpiresAt = %v, want the token's exp %v", creds.ExpiresAt, exp)
	}
	// A broker lease ID would make Release() try to release something that
	// does not exist.
	if creds.LeaseID != "" {
		t.Errorf("LeaseID = %q, want empty: there is no broker lease behind a ServiceAccount", creds.LeaseID)
	}
}

// The kubelet rotates projected tokens under a running Pod. A source that
// cached the first read works for exactly one rotation period and then fails
// every API call, so Renew must go back to the file.
func TestInClusterSource_RenewRereadsRotatedToken(t *testing.T) {
	dir := writeSA(t, fakeToken(time.Now().Add(time.Hour)), "", "cloop")
	s := &InClusterSource{Dir: dir, Host: "10.96.0.1", Port: "443"}

	first, err := s.Acquire(context.Background(), "proj")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	rotated := fakeToken(time.Now().Add(2 * time.Hour))
	if err := os.WriteFile(filepath.Join(dir, saTokenFile), []byte(rotated), 0o600); err != nil {
		t.Fatal(err)
	}

	second, err := s.Renew(context.Background(), first.LeaseID)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if second.Rest.BearerToken == first.Rest.BearerToken {
		t.Error("Renew returned the original token; a kubelet rotation would go unnoticed")
	}
	if second.Rest.BearerToken != rotated {
		t.Errorf("Renew did not return the rotated token")
	}
}

// A token with no parsable exp must still schedule a re-read. Returning a
// zero time would make renewInterval fall back to its maximum, and returning
// something far future would stop rotation being picked up at all.
func TestInClusterSource_ExpiryFallsBackWhenTokenIsOpaque(t *testing.T) {
	dir := writeSA(t, "not-a-jwt", "", "cloop")
	s := &InClusterSource{Dir: dir, Host: "h", Port: "443"}

	creds, err := s.Acquire(context.Background(), "proj")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	d := time.Until(creds.ExpiresAt)
	if d <= 0 || d > fallbackTokenTTL+time.Minute {
		t.Errorf("ExpiresAt is %v away, want roughly %v", d, fallbackTokenTTL)
	}
}

// An already-expired exp is a rotation that has happened; honouring it would
// schedule a renewal in the past.
func TestInClusterSource_ExpiredTokenFallsForward(t *testing.T) {
	dir := writeSA(t, fakeToken(time.Now().Add(-time.Hour)), "", "cloop")
	s := &InClusterSource{Dir: dir, Host: "h", Port: "443"}

	creds, err := s.Acquire(context.Background(), "proj")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if !creds.ExpiresAt.After(time.Now()) {
		t.Errorf("ExpiresAt = %v is in the past; the renew loop would spin", creds.ExpiresAt)
	}
}

// Configured namespace beats the projected one: the executor's namespace is
// where the operator said workloads go, and the projected one is only where
// the hub itself happens to run.
func TestInClusterSource_NamespaceOverrideWins(t *testing.T) {
	dir := writeSA(t, fakeToken(time.Now().Add(time.Hour)), "", "hub-namespace")
	s := &InClusterSource{Dir: dir, Host: "h", Port: "443", Namespace: "cloop-workloads"}

	creds, err := s.Acquire(context.Background(), "proj")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if creds.Namespace != "cloop-workloads" {
		t.Errorf("Namespace = %q, want the configured cloop-workloads", creds.Namespace)
	}
}

// Not running in a Pod must be a refusal, not a fallback. Silently reaching
// for some other credential would make "which identity ran this workload" a
// question the audit trail cannot answer.
func TestNewInClusterSource_RefusesOutsideACluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	if _, err := NewInClusterSource(""); !errors.Is(err, ErrNotInCluster) {
		t.Fatalf("NewInClusterSource err = %v, want ErrNotInCluster", err)
	}
}

func TestNewInClusterSource_RefusesWithoutAProjectedToken(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")

	// Env says "in a Pod", but automountServiceAccountToken was turned off.
	s := &InClusterSource{Dir: t.TempDir()}
	err := s.check()
	if !errors.Is(err, ErrNotInCluster) {
		t.Fatalf("check err = %v, want ErrNotInCluster", err)
	}
	if !strings.Contains(err.Error(), "automountServiceAccountToken") {
		t.Errorf("error does not name the setting to fix: %v", err)
	}
}

func TestInClusterSource_EmptyTokenIsAnError(t *testing.T) {
	dir := writeSA(t, "   \n", "", "cloop")
	s := &InClusterSource{Dir: dir, Host: "h", Port: "443"}

	if _, err := s.Acquire(context.Background(), "proj"); err == nil {
		t.Fatal("Acquire accepted an empty token")
	}
}

func TestInClusterSource_EndpointFallsBackToEnv(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "172.20.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "6443")
	dir := writeSA(t, fakeToken(time.Now().Add(time.Hour)), "", "cloop")

	s := &InClusterSource{Dir: dir}
	creds, err := s.Acquire(context.Background(), "proj")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if got, want := creds.Rest.Server, "https://172.20.0.1:6443"; got != want {
		t.Errorf("Server = %q, want %q", got, want)
	}
}

// Describe feeds diagnostics and the audit trail, so it must never carry the
// token.
func TestInClusterSource_DescribeOmitsTheToken(t *testing.T) {
	tok := fakeToken(time.Now().Add(time.Hour))
	dir := writeSA(t, tok, "", "cloop")
	s := &InClusterSource{Dir: dir, Host: "h", Port: "443"}

	d := s.Describe()
	if strings.Contains(d, tok) {
		t.Errorf("Describe leaked the bearer token: %q", d)
	}
	if !strings.Contains(d, "in-cluster") {
		t.Errorf("Describe = %q, want it to name the credential source", d)
	}
}

// Release must tolerate any input: the driver calls it with a lease ID this
// source never issued.
func TestInClusterSource_ReleaseIsSafe(t *testing.T) {
	s := &InClusterSource{Dir: t.TempDir()}
	s.Release("")
	s.Release("some-lease-that-never-existed")
}

func TestUnverifiedJWTExpiry(t *testing.T) {
	tests := []struct {
		name  string
		token string
		ok    bool
	}{
		{"well formed", fakeToken(time.Unix(1893456000, 0)), true},
		{"not a jwt", "opaque-token", false},
		{"two segments", "aaa.bbb", false},
		{"payload not base64", "aaa.!!!.ccc", false},
		{"payload not json", "aaa." + base64.RawURLEncoding.EncodeToString([]byte("nope")) + ".ccc", false},
		{"no exp claim", "aaa." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`)) + ".ccc", false},
		{"negative exp", "aaa." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":-5}`)) + ".ccc", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := unverifiedJWTExpiry(tc.token)
			if ok != tc.ok {
				t.Errorf("ok = %v, want %v", ok, tc.ok)
			}
		})
	}
}

// The source is a CredentialSource, which is what lets the driver use it in
// place of a broker.
var _ CredentialSource = (*InClusterSource)(nil)
