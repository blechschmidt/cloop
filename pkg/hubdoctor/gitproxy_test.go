package hubdoctor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// gitProxyTLS writes a readable cert/key pair and returns their paths. The
// checks only stat them, so the contents do not have to be real TLS material.
func gitProxyTLS(t *testing.T) (cert, key string) {
	t.Helper()
	dir := t.TempDir()
	cert = filepath.Join(dir, "proxy.crt")
	key = filepath.Join(dir, "proxy.key")
	for _, p := range []string{cert, key} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	return cert, key
}

// hostOnlyConfig is a single-machine install: nothing clones, so nothing hands
// a credential to a sandbox.
func hostOnlyConfig() *config.Config {
	cfg := &config.Config{}
	yes := true
	cfg.Executors.AllowHostProcess = &yes
	return cfg
}

// cloningConfig has an executor that provisions a git workspace.
func cloningConfig() *config.Config {
	cfg := hostOnlyConfig()
	cfg.Executors.Kubernetes.Enabled = true
	return cfg
}

func TestGitProxyDisabledOnAHostOnlyHubIsAPass(t *testing.T) {
	got := findingsFor(t, t.TempDir(), hostOnlyConfig(), Options{Offline: true})
	f := only(t, got, "gitproxy.enabled")
	wantSeverity(t, f, SeverityPass)
	if !strings.Contains(f.Message, "no configured executor provisions a git workspace") {
		t.Fatalf("message does not explain why this is fine: %q", f.Message)
	}
}

// TestGitProxyDisabledWithCloningExecutorsWarns is the finding the check exists
// for: nothing is broken, nothing else reports, and a sandbox is holding a PAT.
func TestGitProxyDisabledWithCloningExecutorsWarns(t *testing.T) {
	got := findingsFor(t, t.TempDir(), cloningConfig(), Options{Offline: true})
	f := only(t, got, "gitproxy.enabled")
	wantSeverity(t, f, SeverityWarn)
	if !strings.Contains(f.Remediation, "executors.git_proxy.enabled: true") {
		t.Fatalf("remediation does not name the setting: %q", f.Remediation)
	}
}

func TestGitProxyEnabledAndWellConfiguredPasses(t *testing.T) {
	cert, key := gitProxyTLS(t)
	cfg := cloningConfig()
	cfg.Executors.GitProxy = config.GitProxyConfig{
		Enabled: true, CertFile: cert, KeyFile: key,
		AdvertiseURL: "https://hub.internal:8443",
	}
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	f := only(t, got, "gitproxy.enabled")
	wantSeverity(t, f, SeverityPass)
	if !strings.Contains(f.Message, "refs/heads/cloop/**") {
		t.Fatalf("the pass does not state the allowlist in force: %q", f.Message)
	}
	for _, unwanted := range []string{"gitproxy.tls", "gitproxy.advertise_url", "gitproxy.allowed_refs"} {
		if len(got[unwanted]) != 0 {
			t.Fatalf("a well-configured proxy still produced %s: %+v", unwanted, got[unwanted])
		}
	}
}

func TestGitProxyEnabledWithoutTLSMaterialFails(t *testing.T) {
	cfg := cloningConfig()
	cfg.Executors.GitProxy = config.GitProxyConfig{
		Enabled: true, AdvertiseURL: "https://hub.internal:8443",
	}
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	if len(got["gitproxy.tls"]) != 2 {
		t.Fatalf("want one finding per missing file, got %d", len(got["gitproxy.tls"]))
	}
	for _, f := range got["gitproxy.tls"] {
		wantSeverity(t, f, SeverityFail)
		// The consequence matters as much as the fault: an operator needs to
		// know this does not silently fall back to handing over the PAT.
		if !strings.Contains(f.Message, "git workspaces will be refused") {
			t.Fatalf("message does not state the consequence: %q", f.Message)
		}
	}
}

func TestGitProxyUnreadableTLSMaterialFails(t *testing.T) {
	cfg := cloningConfig()
	cfg.Executors.GitProxy = config.GitProxyConfig{
		Enabled:  true,
		CertFile: filepath.Join(t.TempDir(), "absent.crt"),
		KeyFile:  filepath.Join(t.TempDir(), "absent.key"),
	}
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	if len(got["gitproxy.tls"]) != 2 {
		t.Fatalf("want one finding per unreadable file, got %d", len(got["gitproxy.tls"]))
	}
}

// TestGitProxyLoopbackAdvertiseWarns covers the misconfiguration that works
// perfectly on the machine it was written on and nowhere a sandbox runs.
func TestGitProxyLoopbackAdvertiseWarns(t *testing.T) {
	cert, key := gitProxyTLS(t)
	for _, adv := range []string{
		"https://127.0.0.1:8443", "https://localhost:8443", "https://[::1]:8443",
	} {
		t.Run(adv, func(t *testing.T) {
			cfg := cloningConfig()
			cfg.Executors.GitProxy = config.GitProxyConfig{
				Enabled: true, CertFile: cert, KeyFile: key, AdvertiseURL: adv,
			}
			got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
			wantSeverity(t, only(t, got, "gitproxy.advertise_url"), SeverityWarn)
		})
	}
}

func TestGitProxyMissingAdvertiseWarns(t *testing.T) {
	cert, key := gitProxyTLS(t)
	cfg := cloningConfig()
	cfg.Executors.GitProxy = config.GitProxyConfig{Enabled: true, CertFile: cert, KeyFile: key}
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	wantSeverity(t, only(t, got, "gitproxy.advertise_url"), SeverityWarn)
}

func TestGitProxyWidenedAllowlistWarns(t *testing.T) {
	cert, key := gitProxyTLS(t)
	cfg := cloningConfig()
	cfg.Executors.GitProxy = config.GitProxyConfig{
		Enabled: true, CertFile: cert, KeyFile: key,
		AdvertiseURL: "https://hub.internal:8443",
		AllowedRefs:  []string{"refs/heads/cloop/**", "refs/heads/main"},
	}
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	f := only(t, got, "gitproxy.allowed_refs")
	wantSeverity(t, f, SeverityWarn)
	if !strings.Contains(f.Message, "refs/heads/main") {
		t.Fatalf("the warning does not name the widened pattern: %q", f.Message)
	}
	// The default alone must never warn, or the check is noise nobody reads.
	cfg.Executors.GitProxy.AllowedRefs = nil
	if got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true}); len(got["gitproxy.allowed_refs"]) != 0 {
		t.Fatalf("the default allowlist warned: %+v", got["gitproxy.allowed_refs"])
	}
}

func TestGitProxyAllowDeleteWarns(t *testing.T) {
	cert, key := gitProxyTLS(t)
	cfg := cloningConfig()
	cfg.Executors.GitProxy = config.GitProxyConfig{
		Enabled: true, CertFile: cert, KeyFile: key,
		AdvertiseURL: "https://hub.internal:8443", AllowDelete: true,
	}
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	wantSeverity(t, only(t, got, "gitproxy.allow_delete"), SeverityWarn)
}

// seedBranchGrants mints one github_app and one github_pat secret and grants
// each with a branch allowlist, plus an unrestricted grant that must not be
// counted, into dir's control plane.
func seedBranchGrants(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("CLOOP_SECRET_KEY", "hubdoctor-branch-grants")
	mustInitStateDB(t, dir)
	db, err := statedb.Open(filepath.Join(dir, ".cloop", "state.db"))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	defer db.Close()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatalf("secretstore.New: %v", err)
	}
	b, err := secretbroker.New(store)
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}
	ctx := context.Background()
	pat, err := b.Mint(ctx, secretbroker.MintRequest{Name: "pat", Kind: secretbroker.KindGitHubPAT,
		Payload: []byte("ghp_hubdoctorBranchGrantToken00000000")})
	if err != nil {
		t.Fatalf("mint pat: %v", err)
	}
	subject := secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/app"}
	for _, c := range []secretbroker.Constraints{
		{Repos: []string{"acme/api"}, Permissions: []string{"contents:write"}, Branches: []string{"cloop/*"}},
		{Repos: []string{"acme/api"}, Permissions: []string{"contents:write"}}, // no list: not counted
	} {
		if _, err := b.Grant(ctx, secretbroker.GrantRequest{SecretRef: pat.ID, Subject: subject,
			Constraints: c}); err != nil {
			t.Fatalf("grant: %v", err)
		}
	}
}

// TestBranchRestrictedGrantsWithoutAProxyWarn: a branch list the hub cannot
// enforce is delivered as something less than it says, and nothing else
// reports it.
func TestBranchRestrictedGrantsWithoutAProxyWarn(t *testing.T) {
	dir := t.TempDir()
	seedBranchGrants(t, dir)

	got := findingsFor(t, dir, hostOnlyConfig(), Options{Offline: true})
	f := only(t, got, "gitproxy.branch_grants")
	wantSeverity(t, f, SeverityWarn)
	if !strings.Contains(f.Message, "1 active grant(s)") || !strings.Contains(f.Message, "not delivered") {
		t.Errorf("message does not count the grant or say what happens to it: %q", f.Message)
	}
	if !strings.Contains(f.Remediation, "executors.git_proxy") {
		t.Errorf("remediation does not name the setting: %q", f.Remediation)
	}

	// With the proxy on, the lists are enforced and there is nothing to say.
	cert, key := gitProxyTLS(t)
	cfg := hostOnlyConfig()
	cfg.Executors.GitProxy = config.GitProxyConfig{Enabled: true, CertFile: cert, KeyFile: key,
		AdvertiseURL: "https://hub.internal:8443"}
	if fs := findingsFor(t, dir, cfg, Options{Offline: true})["gitproxy.branch_grants"]; len(fs) != 0 {
		t.Errorf("warned about branch lists the running proxy enforces: %+v", fs)
	}
}

func TestNoBranchRestrictedGrantsIsSilent(t *testing.T) {
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	if fs := findingsFor(t, dir, hostOnlyConfig(), Options{Offline: true})["gitproxy.branch_grants"]; len(fs) != 0 {
		t.Errorf("reported branch grants on a hub that has none: %+v", fs)
	}
}
