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
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// gitProxyTLS returns a real certificate and key for the proxy.
func gitProxyTLS(t *testing.T) (cert, key string) { return tlsPair(t, "proxy") }

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
	if !strings.Contains(f.Message, "no configured executor or enrolled device provisions a git workspace") {
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
	f := only(t, got, "gitproxy.tls")
	wantSeverity(t, f, SeverityFail)
	// The consequence matters as much as the fault: an operator needs to
	// know this does not silently fall back to handing over the PAT.
	if !strings.Contains(f.Message, "will not start") || !strings.Contains(f.Message, "refused") {
		t.Fatalf("message does not state the consequence: %q", f.Message)
	}
	// A proxy that does not start is not reported as one that works.
	if fs := got["gitproxy.enabled"]; len(fs) != 0 {
		t.Fatalf("a proxy that will not start was also passed: %+v", fs)
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
	wantSeverity(t, only(t, got, "gitproxy.tls"), SeverityFail)
}

// TestGitProxyMismatchedPairFails: two readable files that are not a pair.
// The check used to stat them, and passed; the proxy loads them with
// tlsconf.ServerConfig, refuses, and every git workspace is then refused
// (Task 20387).
func TestGitProxyMismatchedPairFails(t *testing.T) {
	cert, _ := tlsPair(t, "proxy")
	_, otherKey := tlsPair(t, "other")
	cfg := cloningConfig()
	cfg.Executors.GitProxy = config.GitProxyConfig{
		Enabled: true, CertFile: cert, KeyFile: otherKey,
		AdvertiseURL: "https://hub.internal:8443",
	}
	got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
	f := only(t, got, "gitproxy.tls")
	wantSeverity(t, f, SeverityFail)
	if !strings.Contains(f.Message, "private key does not match") {
		t.Errorf("want the loader's own refusal, got %q", f.Message)
	}
	if fs := got["gitproxy.enabled"]; len(fs) != 0 {
		t.Fatalf("a proxy that will not start was also passed: %+v", fs)
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
	mustInitStateDB(t, dir)
	seedBranchGrantsAt(t, filepath.Join(dir, ".cloop", "state.db"))
}

// seedBranchGrantsAt seeds the grants into the database at dbPath.
func seedBranchGrantsAt(t *testing.T, dbPath string) {
	t.Helper()
	t.Setenv("CLOOP_SECRET_KEY", "hubdoctor-branch-grants")
	db, err := statedb.Open(dbPath)
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

// TestGitProxyLoopbackJudgedByTheHubsRule: whether the advertised base names
// this machine only is decided by parsing its host with tlsconf.IsLoopbackHost
// — the rule the hub's own endpoint checks use — not by a substring match,
// which missed 127.0.0.2 and *.localhost and flagged localhost.example.com
// (Task 20387).
func TestGitProxyLoopbackJudgedByTheHubsRule(t *testing.T) {
	cert, key := gitProxyTLS(t)
	for adv, wantWarn := range map[string]bool{
		"https://127.0.0.2:8443":                    true,
		"https://[::ffff:127.0.0.1]:8443":           true,
		"https://git.localhost:8443":                true,
		"https://[::]:8443":                         true,
		"https://localhost.example.com:8443":        false,
		"https://localhost-gitproxy.cloop.svc:8443": false,
	} {
		t.Run(adv, func(t *testing.T) {
			cfg := cloningConfig()
			cfg.Executors.GitProxy = config.GitProxyConfig{
				Enabled: true, CertFile: cert, KeyFile: key, AdvertiseURL: adv,
			}
			got := findingsFor(t, t.TempDir(), cfg, Options{Offline: true})
			if warned := len(got["gitproxy.advertise_url"]) > 0; warned != wantWarn {
				t.Errorf("warned=%v, want %v: %+v", warned, wantWarn, got["gitproxy.advertise_url"])
			}
		})
	}
}

// TestGitProxyUnsetAdvertiseIsTheBoundAddress: with advertise_url unset the
// hub advertises its bound address (gitproxy.AdvertisedBaseURL), naming an
// unspecified bind as loopback. The doctor said "the hub's own bound address"
// for all of them and warned even when that address is a routable one.
func TestGitProxyUnsetAdvertiseIsTheBoundAddress(t *testing.T) {
	cert, key := gitProxyTLS(t)
	run := func(listen string) (map[string][]Finding, []string) {
		var seen []string
		cfg := cloningConfig()
		cfg.Executors.GitProxy = config.GitProxyConfig{
			Enabled: true, CertFile: cert, KeyFile: key, ListenAddr: listen,
		}
		return findingsFor(t, t.TempDir(), cfg, Options{DialContext: fakeDial(&seen, nil)}), seen
	}

	got, seen := run("10.0.0.5:8443")
	if fs := got["gitproxy.advertise_url"]; len(fs) != 0 {
		t.Errorf("a routable bind was warned about: %+v", fs)
	}
	if len(seen) != 1 || seen[0] != "10.0.0.5:8443" {
		t.Errorf("dialled %v, want the advertised bound address", seen)
	}

	got, _ = run("0.0.0.0:8443")
	f := only(t, got, "gitproxy.advertise_url")
	wantSeverity(t, f, SeverityWarn)
	if !strings.Contains(f.Message, "https://127.0.0.1:8443") {
		t.Errorf("the hub advertises an unspecified bind as loopback; message says %q", f.Message)
	}

	got, seen = run("")
	f = only(t, got, "gitproxy.advertise_url")
	if !strings.Contains(f.Message, "port chosen at startup") {
		t.Errorf("the default bind's port is not knowable before startup; message says %q", f.Message)
	}
	if len(seen) != 0 {
		t.Errorf("dialled %v, a port nobody has bound", seen)
	}
}

// TestGitProxyDisabledWithAGitHubGrantWarns: a GitHub grant puts the forge
// credential into a sandbox of any kind when the proxy is off, so a host-only
// hub holding one is not "no forge credential is delivered".
func TestGitProxyDisabledWithAGitHubGrantWarns(t *testing.T) {
	dir := t.TempDir()
	seedBranchGrants(t, dir)
	got := findingsFor(t, dir, hostOnlyConfig(), Options{Offline: true})
	wantSeverity(t, only(t, got, "gitproxy.enabled"), SeverityWarn)
}

// TestDoctorReadsTheActiveSessionDatabase: the hub opens its control plane
// through state.DBPath, which follows .cloop/active_session. The doctor
// hardcoded .cloop/state.db in four checks, and read a database the hub was
// not using.
func TestDoctorReadsTheActiveSessionDatabase(t *testing.T) {
	dir := t.TempDir()
	session := filepath.Join(dir, ".cloop", "sessions", "s1")
	if err := os.MkdirAll(session, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(session, "session.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "active_session"), []byte("s1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(session, "state.db"); state.DBPath(dir) != want {
		t.Fatalf("premise: the hub's database is %s, want %s", state.DBPath(dir), want)
	}
	seedBranchGrantsAt(t, state.DBPath(dir))

	got := findingsFor(t, dir, hostOnlyConfig(), Options{Offline: true})
	wantSeverity(t, only(t, got, "gitproxy.branch_grants"), SeverityWarn)
	if fs := got["storage.database"]; len(fs) != 0 {
		t.Errorf("storage looked for a database other than the hub's: %+v", fs)
	}
	wantSeverity(t, only(t, got, "storage.integrity"), SeverityPass)
}
