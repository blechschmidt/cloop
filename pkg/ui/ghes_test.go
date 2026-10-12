package ui

// A GitHub Enterprise Server App grant on the guarded path (Task 20423), end to
// end: the hub's own git guard, a real proxy, real git with the lease's own
// gitconfig and credential helpers, and two forges — one standing in for
// github.com (the guard's test override), one standing in for an enterprise
// server at its own host, which also serves the App API under /api/v3. The
// lease holds an App for each.
//
// Before, the guarded lease's upstream was the constant github.com, and the
// sandbox's rewrite and helper matched github.com only: the enterprise token
// was presented to github.com whenever a workload cloned a github.com URL with
// the same owner/name. Here each host gets a rewrite of its own, to a proxy
// route of its own; each session presents its token to its own forge; and
// neither forge is ever handed the other's token.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

// appAPIByBase sends each App's API calls to the GitHub its base_url names: the
// enterprise server's, over HTTP to its /api/v3; everything else to the
// in-process stand-in for api.github.com.
type appAPIByBase struct {
	ghesBase string
	ghes     secretbroker.GitHubAppAPI
	public   secretbroker.GitHubAppAPI
}

func (a appAPIByBase) pick(base string) secretbroker.GitHubAppAPI {
	if strings.HasPrefix(base, a.ghesBase) {
		return a.ghes
	}
	return a.public
}

func (a appAPIByBase) CreateInstallationToken(ctx context.Context, req secretbroker.InstallationTokenRequest) (secretbroker.InstallationToken, error) {
	return a.pick(req.BaseURL).CreateInstallationToken(ctx, req)
}

func (a appAPIByBase) ListInstallationRepos(ctx context.Context, base, token string) ([]secretbroker.InstallationRepo, error) {
	return a.pick(base).ListInstallationRepos(ctx, base, token)
}

func (a appAPIByBase) RevokeInstallationToken(ctx context.Context, base, token string) error {
	return a.pick(base).RevokeInstallationToken(ctx, base, token)
}

func (a appAPIByBase) ListAppInstallations(ctx context.Context, base, appJWT string) ([]secretbroker.AppInstallation, error) {
	return a.pick(base).ListAppInstallations(ctx, base, appJWT)
}

func TestAnEnterpriseAppGrantReachesOnlyItsServer(t *testing.T) {
	gitBin, _ := secretbrokertest.GitTools(t)
	cpDir := newWorkspaceControlPlane(t)

	publicGH := secretbrokertest.NewGitHub(secretbroker.InstallationRepo{ID: 7, FullName: "acme/tool"})
	publicForge := secretbrokertest.NewForge(t, publicGH, "acme/tool")
	ghesGH := secretbrokertest.NewGitHub(secretbroker.InstallationRepo{ID: 9, FullName: "acme/tool"})
	ghesForge := secretbrokertest.NewEnterpriseForge(t, ghesGH, "acme/tool")
	ghesHost := strings.TrimPrefix(ghesForge.URL, "https://")

	prevOpts := testBrokerOptions
	testBrokerOptions = []secretbroker.Option{secretbroker.WithGitHubApp(appAPIByBase{
		ghesBase: ghesForge.APIURL,
		ghes:     secretbroker.NewHTTPGitHubAppAPI(&http.Client{Transport: ghesForge.Transport(), Timeout: 30 * time.Second}),
		public:   publicGH,
	})}
	t.Cleanup(func() { testBrokerOptions = prevOpts })

	// The hub's git proxy, as startGitProxy builds it, in front of both forges
	// (one test certificate serves every httptest server).
	var handler atomic.Value
	proxySrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := handler.Load().(http.Handler); ok {
			h.ServeHTTP(w, r)
			return
		}
		http.Error(w, "no proxy yet", http.StatusServiceUnavailable)
	}))
	proxySrv.StartTLS()
	t.Cleanup(proxySrv.Close)
	reg, err := gitproxy.NewRegistry(proxySrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	px, err := gitproxy.New(reg, gitproxy.Options{Transport: publicForge.Transport()})
	if err != nil {
		t.Fatal(err)
	}
	handler.Store(http.Handler(px))
	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	svc := &gitProxyService{reg: reg, proxy: px, baseURL: proxySrv.URL, policy: pol, ttl: time.Hour,
		githubUpstream: publicForge.URL}

	broker, closeDB, err := openUIBroker(cpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDB()
	broker.GitGuard = gitGuard{svc: svc}
	ctx := context.Background()
	mintApp := func(name string, appID, installation int64, base string) {
		t.Helper()
		var doc map[string]any
		if err := json.Unmarshal(secretbrokertest.AppPayload(appID, installation), &doc); err != nil {
			t.Fatal(err)
		}
		if base != "" {
			doc["base_url"] = base
		}
		payload, _ := json.Marshal(doc)
		sec, err := broker.Mint(ctx, secretbroker.MintRequest{Name: name, Kind: secretbroker.KindGitHubApp, Payload: payload, Actor: "t"})
		if err != nil {
			t.Fatalf("mint %s: %v", name, err)
		}
		if _, err := broker.Grant(ctx, secretbroker.GrantRequest{
			SecretRef: sec.ID, Subject: secretbroker.Subject{Type: secretbroker.SubjectProject, Value: "/srv/app"},
			Constraints: secretbroker.Constraints{Repos: []string{"acme/tool"}, Permissions: []string{"contents:read"}},
			TTL:         time.Hour, Actor: "t",
		}); err != nil {
			t.Fatalf("grant %s: %v", name, err)
		}
	}
	mintApp("public-app", 101, 102, "")
	mintApp("ghes-app", 201, 202, ghesForge.APIURL)

	lease, err := broker.Lease(ctx, "exec-1", "/srv/app")
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}
	// Released before the database closes (defers run last-in, first-out),
	// so its audit rows land.
	defer broker.Release(lease.ID)
	hosts := map[string]bool{}
	for _, m := range lease.Materials {
		hosts[m.GitHubHost()] = true
	}
	if !hosts["github.com"] || !hosts[ghesHost] {
		t.Fatalf("lease materials are for %v, want github.com and %s", hosts, ghesHost)
	}
	if len(ghesGH.Creates()) == 0 {
		t.Fatal("the enterprise App's token was not minted at its own /api/v3")
	}
	for _, s := range reg.Sessions() {
		switch s.ForgeHost {
		case "github.com":
			if s.Upstream != publicForge.URL {
				t.Errorf("the github.com session presents its token to %s", s.Upstream)
			}
		case ghesHost:
			if s.Upstream != "https://"+ghesHost {
				t.Errorf("the enterprise session presents its token to %s", s.Upstream)
			}
		default:
			t.Errorf("a session is for %q", s.ForgeHost)
		}
	}

	mount, err := lease.Materialize(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mount.Close() })
	git := func(args ...string) (string, error) {
		cmd := exec.Command(gitBin, args...)
		home := t.TempDir()
		cmd.Dir = home
		cmd.Env = append([]string{
			"HOME=" + home, "PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
			"GIT_ASKPASS=true", "GIT_SSL_NO_VERIFY=true", "LC_ALL=C",
		}, mount.Env()...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// The enterprise server's URL reaches the enterprise forge, through the
	// enterprise route, with the enterprise token.
	acceptedBefore, _ := ghesForge.Counts()
	if out, err := git("clone", "-q", "https://"+ghesHost+"/acme/tool", filepath.Join(t.TempDir(), "ghes")); err != nil {
		t.Fatalf("cloning from the enterprise server: %v\n%s", err, out)
	}
	if accepted, _ := ghesForge.Counts(); accepted == acceptedBefore {
		t.Fatal("the enterprise clone never reached the enterprise forge")
	}
	// github.com's URL — same owner/name — reaches github.com's stand-in with
	// the github.com token.
	publicBefore, _ := publicForge.Counts()
	if out, err := git("clone", "-q", "https://github.com/acme/tool", filepath.Join(t.TempDir(), "gh")); err != nil {
		t.Fatalf("cloning from github.com: %v\n%s", err, out)
	}
	if accepted, _ := publicForge.Counts(); accepted == publicBefore {
		t.Fatal("the github.com clone never reached github.com's stand-in")
	}

	// Neither forge was ever offered a token it did not mint: the enterprise
	// token never went to github.com, nor the github.com token to the server.
	if _, refused := publicForge.Counts(); refused != 0 {
		t.Errorf("github.com's stand-in refused %d request(s): it was offered a token it did not mint", refused)
	}
	if _, refused := ghesForge.Counts(); refused != 0 {
		t.Errorf("the enterprise forge refused %d request(s): it was offered a token it did not mint", refused)
	}
	for _, tok := range ghesGH.Minted() {
		if publicGH.Valid(tok.Token) {
			t.Fatal("token sets overlap; the assertion above would prove nothing")
		}
	}

	// And the sandbox holds neither token.
	for _, gh := range []*secretbrokertest.GitHub{publicGH, ghesGH} {
		for _, tok := range gh.Minted() {
			for _, kv := range mount.Env() {
				if strings.Contains(kv, tok.Token) {
					t.Errorf("the sandbox environment carries an installation token")
				}
			}
			entries, _ := os.ReadDir(mount.Dir)
			for _, e := range entries {
				body, _ := os.ReadFile(filepath.Join(mount.Dir, e.Name()))
				if strings.Contains(string(body), tok.Token) {
					t.Errorf("%s in the lease directory carries an installation token", e.Name())
				}
			}
		}
	}
}
