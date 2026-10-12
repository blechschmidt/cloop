package cmd

// `cloop remote init` against an in-process hub with single sign-on (Task
// 20417): what it creates, binds and attaches, what it checks before
// anything exists, and that a person the dashboard would refuse is refused
// by the hub in the same words.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/pkg/gitremote"
	"github.com/blechschmidt/cloop/pkg/hubclient"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/state"
)

// storeSecret stores a secret as whoever the terminal is signed in as.
func storeSecret(t *testing.T, w *remoteWorld, name, kind, payload string, personal bool) hubclient.Secret {
	t.Helper()
	c, err := remoteClient()
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.CreateSecret(context.Background(), hubclient.CreateSecretRequest{
		Name: name, Kind: kind, Payload: payload, Personal: &personal,
	})
	if err != nil {
		t.Fatalf("store %s: %v", name, err)
	}
	return s
}

// patPayload is a github_pat secret's payload.
const patPayload = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"

func decodeInit(t *testing.T, out string) initView {
	t.Helper()
	var v initView
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &v); err != nil {
		t.Fatalf("init --json printed %q: %v", out, err)
	}
	return v
}

// TestRemoteInitCreatesBindsAndAttaches is the whole of it for an
// administrator: from a checkout whose origin is the scp form, a project
// under the hub's projects root, bound to the executor chosen, with its
// repository granted for writing through the token named, and a link that
// opens it.
func TestRemoteInitCreatesBindsAndAttaches(t *testing.T) {
	w := newRemoteWorld(t)
	w.hub.AddExecutor(t, &ssohubtest.StubExecutor{IDValue: "sandbox-1"}, "Sandbox one")
	w.as(t, rootEmail)
	storeSecret(t, w, "root-pat", "github_pat", patPayload, true)
	checkoutOf(t, "git@github.com:acme/widgets.git")

	out, err := runRemoteCLI(t, "init", "--goal", "Ship the widgets API", "--executor", "sandbox-1",
		"--repo-secret", "root-pat", "--access", "write", "--branch", "cloop/*", "--json")
	if err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	v := decodeInit(t, out)
	wantPath := filepath.Join(w.hub.Home, "projects", "widgets")
	if v.Project.Path != wantPath || v.Project.Name != "widgets" {
		t.Fatalf("created %+v, want widgets at %s", v.Project, wantPath)
	}
	if v.Executor != "sandbox-1" || len(v.Repositories) != 1 || v.Repositories[0] != "acme/widgets" {
		t.Fatalf("executor %q, repositories %v", v.Executor, v.Repositories)
	}
	if v.Attached == nil || len(v.Attached.Assigned) != 1 {
		t.Fatalf("attached %+v, want one grant", v.Attached)
	}
	a := v.Attached.Assigned[0]
	if a.SecretName != "root-pat" || a.Access != "write" || len(a.Repos) != 1 || a.Repos[0] != "acme/widgets" ||
		len(a.Branches) != 1 || a.Branches[0] != "cloop/*" {
		t.Fatalf("the grant is %+v", a)
	}
	if !strings.HasPrefix(v.Project.URL, w.hub.URL+"/?project=") || !strings.Contains(v.Project.URL, "widgets") {
		t.Fatalf("the dashboard link is %q", v.Project.URL)
	}

	// The hub agrees: initialised, owned by the person who created it, bound.
	if _, err := os.Stat(state.DBPath(wantPath)); err != nil {
		t.Fatalf("the project was not initialised: %v", err)
	}
	entries, err := multiui.Load()
	if err != nil {
		t.Fatal(err)
	}
	var owner string
	for _, e := range entries {
		if e.Path == wantPath {
			owner = e.Owner
		}
	}
	if !strings.Contains(owner, rootEmail) {
		t.Fatalf("the project is owned by %q, want %s", owner, rootEmail)
	}
	if id, ok, err := w.hub.ControlPlane(t).ProjectExecutor(wantPath); err != nil || !ok || id != "sandbox-1" {
		t.Fatalf("the project is bound to %q (%v, %v), want sandbox-1", id, ok, err)
	}

	// The same checkout again: the project exists, and is not created twice.
	out, err = runRemoteCLI(t, "init", "--goal", "Ship the widgets API again")
	if err == nil || !strings.Contains(err.Error(), "already exists at "+wantPath) || !strings.Contains(err.Error(), "CONFLICT") {
		t.Fatalf("a second init = %v\n%s, want the hub's conflict", err, out)
	}
	st, lerr := state.LoadLite(wantPath)
	if lerr != nil || st.Goal != "Ship the widgets API" {
		t.Fatalf("the first project's state after a second init: %v, goal %q", lerr, st.Goal)
	}
}

// TestRemoteInitRefusesAViewerAsTheDashboardWould: the hub refuses a viewer's
// New Project, and the terminal says so with the permission, the role and how
// to get it — and with nothing created.
func TestRemoteInitRefusesAViewerAsTheDashboardWould(t *testing.T) {
	w := newRemoteWorld(t)
	w.as(t, vicEmail, ssohubtest.GroupViewers)
	checkoutOf(t, "https://github.com/acme/widgets.git")

	out, err := runRemoteCLI(t, "init", "--goal", "Ship widgets")
	if err == nil {
		t.Fatalf("a viewer created a project:\n%s", out)
	}
	msg := err.Error()
	for _, want := range []string{"your role does not permit this action", "HTTP 403", "FORBIDDEN",
		"needs:      project.write (hub-wide)", "your role:  viewer", "maintainer role"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "{") || strings.Contains(msg, "map[") || strings.Contains(msg, "[object") {
		t.Errorf("the refusal carries raw structure:\n%s", msg)
	}

	// The dashboard's own call, as the same person in a browser.
	status, body := w.hub.Call(t, w.browser(t, vicEmail, ssohubtest.GroupViewers), http.MethodPost, "/api/projects/new",
		map[string]any{"name": "widgets", "goal": "Ship widgets"})
	var dash struct {
		Error struct {
			Code    string         `json:"code"`
			Message string         `json:"message"`
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &dash); err != nil || status != http.StatusForbidden {
		t.Fatalf("the dashboard's call = %d %s", status, body)
	}
	var ae *hubclient.APIError
	if !errors.As(err, &ae) {
		t.Fatalf("the refusal does not carry the hub's answer: %T", err)
	}
	if ae.Status != status || ae.Code != dash.Error.Code || ae.Message != dash.Error.Message ||
		ae.Detail("required_permission") != dash.Error.Details["required_permission"] ||
		ae.Detail("role") != dash.Error.Details["role"] {
		t.Fatalf("the terminal was refused with %+v; the dashboard with %d %+v", ae, status, dash.Error)
	}
	if _, err := os.Stat(filepath.Join(w.hub.Home, "projects", "widgets")); !os.IsNotExist(err) {
		t.Fatalf("the refused init left a directory behind: %v", err)
	}
}

// TestRemoteInitBindingIsAnAdministratorsDecision: a maintainer may create a
// project but not choose its executor; the creation is refused whole, and the
// terminal says only an administrator binds one.
func TestRemoteInitBindingIsAnAdministratorsDecision(t *testing.T) {
	w := newRemoteWorld(t)
	w.hub.AddExecutor(t, &ssohubtest.StubExecutor{IDValue: "sandbox-2"}, "")
	w.as(t, alexEmail, ssohubtest.GroupMaintainers)
	storeSecret(t, w, "alex-pat", "github_pat", patPayload, true)
	checkoutOf(t, "https://github.com/acme/gadgets")

	out, err := runRemoteCLI(t, "init", "--goal", "Gadgets", "--executor", "sandbox-2", "--repo-secret", "alex-pat")
	if err == nil {
		t.Fatalf("a maintainer bound an executor:\n%s", out)
	}
	for _, want := range []string{"needs:      executor.manage (hub-wide)", "your role:  maintainer",
		"only an administrator binds a project to an executor"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q:\n%v", want, err)
		}
	}
	if _, err := os.Stat(filepath.Join(w.hub.Home, "projects", "gadgets")); !os.IsNotExist(err) {
		t.Fatalf("the refused creation left a directory behind: %v", err)
	}

	// Without --executor the same person creates it, on the hub's default.
	out, err = runRemoteCLI(t, "init", "--goal", "Gadgets", "--repo-secret", "alex-pat")
	if err != nil {
		t.Fatalf("init on the default executor: %v\n%s", err, out)
	}
	for _, want := range []string{"Created gadgets on " + w.hub.URL, "Granted acme/gadgets (read) through alex-pat",
		"Dashboard: " + w.hub.URL + "/?project="} {
		if !strings.Contains(out, want) {
			t.Errorf("init printed no %q:\n%s", want, out)
		}
	}
}

// TestRemoteInitChecksWhatItCanBeforeCreating: an executor the caller is not
// admitted to, a secret that does not exist, and a hub with no GitHub
// credential at all are refused before anything is created.
func TestRemoteInitChecksWhatItCanBeforeCreating(t *testing.T) {
	w := newRemoteWorld(t)
	w.hub.AddExecutor(t, &ssohubtest.StubExecutor{IDValue: "locked-box"}, "Locked box")
	w.hub.RestrictExecutor(t, "locked-box", "platform")
	w.as(t, rootEmail)
	checkoutOf(t, "https://github.com/acme/widgets")

	// No GitHub credential the caller could use or ask for.
	_, err := runRemoteCLI(t, "init", "--goal", "Widgets")
	if err == nil || !strings.Contains(err.Error(), "no GitHub credential on this hub") {
		t.Fatalf("init with no credential anywhere = %v", err)
	}
	storeSecret(t, w, "root-pat", "github_pat", patPayload, true)

	// An executor restricted to a group the caller is not in.
	_, err = runRemoteCLI(t, "init", "--goal", "Widgets", "--executor", "locked-box", "--repo-secret", "root-pat")
	if err == nil || !strings.Contains(err.Error(), "restricted and your account is not on its access list") {
		t.Fatalf("init on a restricted executor = %v", err)
	}
	// One that does not exist, named as a person would.
	_, err = runRemoteCLI(t, "init", "--goal", "Widgets", "--executor", "no-such-box", "--repo-secret", "root-pat")
	if err == nil || !strings.Contains(err.Error(), `no executor "no-such-box"`) {
		t.Fatalf("init on a missing executor = %v", err)
	}
	// A --grant naming nothing.
	_, err = runRemoteCLI(t, "init", "--goal", "Widgets", "--repo-secret", "root-pat", "--grant", "nope,namespace=x")
	if err == nil || !strings.Contains(err.Error(), "--grant nope: there is no secret by that name") {
		t.Fatalf("init granting a missing secret = %v", err)
	}
	if _, err := os.Stat(filepath.Join(w.hub.Home, "projects", "widgets")); !os.IsNotExist(err) {
		t.Fatalf("a refused init left a directory behind: %v", err)
	}
}

// TestRemoteInitRefusesARemoteItCannotUse: a checkout whose origin is not on
// GitHub, or carries a credential, is refused with the reason and without
// the credential in the message.
func TestRemoteInitRefusesARemoteItCannotUse(t *testing.T) {
	credentialHome(t)
	for _, tc := range []struct {
		origin string
		want   string
		secret string
	}{
		{"https://gitlab.com/acme/widgets.git", "is on gitlab.com, not github.com", ""},
		{"git@bitbucket.org:acme/widgets.git", "is on bitbucket.org, not github.com", ""},
		{"https://ghp_leakedtoken123@github.com/acme/widgets.git", "embeds a credential", "ghp_leakedtoken123"},
		{"https://user:hunter2@github.com/acme/widgets.git", "embeds a credential", "hunter2"},
	} {
		checkoutOf(t, tc.origin)
		_, err := runRemoteCLI(t, "init", "--goal", "Widgets")
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "the origin remote") {
			t.Errorf("init with origin %s = %v, want %q", gitremote.Redact(tc.origin), err, tc.want)
			continue
		}
		if tc.secret != "" && strings.Contains(err.Error(), tc.secret) {
			t.Errorf("the refusal quotes the credential: %v", err)
		}
	}
}

// TestRemoteInitReadsTheOriginInEveryForm: the ssh and https spellings of one
// repository derive one project, named after it.
func TestRemoteInitReadsTheOriginInEveryForm(t *testing.T) {
	for _, origin := range []string{
		"git@github.com:acme/widgets.git",
		"ssh://git@github.com/acme/widgets.git",
		"ssh://git@ssh.github.com:443/acme/widgets.git",
		"https://github.com/acme/widgets",
		"https://github.com/acme/widgets.git/",
	} {
		dir := checkoutOf(t, origin)
		co, err := readCheckout(context.Background(), dir, false)
		if err != nil || co.Origin == nil || co.Origin.FullName() != "acme/widgets" {
			t.Errorf("readCheckout(origin %s) = %+v, %v", origin, co.Origin, err)
			continue
		}
		if name := defaultProjectName(co, nil); name != "widgets" {
			t.Errorf("origin %s names the project %q", origin, name)
		}
	}
	// No checkout at all, and a checkout without an origin, say what to do.
	t.Chdir(t.TempDir())
	if _, err := readCheckout(context.Background(), ".", false); err == nil || !strings.Contains(err.Error(), "inside a git checkout") {
		t.Errorf("outside a checkout: %v", err)
	}
	dir := checkoutOf(t, "")
	if _, err := readCheckout(context.Background(), dir, false); err == nil || !strings.Contains(err.Error(), "no origin remote") {
		t.Errorf("without an origin: %v", err)
	}
	if co, err := readCheckout(context.Background(), dir, true); err != nil || co.Origin != nil {
		t.Errorf("without an origin but with --repo: %+v, %v", co, err)
	}
}

func TestParseGrantSpec(t *testing.T) {
	g, err := parseGrantSpec("staging,namespace=payments,namespace=staging,context=aks, ttl=12h,scope=deploy")
	if err != nil {
		t.Fatal(err)
	}
	if g.SecretRef != "staging" || len(g.Namespaces) != 2 || g.Namespaces[1] != "staging" ||
		len(g.Contexts) != 1 || g.TTLMinutes != 720 || g.Scope != "deploy" {
		t.Fatalf("parsed %+v", g)
	}
	g, err = parseGrantSpec("org-app,repo=git@github.com:acme/api.git,access=write,branch=cloop/*")
	if err != nil || len(g.Repos) != 1 || g.Repos[0] != "acme/api" || len(g.Permissions) != 2 || g.Branches[0] != "cloop/*" {
		t.Fatalf("parsed %+v, %v", g, err)
	}
	g, err = parseGrantSpec("dev-board,writable")
	if err != nil || !g.Writable {
		t.Fatalf("parsed %+v, %v", g, err)
	}
	for _, bad := range []string{"", "namespace=x", "s,namespace", "s,bogus=1", "s,ttl=10s", "s,repo=gitlab.com/x/y",
		"s,writable=maybe", "s,access=admin"} {
		if _, err := parseGrantSpec(bad); err == nil {
			t.Errorf("parseGrantSpec(%q) accepted", bad)
		}
	}
}

// TestRemoteInitWarnsWhenTheDefaultExecutorWouldRefuse: without --executor a
// project runs on the hub's default; when its access list leaves the caller
// out, init says so instead of creating a project whose every run is refused.
func TestRemoteInitWarnsWhenTheDefaultExecutorWouldRefuse(t *testing.T) {
	w := newRemoteWorld(t)
	w.as(t, rootEmail)
	storeSecret(t, w, "root-pat", "github_pat", patPayload, true)
	out, err := runRemoteCLI(t, "executors", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var fleet executorsView
	if err := json.Unmarshal([]byte(out), &fleet); err != nil || fleet.DefaultID == "" {
		t.Fatalf("executors --json = %q (%v)", out, err)
	}
	w.hub.RestrictExecutor(t, fleet.DefaultID, "platform")
	checkoutOf(t, "https://github.com/acme/widgets")

	out, err = runRemoteCLI(t, "init", "--goal", "Widgets", "--repo-secret", "root-pat")
	if err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	want := "the hub's default executor " + fleet.DefaultID + " is restricted and you are not on its access list"
	if !strings.Contains(out, want) {
		t.Fatalf("init did not warn %q:\n%s", want, out)
	}
}

// TestRemoteInitDirOutsideTheRootIsAnAdministratorsDecision: a maintainer
// names a --dir outside the hub's projects root and is refused before anything
// is made, in the dashboard's words, with how to create it instead (Task
// 20418). The same --dir is an administrator's to choose, and a --dir inside
// the root is the maintainer's.
func TestRemoteInitDirOutsideTheRootIsAnAdministratorsDecision(t *testing.T) {
	w := newRemoteWorld(t)
	w.as(t, alexEmail, ssohubtest.GroupMaintainers)
	storeSecret(t, w, "alex-pat", "github_pat", patPayload, true)
	checkoutOf(t, "https://github.com/acme/gizmos")

	outside := filepath.Join(t.TempDir(), "gizmos")
	out, err := runRemoteCLI(t, "init", "--goal", "Gizmos", "--dir", outside, "--repo-secret", "alex-pat")
	if err == nil {
		t.Fatalf("a maintainer created a project outside the projects root:\n%s", out)
	}
	root := filepath.Join(w.hub.Home, "projects")
	for _, want := range []string{"only an administrator places a project outside the hub's projects root",
		"HTTP 403", "needs:      executor.manage (hub-wide)", "your role:  maintainer",
		"leave out --dir and it goes under " + root} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q:\n%v", want, err)
		}
	}
	if strings.Contains(err.Error(), "binds a project to an executor") {
		t.Errorf("the refusal explains an executor binding nobody asked for:\n%v", err)
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatalf("the refused init made %s: %v", outside, err)
	}

	// The root itself and its parent — here the hub's home — are nobody's
	// project.
	for dir, want := range map[string]string{root: "is the hub's projects root",
		filepath.Join(root, ".."): "the hub user's home directory"} {
		if _, err := runRemoteCLI(t, "init", "--goal", "Gizmos", "--dir", dir, "--repo-secret", "alex-pat"); err == nil ||
			!strings.Contains(err.Error(), want) {
			t.Fatalf("init --dir %s = %v, want a refusal saying %q", dir, err, want)
		}
	}

	// Inside the root, the maintainer's own choice of directory.
	inside := filepath.Join(root, "gizmos-here")
	if out, err := runRemoteCLI(t, "init", "--goal", "Gizmos", "--dir", inside, "--repo-secret", "alex-pat", "--json"); err != nil {
		t.Fatalf("init --dir inside the root: %v\n%s", err, out)
	} else if v := decodeInit(t, out); v.Project.Path != inside {
		t.Fatalf("created at %s, want %s", v.Project.Path, inside)
	}

	// And outside it, an administrator's.
	w.as(t, rootEmail)
	storeSecret(t, w, "root-pat", "github_pat", patPayload, true)
	if out, err := runRemoteCLI(t, "init", "--goal", "Gizmos", "--dir", outside, "--repo-secret", "root-pat", "--json"); err != nil {
		t.Fatalf("an administrator's init --dir outside the root: %v\n%s", err, out)
	}
}
