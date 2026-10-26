package security

// The proofs behind gatedHostSteps (callgraph_test.go): a handler that runs a
// program on the control-plane host as one step of an operation that must not
// be refused under strict mode spawns nothing when host execution is off — and
// does spawn it when host execution is on, so a proof cannot pass because the
// step never ran.
//
// Each proof drives the real handler. For handleClusterOffboardClaude that
// means a real peer call: two hub cluster members over one control plane, the
// second calling the first's internal endpoint with a signature only a member
// can make, exactly as the member serving a dashboard offboarding does. The
// program is a stand-in `claude` on PATH that records how it was called.
//
// The host-execution policy is process-global, so nothing here may run in
// parallel.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/provision"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// gatedStepProofs proves each gatedHostSteps entry, keyed the same way.
var gatedStepProofs = map[string]func(t *testing.T){
	"(*github.com/blechschmidt/cloop/pkg/ui.Server).handleClusterOffboardClaude": proveClusterOffboardClaudeIsStepGated,
	"(*github.com/blechschmidt/cloop/pkg/ui.Server).handleUserOffboard":          proveUserOffboardIsStepGated,
	"(*github.com/blechschmidt/cloop/pkg/ui.Server).handleSCIMUserDelete":        proveSCIMUserDeleteIsStepGated,
}

// TestGatedStepsRunNothingUnderStrictMode runs every proof.
func TestGatedStepsRunNothingUnderStrictMode(t *testing.T) {
	for key, prove := range gatedStepProofs {
		t.Run(key, prove)
	}
}

// TestGatedStepListsAgree keeps the exemption and its proof in lockstep, as
// TestGatedListsAgree does for gatedHostExecution: an exemption with no proof is
// a suppression, and a proof with no exemption proves nothing anyone relies on.
func TestGatedStepListsAgree(t *testing.T) {
	for key := range gatedHostSteps {
		if gatedStepProofs[key] == nil {
			t.Errorf("%s is exempt as a gated step but nothing in gatedStepProofs proves it spawns "+
				"nothing under strict mode", key)
		}
	}
	for key := range gatedStepProofs {
		if _, ok := gatedHostSteps[key]; !ok {
			t.Errorf("gatedStepProofs proves %s, which gatedHostSteps does not exempt — remove the stale proof", key)
		}
	}
}

// proveClusterOffboardClaudeIsStepGated: a member asked by a peer to end a
// departed identity's Claude login removes the home either way, and runs
// `claude auth logout` only when host execution is allowed.
func proveClusterOffboardClaudeIsStepGated(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir := statedbtest.Dir(t)
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}

	// The identity is offboarded: a member acts on another process's word only
	// for an identity the control plane denies.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.PutRoleBinding(statedb.RoleBindingRow{Effect: statedb.RoleEffectDeny,
		Claim: "email", Value: "leaver@example.com", Reason: "offboarded"}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	log := recordingClaude(t)

	target, caller := gatedStepCluster(t, dir)

	sever := func() (removed bool, logout string) {
		t.Helper()
		home, err := claudecodeauth.HomeFor("leaver@example.com")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(claudecodeauth.CredentialsPath(home), []byte(`{"claudeAiOauth":{}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		var out struct {
			Error   string `json:"error"`
			Results []struct {
				Removed bool   `json:"removed"`
				Logout  string `json:"logout"`
			} `json:"results"`
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := caller.Call(ctx, target, http.MethodPost, "/api/internal/cluster/offboard/claude",
			map[string]any{"op": "sever", "keys": []string{"leaver@example.com"}},
			&out); err != nil {
			t.Fatalf("peer call: %v", err)
		}
		if out.Error != "" || len(out.Results) != 1 {
			t.Fatalf("answer error %q results %+v, want the one home handled", out.Error, out.Results)
		}
		if _, err := os.Stat(home); !os.IsNotExist(err) {
			t.Fatalf("the home survived the request: %v", err)
		}
		return out.Results[0].Removed, out.Results[0].Logout
	}

	strictMode(t)
	removed, logout := sever()
	if !removed || !strings.Contains(logout, "allow_host_process") {
		t.Fatalf("under strict mode: removed=%v logout=%q, want the home removed and the skipped logout named",
			removed, logout)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		raw, _ := os.ReadFile(log)
		t.Fatalf("under strict mode the handler ran the claude binary: %s", raw)
	}

	// Non-vacuity: the same request with host execution allowed does run it,
	// scoped to the departed identity's directory.
	permissiveMode(t)
	if removed, _ := sever(); !removed {
		t.Fatal("permissive: the home was not removed")
	}
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("with host execution allowed the step never ran, so the strict-mode result proves nothing: %v", err)
	}
	if !strings.Contains(string(raw), "claude-identities") || !strings.Contains(string(raw), "auth logout") {
		t.Fatalf("claude ran as %q, want a logout scoped to the identity's home", raw)
	}
}

// recordingClaude puts a `claude` first on PATH that records every invocation
// — its CLAUDE_CONFIG_DIR and arguments — in the file whose path it returns.
func recordingClaude(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "claude.log")
	// Quoted: a subtest's temporary directory carries its name, parentheses
	// and all, which an unquoted shell redirect reads as syntax.
	script := "#!/bin/sh\necho \"$CLAUDE_CONFIG_DIR $*\" >> '" + log + "'\n"
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

// seedClaudeHome gives identity a Claude Code login home with a credential in
// it, and returns the home.
func seedClaudeHome(t *testing.T, identity string) string {
	t.Helper()
	home, err := claudecodeauth.HomeFor(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(claudecodeauth.CredentialsPath(home), []byte(`{"claudeAiOauth":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// assertStepGated runs an offboarding of a fresh identity under strict mode
// and then with host execution allowed: both remove the identity's Claude
// home, and only the second runs the `claude` that log records — so the first
// cannot pass because the step never runs at all.
func assertStepGated(t *testing.T, log string, offboardIdentity func(identity string)) {
	t.Helper()
	strictMode(t)
	home := seedClaudeHome(t, "leaver@example.com")
	offboardIdentity("leaver@example.com")
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("under strict mode the departed identity's Claude home survived: %v", err)
	}
	if _, err := os.Stat(log); !os.IsNotExist(err) {
		raw, _ := os.ReadFile(log)
		t.Fatalf("under strict mode the handler ran the claude binary: %s", raw)
	}

	permissiveMode(t)
	home = seedClaudeHome(t, "second-leaver@example.com")
	offboardIdentity("second-leaver@example.com")
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("permissive: the Claude home survived: %v", err)
	}
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("with host execution allowed the step never ran, so the strict-mode result proves nothing: %v", err)
	}
	if !strings.Contains(string(raw), "claude-identities") || !strings.Contains(string(raw), "auth logout") {
		t.Fatalf("claude ran as %q, want a logout scoped to the identity's home", raw)
	}
}

// proveUserOffboardIsStepGated: the dashboard's offboarding (Settings →
// Offboard a user) severs the departed identity's Claude login on this member
// through offboard.ClaudeHomes, the interface Task 20442 taught the reference
// graph to follow, and runs `claude auth logout` only when host execution is
// allowed.
func proveUserOffboardIsStepGated(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	log := recordingClaude(t)
	hub := ssohubtest.Start(t, ssohubtest.Options{AdminEmails: []string{"root@example.com"}})
	admin := hub.SignIn(t, "root@example.com")
	assertStepGated(t, log, func(identity string) {
		t.Helper()
		status, raw := hub.Call(t, admin, http.MethodPost, "/api/users/offboard",
			map[string]any{"identity": identity, "reason": "left the company, HR-1"})
		if status != http.StatusOK {
			t.Fatalf("offboarding %s = %d: %s", identity, status, raw)
		}
	})
}

// proveSCIMUserDeleteIsStepGated: deleting a user at the identity provider
// offboards them through the same step, from the SCIM endpoint.
func proveSCIMUserDeleteIsStepGated(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	log := recordingClaude(t)
	hub := ssohubtest.Start(t, ssohubtest.Options{AdminEmails: []string{"root@example.com"}})
	if _, err := hub.Server.OpenSCIM(config.SCIMConfig{}); err != nil {
		t.Fatalf("OpenSCIM: %v", err)
	}
	minted, err := provision.MintCredential(hub.ControlPlane(t), "entra",
		provision.AdminContext{Actor: "root@example.com", Reason: "tests"}, time.Now())
	if err != nil {
		t.Fatalf("MintCredential: %v", err)
	}
	scimCall := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, hub.URL+path, rd)
		if err != nil {
			t.Fatal(err)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/scim+json")
		}
		req.Header.Set("Authorization", "Bearer "+minted.Plaintext)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	assertStepGated(t, log, func(identity string) {
		t.Helper()
		status, out := scimCall(http.MethodPost, "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],`+
			`"userName":"`+identity+`","active":true,"emails":[{"primary":true,"value":"`+identity+`"}]}`)
		id, _ := out["id"].(string)
		if status != http.StatusCreated || id == "" {
			t.Fatalf("provisioning %s = %d: %v", identity, status, out)
		}
		if status, out := scimCall(http.MethodDelete, "/scim/v2/Users/"+id, ""); status != http.StatusNoContent {
			t.Fatalf("deleting %s = %d: %v", identity, status, out)
		}
	})
}

// gatedStepCluster starts two members over the control plane at dir and
// returns the first, as the second sees it, and the second's node.
func gatedStepCluster(t *testing.T, dir string) (hubcluster.Member, *hubcluster.Node) {
	t.Helper()
	var (
		mu      sync.RWMutex
		handler http.Handler = http.NotFoundHandler()
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		h := handler
		mu.RUnlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)

	join := func(advertise string) *hubcluster.Node {
		t.Helper()
		n, err := hubcluster.Join(hubcluster.Options{
			DBPath: state.DBPath(dir), AdvertiseURL: advertise,
			Heartbeat: 40 * time.Millisecond, MemberTTL: 500 * time.Millisecond,
			BusPoll: 15 * time.Millisecond, BusFlush: 5 * time.Millisecond,
			Campaign: 30 * time.Millisecond, LeaderTTL: 600 * time.Millisecond,
			LeaderInterval: 60 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("join: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		n.Start(ctx)
		t.Cleanup(func() {
			cancel()
			_ = n.Close()
		})
		return n
	}

	targetNode := join(ts.URL)
	srv := ui.New(dir, 0, "")
	srv.Cluster = targetNode
	mu.Lock()
	handler = srv.Handler()
	mu.Unlock()

	caller := join("http://127.0.0.1:1")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, m := range caller.Peers() {
			if m.ID == targetNode.ID() {
				return m, caller
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the members never saw each other")
	return hubcluster.Member{}, nil
}
