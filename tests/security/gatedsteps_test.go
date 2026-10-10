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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// gatedStepProofs proves each gatedHostSteps entry, keyed the same way.
var gatedStepProofs = map[string]func(t *testing.T){
	"(*github.com/blechschmidt/cloop/pkg/ui.Server).handleClusterOffboardClaude": proveClusterOffboardClaudeIsStepGated,
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

	// A `claude` that records every invocation.
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "claude.log")
	// Quoted: a subtest's temporary directory carries its name, parentheses
	// and all, which an unquoted shell redirect reads as syntax.
	script := "#!/bin/sh\necho \"$CLAUDE_CONFIG_DIR $*\" >> '" + log + "'\n"
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

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
