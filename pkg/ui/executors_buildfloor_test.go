package ui

// executors_buildfloor_test.go covers the Executors panel's half of the fleet
// build floor (Task 20252).
//
// The scheduler's half is tested in pkg/executor. What has to be true *here* is
// that the panel and the API agree with it — a device that placement silently
// skips looks identical on a card to one that is merely idle, and the operator's
// next move, waiting, is the one thing that will not help.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// staleDevice is a remote-agent-shaped executor reporting an old build, so it
// satisfies executor.BuildReporter the way remote.Executor does.
type staleDevice struct {
	executor.Executor
	id    string
	build string
}

func (d *staleDevice) ID() string   { return d.id }
func (d *staleDevice) Kind() string { return executor.KindRemoteAgent }
func (d *staleDevice) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationRemote}
}
func (d *staleDevice) AgentVersion() string { return d.build }

func withBuildFloor(t *testing.T, floor string) {
	t.Helper()
	prev := executor.SetMinAgentBuild(floor)
	t.Cleanup(func() { executor.SetMinAgentBuild(prev) })
}

// TestBlockedForReportsAnOutdatedDevice is the panel's side of the contract. It
// runs with host execution *allowed*, which is the trap: the old blockedFor
// returned early on that and would have reported an outdated remote agent as
// perfectly fine.
func TestBlockedForReportsAnOutdatedDevice(t *testing.T) {
	prevHost := executor.SetAllowHostExecution(true)
	t.Cleanup(func() { executor.SetAllowHostExecution(prevHost) })
	withBuildFloor(t, "v2.0.0")

	blocked, reason := blockedFor(&staleDevice{id: "edge-1", build: "v1.0.0"})
	if !blocked {
		t.Fatal("an agent below the fleet's build floor was reported as usable")
	}
	for _, want := range []string{"v1.0.0", "v2.0.0", AgentUpgradeCommand} {
		if !strings.Contains(reason, want) {
			t.Errorf("the card's reason does not mention %q: %s", want, reason)
		}
	}

	// A current device is untouched, or the floor would read as an outage.
	if blocked, _ := blockedFor(&staleDevice{id: "edge-2", build: "v2.1.0"}); blocked {
		t.Error("a device above the floor was reported as blocked")
	}
}

// TestBindRefusesAnOutdatedDeviceUnderItsOwnCode pins the taxonomy. Folding this
// into host_execution_denied would tell an operator that host execution is
// disabled — about a remote device, which is not the host — and offer "bind to
// an isolated executor" as the fix, which is what they just tried to do.
func TestBindRefusesAnOutdatedDeviceUnderItsOwnCode(t *testing.T) {
	w := httptest.NewRecorder()
	writeExecutorBlocked(w, "agent_build_too_old",
		`executor "edge-1" is below this fleet's minimum agent build`,
		"This device runs cloop v1.0.0, below the fleet's minimum of v2.0.0. Copy the new binary "+
			"to the device and run `"+AgentUpgradeCommand+"` there.")

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", w.Code, http.StatusConflict)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["code"] != "agent_build_too_old" {
		t.Errorf("code = %v, want agent_build_too_old", body["code"])
	}
	// The envelope must match the host-denial one key for key, so a client that
	// does not know the new code still renders the sentence instead of falling
	// back to "something went wrong".
	for _, key := range []string{"error", "code", "remediation"} {
		if v, ok := body[key].(string); !ok || strings.TrimSpace(v) == "" {
			t.Errorf("body is missing a usable %q: %#v", key, body[key])
		}
	}
	if rem, _ := body["remediation"].(string); !strings.Contains(rem, AgentUpgradeCommand) {
		t.Errorf("remediation does not name the fix: %s", rem)
	}
}

// TestAgentUpgradeCommandIsTheOneDefinition. The panel used to recommend a flag
// that did not exist, and an operator who tried the documented fix got an
// unknown-flag error. Three layers now name this string; one definition is what
// keeps the advice and the flag from drifting apart again.
func TestAgentUpgradeCommandIsTheOneDefinition(t *testing.T) {
	if AgentUpgradeCommand != executor.AgentUpgradeProcedure {
		t.Errorf("the panel recommends %q while the scheduler recommends %q",
			AgentUpgradeCommand, executor.AgentUpgradeProcedure)
	}
}
