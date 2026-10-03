package remote_test

// Tests for the device path's half of the stored firewall levels (Task 20363):
// what a device and a virtual executor report to the dispatch step, and the
// refusals made on the hub before a start frame carrying rules is sent.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
)

// storedDevice is a fwpolicy.Source holding one device's rule set.
type storedDevice struct {
	id    string
	rules *executor.FirewallRules
}

func (s storedDevice) DeviceFirewall(id string) (*executor.FirewallRules, error) {
	if id == s.id {
		return s.rules, nil
	}
	return nil, nil
}

func (storedDevice) ProjectFirewall(string) (*executor.FirewallRules, error) { return nil, nil }

func firewallDevice(t *testing.T, sandbox executor.SandboxSettings) *remote.Executor {
	t.Helper()
	ex, err := remote.NewExecutor(remote.Options{
		ID: "agent-1", Name: "edge-1",
		Sandbox: func() (executor.SandboxSettings, error) { return sandbox, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return ex
}

func helloWithFilter(version int) remote.HelloPayload {
	h := helloAt(version)
	h.Capabilities.PacketFilter = true
	h.Capabilities.ContainerRuntimes = []string{"docker"}
	return h
}

var publicHTTPS = executor.FirewallRules{AllowPublicInternet: true, AllowPorts: []int{443},
	Resolvers: []string{"1.1.1.1"}}

func TestEgressRulesNeedAProtocolV15Agent(t *testing.T) {
	ex := firewallDevice(t, executor.SandboxSettings{Mode: executor.SandboxModeContainer, Engine: "docker",
		Network: executor.SandboxNetworkBridge})
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"},
		helloWithFilter(remote.MinEgressRulesVersion-1), nil)
	defer sess.Close()

	rules := publicHTTPS
	_, err := ex.Start(context.Background(), executor.Spec{WorkDir: t.TempDir(), Argv: []string{"true"},
		EgressRules: &rules})
	if !errors.Is(err, executor.ErrUnsupported) || !strings.Contains(err.Error(), "needs v15") {
		t.Fatalf("Start on a v14 agent = %v, want a refusal naming v15", err)
	}
	if len(ex.Handles()) != 0 {
		t.Errorf("a refused dispatch left handles %v", ex.Handles())
	}
	if p := ex.EgressPosture(); p.Enforceable || !strings.Contains(p.Reason, "upgrade") {
		t.Errorf("a connected v14 agent must not claim to enforce rules: %+v", p)
	}
}

func TestEgressRulesAreRefusedOnAHostModeDevice(t *testing.T) {
	ex := firewallDevice(t, executor.SandboxSettings{Mode: executor.SandboxModeHost})
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloWithFilter(remote.ProtocolVersion), nil)
	defer sess.Close()

	if p := ex.EgressPosture(); p.Enforceable || !strings.Contains(p.Reason, "on its host") {
		t.Errorf("a host-mode device must say it cannot enforce rules: %+v", p)
	}
	rules := publicHTTPS
	_, err := ex.Start(context.Background(), executor.Spec{WorkDir: t.TempDir(), Argv: []string{"true"},
		EgressRules: &rules})
	if !errors.Is(err, executor.ErrUnsupported) || !strings.Contains(err.Error(), "on its host") {
		t.Fatalf("Start under rules on a host-mode device = %v", err)
	}
}

func TestTheHubRefusesWhatTheDeviceBoundDoesNotAllow(t *testing.T) {
	device := executor.FirewallRules{AllowCIDRs: []string{"1.1.1.0/24"}, AllowPorts: []int{443}}
	restore := fwpolicy.SetSource(storedDevice{id: "agent-1", rules: &device})
	defer restore()

	ex := firewallDevice(t, executor.SandboxSettings{Mode: executor.SandboxModeContainer, Engine: "docker",
		Network: executor.SandboxNetworkBridge})
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, helloWithFilter(remote.ProtocolVersion), nil)
	defer sess.Close()

	// A dispatch path that skipped the firewall step.
	_, err := ex.Start(context.Background(), executor.Spec{WorkDir: t.TempDir(), Argv: []string{"true"}})
	if err == nil || !strings.Contains(err.Error(), "dispatched without") {
		t.Fatalf("Start without the device's rules = %v", err)
	}
	// Rules reaching past the stored device rules, whatever bound the spec names.
	wide := publicHTTPS
	_, err = ex.Start(context.Background(), executor.Spec{WorkDir: t.TempDir(), Argv: []string{"true"},
		EgressRules: &wide, EgressBound: &wide})
	if !fwpolicy.IsExceeds(err) {
		t.Fatalf("Start with rules wider than the device = %v", err)
	}
	if len(ex.Handles()) != 0 {
		t.Errorf("refused dispatches left handles %v", ex.Handles())
	}
}

func TestVirtualExecutorPostureCarriesItsFirewall(t *testing.T) {
	parent := firewallDevice(t, executor.SandboxSettings{Mode: executor.SandboxModeHost})
	_, sess := connect(t, parent, remote.AgentRecord{AgentID: "agent-1"}, helloWithFilter(remote.ProtocolVersion), nil)
	defer sess.Close()

	fw := publicHTTPS
	v := virtualOver(t, parent, "vx-fw", executor.VirtualSpec{
		Sandbox: executor.SandboxSettings{Mode: executor.SandboxModeContainer}, Firewall: &fw})
	p := v.EgressPosture()
	if p.DeviceID != "agent-1" || p.Own == nil || !fwpolicy.Equal(*p.Own, fw) || !p.Enforceable {
		t.Errorf("virtual executor posture = %+v", p)
	}
	none := virtualOver(t, parent, "vx-none", executor.VirtualSpec{
		Sandbox: executor.SandboxSettings{Mode: executor.SandboxModeContainer}})
	if p := none.EgressPosture(); p.Own == nil || p.Own.HasDestination() {
		t.Errorf("no network is a level that reaches nothing: %+v", p)
	}
	open := virtualOver(t, parent, "vx-open", executor.VirtualSpec{
		Sandbox: executor.SandboxSettings{Mode: executor.SandboxModeContainer, Network: "lab-net"}})
	if p := open.EgressPosture(); p.Own != nil {
		t.Errorf("an unfiltered network narrows nothing: %+v", p)
	}

	// The hub refuses rules wider than the virtual executor's own firewall
	// before anything is sent.
	wide := executor.FirewallRules{AllowPublicInternet: true, AllowPorts: []int{22}}
	_, err := v.Start(context.Background(), executor.Spec{WorkDir: t.TempDir(), Argv: []string{"true"},
		EgressRules: &wide})
	if !fwpolicy.IsExceeds(err) || !strings.Contains(err.Error(), "vx-fw") {
		t.Fatalf("Start with rules wider than the virtual executor = %v", err)
	}
}
