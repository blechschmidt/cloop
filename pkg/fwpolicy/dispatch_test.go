package fwpolicy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// fakeSource is an in-memory store of the two stored levels.
type fakeSource struct {
	devices  map[string]*Rules
	projects map[string]*Rules
	err      error
}

func (f fakeSource) DeviceFirewall(id string) (*Rules, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.devices[id], nil
}

func (f fakeSource) ProjectFirewall(path string) (*Rules, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.projects[path], nil
}

// fakeExecutor is an executor whose posture a test sets.
type fakeExecutor struct {
	id      string
	posture executor.EgressPosture
}

func (f fakeExecutor) ID() string   { return f.id }
func (f fakeExecutor) Kind() string { return "fake" }
func (f fakeExecutor) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationContainer}
}
func (f fakeExecutor) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, errors.New("not startable")
}
func (f fakeExecutor) Signal(context.Context, string, executor.Signal) error { return nil }
func (f fakeExecutor) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, nil
}
func (f fakeExecutor) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	return nil, errors.New("no stream")
}
func (f fakeExecutor) HealthCheck(context.Context) error { return nil }
func (f fakeExecutor) EgressPosture() executor.EgressPosture {
	p := f.posture
	if p.DeviceID == "" {
		p.DeviceID = f.id
	}
	return p
}

func withSource(t *testing.T, s Source) {
	t.Helper()
	restore := SetSource(s)
	t.Cleanup(restore)
}

var vxFirewall = Rules{
	AllowPublicInternet: true,
	AllowCIDRs:          []string{"10.20.0.0/16"},
	AllowPorts:          []int{80, 443},
	Resolvers:           []string{"1.1.1.1"},
}

func virtualOn(device string, own *Rules) fakeExecutor {
	return fakeExecutor{id: "vx-1", posture: executor.EgressPosture{
		DeviceID: device, Own: own, OwnName: "virtual executor vx-1's firewall",
		Enforceable: true, RemovesNetwork: true,
	}}
}

func TestResolveLeavesAnUnconfiguredWorkloadAlone(t *testing.T) {
	withSource(t, fakeSource{})
	spec := executor.Spec{EgressScope: executor.EgressScopePublic}
	res, err := Resolve(&spec, virtualOn("sgx", &vxFirewall), "/srv/p")
	if err != nil || res.Applied() {
		t.Fatalf("Resolve = %+v, %v", res, err)
	}
	if spec.EgressRules != nil || spec.EgressBound != nil || spec.EgressScope != executor.EgressScopePublic {
		t.Errorf("a workload under no stored rule set must be untouched: %+v", spec)
	}
}

func TestResolveComposesDeviceVirtualAndProject(t *testing.T) {
	device := Rules{AllowPublicInternet: true, AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []int{22, 80, 443},
		DenyCIDRs: []string{"203.0.113.0/24"}, Resolvers: []string{"1.1.1.1", "10.0.0.53"}}
	project := Rules{AllowCIDRs: []string{"10.20.1.0/24"}, AllowPorts: []int{443}, Resolvers: []string{"1.1.1.1"}}
	withSource(t, fakeSource{
		devices:  map[string]*Rules{"sgx": &device},
		projects: map[string]*Rules{"/srv/p": &project},
	})
	spec := executor.Spec{EgressScope: executor.EgressScopePublic}
	res, err := Resolve(&spec, virtualOn("sgx", &vxFirewall), "/srv/p")
	if err != nil {
		t.Fatal(err)
	}
	if spec.EgressRules == nil || spec.EgressBound == nil {
		t.Fatalf("rules and bound must both be set: %+v", spec)
	}
	want, _ := Effective(&device, project)
	if !Equal(*spec.EgressRules, want) {
		t.Errorf("EgressRules = %v, want the project's under the device's denylist (%v)",
			spec.EgressRules.Describe(), want.Describe())
	}
	if !Equal(*spec.EgressBound, device) {
		t.Errorf("EgressBound = %v, want the device's rules", spec.EgressBound.Describe())
	}
	if spec.EgressScope != executor.EgressScopePublic {
		t.Error("the scope must stay on the spec, so a re-composition can fold it in again")
	}
	// Composing again — a failover — gives the same rules.
	again := spec
	again.EgressRules, again.EgressBound = nil, nil
	if _, err := Resolve(&again, virtualOn("sgx", &vxFirewall), "/srv/p"); err != nil ||
		!Equal(*again.EgressRules, *spec.EgressRules) {
		t.Errorf("re-composing gave %v, want %v (%v)", again.EgressRules, spec.EgressRules, err)
	}
	if len(res.Levels) != 4 || !strings.Contains(res.Describe(), "this project's firewall") {
		t.Errorf("resolution = %+v", res)
	}
	if err := CheckAtDriver(spec, &vxFirewall, "vx", "sgx"); err != nil {
		t.Errorf("the driver must accept what dispatch composed: %v", err)
	}
}

func TestResolveRefusesAProjectWiderThanItsVirtualExecutor(t *testing.T) {
	project := Rules{AllowPublicInternet: true, AllowPorts: []int{22}}
	withSource(t, fakeSource{projects: map[string]*Rules{"/srv/p": &project}})
	spec := executor.Spec{}
	_, err := Resolve(&spec, virtualOn("sgx", &vxFirewall), "/srv/p")
	if !IsExceeds(err) || !errors.Is(err, executor.ErrUnsupported) || !strings.Contains(err.Error(), "port 22") {
		t.Fatalf("Resolve = %v, want a containment refusal naming port 22", err)
	}
	if spec.EgressRules != nil {
		t.Error("a refused dispatch must not leave rules on the spec")
	}
}

func TestResolveRefusesAVirtualExecutorWiderThanItsDevice(t *testing.T) {
	device := Rules{AllowCIDRs: []string{"10.20.0.0/16"}, AllowPorts: []int{443}}
	withSource(t, fakeSource{devices: map[string]*Rules{"sgx": &device}})
	spec := executor.Spec{}
	_, err := Resolve(&spec, virtualOn("sgx", &vxFirewall), "/srv/p")
	if !IsExceeds(err) || !strings.Contains(err.Error(), "virtual executor vx-1") {
		t.Fatalf("Resolve = %v, want the virtual executor named as exceeding the device", err)
	}
}

func TestResolveAppliesTheDeviceToAnUnfilteredVirtualExecutor(t *testing.T) {
	device := Rules{AllowPublicInternet: true, AllowPorts: []int{443}, Resolvers: []string{"1.1.1.1"}}
	withSource(t, fakeSource{devices: map[string]*Rules{"sgx": &device}})
	spec := executor.Spec{}
	if _, err := Resolve(&spec, virtualOn("sgx", nil), "/srv/p"); err != nil {
		t.Fatal(err)
	}
	if spec.EgressRules == nil || !Equal(*spec.EgressRules, device) {
		t.Fatalf("an unfiltered level adds no narrowing, so the device's rules apply: %+v", spec.EgressRules)
	}
}

func TestResolveFoldsTheRepositoryScopeIn(t *testing.T) {
	device := Rules{AllowPublicInternet: true, AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []int{443},
		Resolvers: []string{"1.1.1.1"}}
	withSource(t, fakeSource{devices: map[string]*Rules{"sgx": &device}})
	spec := executor.Spec{EgressScope: executor.EgressScopePublic}
	if _, err := Resolve(&spec, virtualOn("sgx", nil), "/srv/p"); err != nil {
		t.Fatal(err)
	}
	want := Rules{AllowPublicInternet: true, AllowPorts: []int{443}, Resolvers: []string{"1.1.1.1"}}
	if !Equal(*spec.EgressRules, want) {
		t.Errorf("egress: public must drop the private range and keep ports and resolvers, got %v",
			spec.EgressRules.Describe())
	}

	// And a scope asking for more than the device grants is refused.
	private := Rules{AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []int{443}}
	withSource(t, fakeSource{devices: map[string]*Rules{"sgx": &private}})
	spec = executor.Spec{EgressScope: executor.EgressScopePublic}
	if _, err := Resolve(&spec, virtualOn("sgx", nil), "/srv/p"); !IsExceeds(err) {
		t.Errorf("egress: public under a private-only device must be refused, got %v", err)
	}
}

func TestResolveRefusesWhatTheExecutorCannotEnforce(t *testing.T) {
	device := Rules{AllowPublicInternet: true, AllowPorts: []int{443}}
	withSource(t, fakeSource{devices: map[string]*Rules{"host": &device}})
	host := fakeExecutor{id: "host", posture: executor.EgressPosture{Reason: "it runs payloads on its host"}}
	spec := executor.Spec{}
	if _, err := Resolve(&spec, host, ""); err == nil || !strings.Contains(err.Error(), "runs payloads on its host") {
		t.Fatalf("Resolve on an executor that cannot enforce = %v", err)
	}

	// Reaching nothing needs no filter, only no network.
	nothing := Rules{}
	withSource(t, fakeSource{devices: map[string]*Rules{"host": &nothing}})
	canDrop := fakeExecutor{id: "host", posture: executor.EgressPosture{RemovesNetwork: true, Reason: "no nft"}}
	spec = executor.Spec{}
	if _, err := Resolve(&spec, canDrop, ""); err != nil {
		t.Fatal(err)
	}
	if !spec.DisableNetwork || spec.EgressRules == nil || spec.EgressRules.HasDestination() {
		t.Errorf("rules reaching nothing must take the network away: %+v", spec)
	}
	spec = executor.Spec{Workspace: executor.Workspace{Kind: executor.WorkspaceGit,
		Repo: "https://github.com/o/r.git"}}
	if _, err := Resolve(&spec, canDrop, ""); err == nil || !strings.Contains(err.Error(), "fetched") {
		t.Errorf("a tree that must be fetched cannot run with no network: %v", err)
	}
}

func TestResolveRefusesAHostInterfaceUnderRules(t *testing.T) {
	device := Rules{AllowPublicInternet: true, AllowPorts: []int{443}}
	withSource(t, fakeSource{devices: map[string]*Rules{"sgx": &device}})
	spec := executor.Spec{Interfaces: []executor.HostInterface{{Name: "lab", Source: "veth-lab"}}}
	if _, err := Resolve(&spec, virtualOn("sgx", nil), ""); err == nil || !strings.Contains(err.Error(), "lab") {
		t.Fatalf("a granted interface is a route around the firewall and must be refused: %v", err)
	}
}

func TestResolveFailsClosedOnAnUnreadableStore(t *testing.T) {
	withSource(t, fakeSource{err: errors.New("disk I/O error")})
	spec := executor.Spec{}
	if _, err := Resolve(&spec, virtualOn("sgx", &vxFirewall), "/srv/p"); err == nil ||
		!strings.Contains(err.Error(), "disk I/O error") {
		t.Fatalf("a store that cannot be read must refuse the dispatch, got %v", err)
	}
	if err := CheckAtDriver(executor.Spec{}, nil, "", "sgx"); err == nil {
		t.Error("the driver must refuse too when it cannot read the device's rules")
	}
}

func TestCheckAtDriverIsAuthoritative(t *testing.T) {
	device := Rules{AllowPublicInternet: true, AllowPorts: []int{443}, Resolvers: []string{"1.1.1.1"}}
	withSource(t, fakeSource{devices: map[string]*Rules{"sgx": &device}})

	// A dispatch path that skipped Resolve: no rules on a device that has some.
	if err := CheckAtDriver(executor.Spec{}, nil, "", "sgx"); err == nil ||
		!strings.Contains(err.Error(), "dispatched without") {
		t.Errorf("a workload dispatched past the device's rules must be refused: %v", err)
	}
	// Rules wider than the stored device rule set, whatever the spec claims the
	// bound was.
	wide := Rules{AllowPublicInternet: true}
	claimed := wide
	spec := executor.Spec{EgressRules: &wide, EgressBound: &claimed}
	if err := CheckAtDriver(spec, nil, "", "sgx"); !IsExceeds(err) {
		t.Errorf("the stored rule set is the authority, not the copy in the spec: %v", err)
	}
	// Rules wider than the executor's own level.
	narrowOwn := Rules{AllowCIDRs: []string{"1.1.1.0/24"}, AllowPorts: []int{443}}
	ok := Rules{AllowPublicInternet: true, AllowPorts: []int{443}}
	spec = executor.Spec{EgressRules: &ok, EgressBound: &device}
	if err := CheckAtDriver(spec, &narrowOwn, "virtual executor vx-1's firewall", "sgx"); !IsExceeds(err) ||
		!strings.Contains(err.Error(), "vx-1") {
		t.Errorf("rules wider than the executor's own firewall must be refused: %v", err)
	}
	// And without a store — an agent on another machine — the spec's bound and
	// the executor's own level still bind.
	restore := SetSource(nil)
	defer restore()
	spec = executor.Spec{EgressRules: &wide, EgressBound: &device}
	if err := CheckAtDriver(spec, nil, "", "sgx"); !IsExceeds(err) {
		t.Errorf("an agent must check the bound the spec carries: %v", err)
	}
	if err := CheckAtDriver(executor.Spec{EgressBound: &device}, nil, "", "sgx"); err == nil {
		t.Error("a bound without rules is malformed and must be refused")
	}
}
