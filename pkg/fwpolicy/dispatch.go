package fwpolicy

// dispatch.go composes the levels for one workload (the dispatch-time check)
// and gives drivers the check they make before installing anything (the
// authoritative one).
//
// The save-time check lives with the forms in pkg/ui. It is the one that puts
// the error where the person who typed the range is looking, but it can only
// test against the executor a project resolves to *then*; a project can be
// rebound, a device tightened or a virtual executor edited at any point after.
// So the containment is proven three times, and only the last proof — in the
// driver, against what the driver itself knows — is the one the guarantee rests
// on.

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// Source reads the two stored levels: a device's rule set and a project's.
//
// nil from either means "no rule set stored", and an error means the store
// could not be read — which every caller here treats as a refusal, never as
// "no rules": a decode fault that read as absence would widen a firewall.
type Source interface {
	DeviceFirewall(executorID string) (*Rules, error)
	ProjectFirewall(projectPath string) (*Rules, error)
}

var (
	sourceMu sync.RWMutex
	source   Source
)

// SetSource installs the store Resolve and CheckAtDriver read, returning a
// function that restores the previous one. A process with no control plane —
// `cloop run` on a laptop, an executor agent — installs none, and then no stored
// level exists.
func SetSource(s Source) (restore func()) {
	sourceMu.Lock()
	prev := source
	source = s
	sourceMu.Unlock()
	return func() {
		sourceMu.Lock()
		source = prev
		sourceMu.Unlock()
	}
}

func currentSource() Source {
	sourceMu.RLock()
	defer sourceMu.RUnlock()
	return source
}

// Level is one link of the chain, outermost first.
type Level struct {
	// Kind is "config", "device", "own", "scope" or "project".
	Kind string `json:"kind"`
	// Name says where the rules came from, in a sentence.
	Name string `json:"name"`
	// Rules is nil when this level adds no narrowing.
	Rules *Rules `json:"rules,omitempty"`
}

// ExceedsError reports one level reaching further than the level it must fit
// inside. It unwraps to executor.ErrUnsupported, the refusal a dispatch that
// cannot be honoured as configured has always returned.
type ExceedsError struct {
	Level   string
	Bound   string
	Reasons []string
}

func (e *ExceedsError) Error() string {
	return fmt.Sprintf("%s: %s reaches further than %s permits: %s", executor.ErrUnsupported,
		e.Level, e.Bound, strings.Join(e.Reasons, "; "))
}

func (e *ExceedsError) Unwrap() error { return executor.ErrUnsupported }

// Chain composes levels outermost first, proving each fits inside the
// effective rule set of the levels above it. It returns the innermost
// effective rule set, or nil when no level sets one.
func Chain(levels []Level) (*Rules, error) {
	var cur *Rules
	curName := ""
	for _, l := range levels {
		if l.Rules == nil {
			continue
		}
		if cur != nil {
			if reasons := Permits(cur, *l.Rules); len(reasons) > 0 {
				return nil, &ExceedsError{Level: l.Name, Bound: curName, Reasons: reasons}
			}
		}
		eff, err := Effective(cur, *l.Rules)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", l.Name, err)
		}
		cur, curName = &eff, l.Name
	}
	return cur, nil
}

// Resolution is what Resolve decided, for the run's event log.
type Resolution struct {
	Levels    []Level
	Effective *Rules
	Bound     *Rules
}

// Applied reports whether a stored level shaped the workload.
func (r Resolution) Applied() bool { return r.Effective != nil }

// Describe names the levels and what came out of them, in one line.
func (r Resolution) Describe() string {
	if !r.Applied() {
		return ""
	}
	var names []string
	for _, l := range r.Levels {
		if l.Rules != nil {
			names = append(names, l.Name)
		}
	}
	return fmt.Sprintf("firewall: %s (from %s)", Describe(r.Effective), strings.Join(names, ", then "))
}

// Resolve composes the firewall levels for one workload on ex and records the
// result on spec: the dispatch-time check.
//
// A workload under no stored rule set — no device rules, no project rules — is
// left exactly as it was, so every executor keeps the behaviour it had before
// these levels existed, down to the bridge its sandboxes join. Otherwise the
// chain is proven level by level; a level that reaches further than the one
// above it, a store that cannot be read, or an executor that cannot enforce
// the result each refuse the dispatch, because starting a sandbox whose
// firewall could not be established is the failure this exists to prevent.
func Resolve(spec *executor.Spec, ex executor.Executor, projectPath string) (Resolution, error) {
	src := currentSource()
	if src == nil || ex == nil || spec == nil {
		return Resolution{}, nil
	}
	pos := executor.PostureOf(ex)
	device, err := src.DeviceFirewall(pos.DeviceID)
	if err != nil {
		return Resolution{}, fmt.Errorf("%w: device %s's firewall rules could not be read, so this run "+
			"cannot be confined as configured: %v", executor.ErrUnsupported, pos.DeviceID, err)
	}
	var project *Rules
	if strings.TrimSpace(projectPath) != "" {
		if project, err = src.ProjectFirewall(projectPath); err != nil {
			return Resolution{}, fmt.Errorf("%w: this project's firewall rules could not be read, so this "+
				"run cannot be confined as configured: %v", executor.ErrUnsupported, err)
		}
	}
	if device == nil && project == nil {
		return Resolution{}, nil
	}

	levels := []Level{
		{Kind: "config", Name: "executor " + ex.ID() + "'s configuration", Rules: pos.Config},
		{Kind: "device", Name: "device " + pos.DeviceID + "'s firewall", Rules: device},
		{Kind: "own", Name: ownName(pos), Rules: pos.Own},
	}
	cur, err := Chain(levels)
	if err != nil {
		return Resolution{}, err
	}
	if project != nil {
		// The dashboard's rule set supersedes the repo's coarse scope: both can
		// only narrow, and this one is the more specific statement, made by an
		// identity the hub authenticated.
		levels = append(levels, Level{Kind: "project", Name: "this project's firewall", Rules: project})
		if cur, err = Chain(levels); err != nil {
			return Resolution{}, err
		}
	} else if spec.EgressScope == executor.EgressScopePublic {
		// The repo's `egress: public`, as a level: the public Internet on the
		// ports and through the resolvers the levels above already allow.
		scope := Rules{AllowPublicInternet: true, AllowPorts: cur.AllowPorts, Resolvers: cur.Resolvers}
		levels = append(levels, Level{Kind: "scope",
			Name: "this project's .cloop/sandbox.yaml (egress: public)", Rules: &scope})
		if cur, err = Chain(levels); err != nil {
			return Resolution{}, err
		}
	}
	spec.EgressScope = executor.EgressScopeUnset

	if len(spec.Interfaces) > 0 {
		return Resolution{}, fmt.Errorf("%w: this run is bounded by firewall rules stored in the hub, but "+
			"it was also granted host interface(s) %s, which the firewall cannot filter. Withdraw the "+
			"host_interface grant, or clear the device's and the project's firewall rules",
			executor.ErrUnsupported, strings.Join(executor.InterfaceNames(spec.Interfaces), ", "))
	}

	switch {
	case spec.DisableNetwork:
		// The spec already gives up the network; the rules can only agree.
		cur = &Rules{}
	case cur.HasDestination():
		if !pos.Enforceable {
			return Resolution{}, fmt.Errorf("%w: this run is bounded by %s, but %s; refusing rather than "+
				"running it unfiltered. Bind the project to an executor that can enforce the rules, or "+
				"clear them", executor.ErrUnsupported, describeLevels(levels), pos.Reason)
		}
	default:
		// The rules reach nothing. That needs no packet filter, only no
		// network — which any container can be given.
		if !pos.RemovesNetwork && !pos.Enforceable {
			return Resolution{}, fmt.Errorf("%w: the firewall rules for this run (%s) allow no "+
				"destination, but %s", executor.ErrUnsupported, describeLevels(levels), pos.Reason)
		}
		if spec.Workspace.NeedsProvisioning() {
			return Resolution{}, fmt.Errorf("%w: the firewall rules for this run (%s) allow no "+
				"destination, but its source tree has to be fetched from %s first",
				executor.ErrUnsupported, describeLevels(levels), spec.Workspace.Host())
		}
		spec.DisableNetwork = true
	}

	eff := *cur
	spec.EgressRules = &eff
	spec.EgressBound = nil
	if device != nil {
		b, err := device.Normalize()
		if err != nil {
			return Resolution{}, fmt.Errorf("%w: device %s's firewall rules are unreadable: %v",
				executor.ErrUnsupported, pos.DeviceID, err)
		}
		spec.EgressBound = &b
	}
	return Resolution{Levels: levels, Effective: &eff, Bound: spec.EgressBound}, nil
}

// CheckAtDriver is the proof a driver makes immediately before it installs a
// workload's network, against everything it knows bounds that workload: its
// own configured level (own), the device's rule set the dispatch carried, and
// — in a process that holds the control plane — the device's rule set as it is
// stored right now.
//
// The last is what makes this authoritative rather than a repeat of the
// dispatch step. A dispatch path that never ran Resolve, or ran it before an
// admin tightened the device, hands the driver a Spec this check reads fresh
// against the store; and an agent on another machine, which has no store,
// still proves the rules against the bound in the Spec and its own firewall
// before it installs a single rule.
func CheckAtDriver(spec executor.Spec, own *Rules, ownName, deviceID string) error {
	var stored *Rules
	if src := currentSource(); src != nil && strings.TrimSpace(deviceID) != "" {
		s, err := src.DeviceFirewall(deviceID)
		if err != nil {
			return fmt.Errorf("%w: device %s's firewall rules could not be read, so this workload cannot "+
				"be proven to fit inside them: %v", executor.ErrUnsupported, deviceID, err)
		}
		stored = s
	}
	if spec.EgressRules == nil {
		if spec.EgressBound != nil {
			return fmt.Errorf("%w: the workload carries a device firewall bound but no firewall rules",
				executor.ErrInvalidSpec)
		}
		if stored != nil {
			return fmt.Errorf("%w: device %s has firewall rules, but this workload was dispatched without "+
				"them; refusing rather than starting it outside them", executor.ErrUnsupported, deviceID)
		}
		return nil
	}
	if ownName == "" {
		ownName = "this executor's own firewall"
	}
	for _, b := range []struct {
		name string
		r    *Rules
	}{
		{ownName, own},
		{"the device firewall the dispatch carried", spec.EgressBound},
		{"device " + deviceID + "'s firewall", stored},
	} {
		if b.r == nil {
			continue
		}
		if reasons := Permits(b.r, *spec.EgressRules); len(reasons) > 0 {
			return &ExceedsError{Level: "this workload's firewall rules", Bound: b.name, Reasons: reasons}
		}
	}
	return nil
}

// IsExceeds reports whether err is a containment refusal.
func IsExceeds(err error) bool {
	var e *ExceedsError
	return errors.As(err, &e)
}

func ownName(p executor.EgressPosture) string {
	if p.OwnName != "" {
		return p.OwnName
	}
	return "the executor's own network"
}

func describeLevels(levels []Level) string {
	var names []string
	for _, l := range levels {
		if l.Rules != nil {
			names = append(names, l.Name)
		}
	}
	if len(names) == 0 {
		return "no stored rules"
	}
	return strings.Join(names, " and ")
}

// NetworkLevel is the level a sandbox network amounts to: an empty rule set
// for no network, nil for an unfiltered one — the engine's bridge or a named
// network — which narrows nothing.
func NetworkLevel(network string) *Rules {
	switch strings.TrimSpace(network) {
	case "", executor.SandboxNetworkNone:
		return &Rules{}
	default:
		return nil
	}
}

// VirtualLevel is a virtual executor's own level: its firewall, or the network
// its sandboxes get when it has none.
func VirtualLevel(vs executor.VirtualSpec) *Rules {
	if vs.Firewall != nil {
		fw := *vs.Firewall
		return &fw
	}
	return NetworkLevel(vs.Sandbox.Network)
}
