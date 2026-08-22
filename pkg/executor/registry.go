package executor

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Registry is a thread-safe set of registered executors plus the policy for
// deciding which one a given project runs on.
//
// Two layers of binding exist:
//
//   - an in-memory binding map, authoritative and cheap, used for tests and
//     for bindings applied at runtime; and
//   - an optional persistent lookup (SetBindingLookup) that reads the
//     project→executor binding out of statedb. The registry takes a function
//     rather than a *statedb.DB so this package stays free of storage
//     dependencies and remains importable from anywhere.
//
// Resolution order for Resolve(projectPath):
//
//	in-memory binding → persistent binding → default executor
//
// A binding that names an unregistered executor is a hard error, never a
// silent fallback to the default. See the package doc for why.
type Registry struct {
	mu        sync.RWMutex
	executors map[string]Executor
	bindings  map[string]string // canonical project path → executor ID
	defaultID string
	lookup    func(projectPath string) (string, bool)
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		executors: make(map[string]Executor),
		bindings:  make(map[string]string),
	}
}

// DefaultRegistry is the process-wide registry. Drivers register into it at
// startup (see pkg/executor/localprocess.Ensure) and the package-level
// helpers below operate on it.
var DefaultRegistry = NewRegistry()

// Register adds ex to the registry. The first executor registered also
// becomes the default, so a process that only ever configures one backend
// needs no extra wiring. Returns ErrAlreadyRegistered if the ID is taken.
//
// Under strict no-host-execution mode a driver that offers no isolation is
// refused outright, with a *HostExecutionDeniedError. Resolve and the driver's
// own Start both refuse such an executor too, so this is defense in depth
// rather than the only gate — but it is the layer that matters most, because
// an executor that was never registered cannot become the registry's default.
// Without it, a project with no explicit binding falls back to Default() and
// gets the host driver, which then refuses at Start: a confusing late failure
// where the honest answer is that no executor is available at all.
func (r *Registry) Register(ex Executor) error {
	if ex == nil {
		return fmt.Errorf("%w: nil executor", ErrInvalidSpec)
	}
	id := strings.TrimSpace(ex.ID())
	if id == "" {
		return fmt.Errorf("%w: executor ID is blank", ErrInvalidSpec)
	}
	if !HostExecutionAllowed() && !isolatesFromHost(ex) {
		return &HostExecutionDeniedError{
			ExecutorID:   id,
			Alternatives: r.IsolatedIDs(),
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.executors[id]; exists {
		return fmt.Errorf("%w: %q", ErrAlreadyRegistered, id)
	}
	r.executors[id] = ex
	if r.defaultID == "" {
		r.defaultID = id
	}
	return nil
}

// Ensure registers ex unless an executor with the same ID is already
// present, in which case it is a no-op. Useful for idempotent bootstrap
// paths that may run from several entry points (CLI, UI server, tests).
func (r *Registry) Ensure(ex Executor) error {
	err := r.Register(ex)
	if err != nil && strings.Contains(err.Error(), ErrAlreadyRegistered.Error()) {
		return nil
	}
	return err
}

// Unregister removes the executor with the given ID. If it was the default,
// the default is reassigned deterministically (lowest remaining ID) so the
// registry never silently becomes defaultless while executors remain.
func (r *Registry) Unregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.executors, id)
	if r.defaultID != id {
		return
	}
	r.defaultID = ""
	ids := make([]string, 0, len(r.executors))
	for k := range r.executors {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	if len(ids) > 0 {
		r.defaultID = ids[0]
	}
}

// Get returns the executor with the given ID, or ErrExecutorNotFound.
func (r *Registry) Get(id string) (Executor, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ex, ok := r.executors[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrExecutorNotFound, id)
	}
	return ex, nil
}

// List returns every registered executor, ordered by ID for stable output.
func (r *Registry) List() []Executor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.executors))
	for id := range r.executors {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Executor, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.executors[id])
	}
	return out
}

// SetDefault marks id as the fallback executor for projects with no
// binding. The executor must already be registered.
func (r *Registry) SetDefault(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.executors[id]; !ok {
		return fmt.Errorf("%w: %q", ErrExecutorNotFound, id)
	}
	r.defaultID = id
	return nil
}

// DefaultID returns the current default executor ID, or "" when none is set.
func (r *Registry) DefaultID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.defaultID
}

// Default returns the fallback executor, or ErrNoDefault.
func (r *Registry) Default() (Executor, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.defaultID == "" {
		return nil, ErrNoDefault
	}
	ex, ok := r.executors[r.defaultID]
	if !ok {
		// Registry corruption: default points at a removed executor.
		return nil, fmt.Errorf("%w: default %q", ErrExecutorNotFound, r.defaultID)
	}
	return ex, nil
}

// Bind pins a project path to a specific executor ID. The executor need not
// be registered yet — bindings are configuration and may be restored from
// storage before drivers finish connecting — but Resolve will fail until it
// is. Pass an empty executorID to clear the binding.
func (r *Registry) Bind(projectPath, executorID string) error {
	key := canonicalProjectKey(projectPath)
	if key == "" {
		return fmt.Errorf("%w: project path is blank", ErrInvalidSpec)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if strings.TrimSpace(executorID) == "" {
		delete(r.bindings, key)
		return nil
	}
	r.bindings[key] = executorID
	return nil
}

// Unbind removes any in-memory binding for projectPath.
func (r *Registry) Unbind(projectPath string) {
	key := canonicalProjectKey(projectPath)
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.bindings, key)
}

// Binding returns the executor ID bound to projectPath and whether one
// exists, consulting the in-memory map first and then the persistent
// lookup.
func (r *Registry) Binding(projectPath string) (string, bool) {
	key := canonicalProjectKey(projectPath)
	r.mu.RLock()
	id, ok := r.bindings[key]
	lookup := r.lookup
	r.mu.RUnlock()
	if ok {
		return id, true
	}
	if lookup == nil || key == "" {
		return "", false
	}
	// Called without the lock held: the lookup hits storage and must not
	// serialize unrelated registry reads, nor deadlock if it re-enters.
	if id, ok := lookup(key); ok && strings.TrimSpace(id) != "" {
		return id, true
	}
	return "", false
}

// SetBindingLookup installs the persistent project→executor resolver.
// Pass nil to remove it.
func (r *Registry) SetBindingLookup(fn func(projectPath string) (string, bool)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookup = fn
}

// IsolatedIDs returns the IDs of registered executors that put some boundary
// between a workload and the control-plane host, ordered by ID.
//
// It exists so a host-execution refusal can name concrete alternatives rather
// than telling the operator to go read the docs.
func (r *Registry) IsolatedIDs() []string {
	var out []string
	for _, ex := range r.List() {
		if isolatesFromHost(ex) {
			out = append(out, ex.ID())
		}
	}
	return out
}

// Resolve returns the executor that should run work for projectPath.
//
// It fails closed in two ways:
//
//   - if the project is bound to an executor that is not registered, the
//     error is ErrExecutorNotFound. Downgrading such a project to the default
//     (typically the local host) would defeat the entire point of binding it
//     to an isolated backend; and
//   - if strict no-host-execution mode is on and the resolved executor offers
//     no isolation, the error is *HostExecutionDeniedError. Resolve is the
//     chokepoint every UI code path funnels through, which is what lets one
//     config flag turn "the UI may not spawn harnesses on the host" from a
//     convention into an invariant.
func (r *Registry) Resolve(projectPath string) (Executor, error) {
	ex, err := r.resolveBinding(projectPath)
	if err != nil {
		return nil, err
	}
	if !HostExecutionAllowed() && !isolatesFromHost(ex) {
		return nil, &HostExecutionDeniedError{
			ExecutorID:   ex.ID(),
			ProjectPath:  projectPath,
			Alternatives: r.IsolatedIDs(),
		}
	}
	return ex, nil
}

// resolveBinding is Resolve without the host-execution policy check, so
// callers that only want to know *which* executor a project points at (the
// Executors panel, `cloop executor list`) are not told it is forbidden.
func (r *Registry) resolveBinding(projectPath string) (Executor, error) {
	if id, ok := r.Binding(projectPath); ok {
		ex, err := r.Get(id)
		if err != nil {
			return nil, fmt.Errorf("project %q is bound to executor %q which is not available: %w",
				projectPath, id, err)
		}
		return ex, nil
	}
	return r.Default()
}

// canonicalProjectKey normalizes a project path for use as a binding key so
// that "/srv/proj", "/srv/proj/", and "/srv/./proj" all agree. Symlinks are
// deliberately not resolved: bindings are configuration keyed by the path
// the operator typed, and resolving would make the key depend on filesystem
// state that may not exist yet.
func canonicalProjectKey(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if abs, err := filepath.Abs(p); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(p)
}

// Package-level helpers operating on DefaultRegistry. These are what callers
// outside this package normally use.

// Register adds ex to the default registry.
func Register(ex Executor) error { return DefaultRegistry.Register(ex) }

// Ensure idempotently adds ex to the default registry.
func Ensure(ex Executor) error { return DefaultRegistry.Ensure(ex) }

// Get returns the executor with the given ID from the default registry.
func Get(id string) (Executor, error) { return DefaultRegistry.Get(id) }

// List returns every executor in the default registry.
func List() []Executor { return DefaultRegistry.List() }

// Resolve returns the executor bound to projectPath in the default
// registry, falling back to the default executor.
func Resolve(projectPath string) (Executor, error) { return DefaultRegistry.Resolve(projectPath) }

// ResolveBinding is Resolve without the host-execution policy check: it
// answers "which executor is this project pointing at", which the Executors
// panel needs even for a binding that policy currently forbids running.
func ResolveBinding(projectPath string) (Executor, error) {
	return DefaultRegistry.resolveBinding(projectPath)
}

// IsolatedIDs returns the isolating executors registered in the default
// registry.
func IsolatedIDs() []string { return DefaultRegistry.IsolatedIDs() }

// Bind pins projectPath to executorID in the default registry.
func Bind(projectPath, executorID string) error { return DefaultRegistry.Bind(projectPath, executorID) }

// SetBindingLookup installs the persistent binding resolver on the default
// registry.
func SetBindingLookup(fn func(projectPath string) (string, bool)) {
	DefaultRegistry.SetBindingLookup(fn)
}
