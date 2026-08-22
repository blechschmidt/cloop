package localprocess

// scrub.go lets a caller take an environment-borne credential back out of the
// driver's own memory after a workload has already started.
//
// It exists for lease revocation (Task 20178). When the control plane revokes
// a secret lease mid-run, the material has to stop being reachable everywhere
// it can be reached. This driver holds two copies of it after Start: the
// exec.Cmd's Env, and the Spec it recorded for bookkeeping. Neither is read
// again — the child received its environment at fork time — so both are pure
// retention, and both would keep a revoked credential alive in the hub's or
// the agent's heap for as long as the handle is retained, which is up to
// maxRetainedHandles workloads after the run itself ended.
//
// # What this does and does not guarantee
//
// It drops the driver's references. It does not overwrite the bytes: Go
// strings are immutable, so the only thing available is to replace the slice
// entry and let the garbage collector reclaim the original. A memory dump
// taken in the window before collection can still contain it.
//
// It emphatically does not reach the running child. That process was handed
// its own copy of the environment by the kernel at exec time, and no API can
// take it back — which is precisely why revocation offers a "kill" action
// alongside "scrub". Callers must not describe an env scrub as though the
// running task had lost the credential; see docs/security/model.md.

import (
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// scrubbedValue replaces a revoked variable's value.
//
// The variable is kept rather than removed so that a later reader sees "this
// was taken away" instead of "this was never set". The two call for different
// operator responses, and a bare deletion cannot tell them apart.
const scrubbedValue = "<revoked>"

// ScrubEnv drops the values of the named environment variables from this
// driver's retained copies of handleID's environment, returning the names it
// actually found.
//
// Returning the names rather than a count is what lets a revocation ack say
// which credentials were reached. A caller that asked for three and got one
// back knows the other two were never here, which is a different situation
// from a scrub that failed.
//
// Unknown handles and unknown keys are not errors: both mean "that material
// is not here", which is the end state a revocation wants.
func (e *Executor) ScrubEnv(handleID string, keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	want := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		if k = strings.TrimSpace(k); k != "" {
			want[k] = struct{}{}
		}
	}
	if len(want) == 0 {
		return nil
	}

	e.mu.Lock()
	rec, ok := e.handles[handleID]
	e.mu.Unlock()
	if !ok {
		return nil
	}

	// rec.mu is the handle's own lock, held by every state transition. Taking
	// it here is what makes the scrub safe against a concurrent Signal or
	// Status on the same handle rather than a data race the race detector
	// would find only under load.
	rec.mu.Lock()
	defer rec.mu.Unlock()

	found := make(map[string]struct{}, len(want))
	if rec.cmd != nil {
		rec.cmd.Env = scrubEnvSlice(rec.cmd.Env, want, found)
	}
	rec.spec.Env = scrubEnvSlice(rec.spec.Env, want, found)

	out := make([]string, 0, len(found))
	for _, k := range keys {
		if _, ok := found[strings.TrimSpace(k)]; ok {
			out = append(out, strings.TrimSpace(k))
			delete(found, strings.TrimSpace(k))
		}
	}
	return out
}

// scrubEnvSlice replaces the values of matching "K=V" entries in place,
// recording which keys were hit.
//
// It rewrites rather than filters so the slice's length and the position of
// every other variable are unchanged: a caller holding an index into this
// environment (nothing does today, but the cost of not surprising one later
// is a single assignment) keeps pointing at the same variable.
func scrubEnvSlice(env []string, want, found map[string]struct{}) []string {
	for i, kv := range env {
		key, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if _, hit := want[key]; !hit {
			continue
		}
		found[key] = struct{}{}
		env[i] = key + "=" + scrubbedValue
	}
	return env
}

// ScrubSpecSecrets scrubs every environment variable a spec's secret bindings
// contributed, for callers that have the spec rather than a key list.
func (e *Executor) ScrubSpecSecrets(handleID string, bindings []executor.SecretBinding) []string {
	var keys []string
	for _, b := range bindings {
		keys = append(keys, b.EnvKeys...)
	}
	return e.ScrubEnv(handleID, keys)
}
