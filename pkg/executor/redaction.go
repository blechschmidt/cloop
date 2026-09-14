package executor

// redaction.go answers one question for a driver: which byte sequences must
// never appear in the output it captures.
//
// # Why the driver is the right place to ask
//
// The hub mints a lease and hands the material to an executor. From that moment
// the executor is the only party that holds both the credential *and* the
// workload's output — the broker has forgotten the plaintext, and the consumers
// downstream (the artifact writer, the live-log room, the audit trail) never
// had it. So the driver is where a value and its appearance in a transcript can
// be matched, and it is the last place before that transcript becomes durable.
//
// pkg/audit scans artifacts for leaked credentials after the fact, which is the
// admission that this leak was expected. Scrubbing here is what makes that scan
// find nothing.
//
// # Why not every lease variable
//
// A lease injects credentials *and* the constraints they were narrowed to:
// GITHUB_TOKEN next to CLOOP_GITHUB_REPO_ALLOWLIST, KUBECONFIG next to
// CLOOP_K8S_NAMESPACE. Redacting the second kind would replace a repository
// name or a namespace — strings that legitimately recur all over a task's
// output — with a marker, turning a readable transcript into noise and teaching
// operators to distrust the marker. So only the values the broker declared
// sensitive are matched; see redact.EnvKey for how that declaration travels.

import (
	"strings"

	"github.com/blechschmidt/cloop/pkg/redact"
)

// SecretValues returns the plaintext this Spec carries into the workload, for a
// driver to scrub out of the output it captures.
//
// Two sources, matching the two ways material reaches a workload:
//
//   - SecretFiles, when the driver places the bytes itself (a container's
//     staged tmpfs, a projected Kubernetes Secret, a remote agent's vault).
//   - Env, for the variables the lease declared credential-bearing.
//
// A localprocess workload has neither: the hub materialised the files on the
// shared filesystem, so Spec.SecretFiles is empty and only the paths travel.
// That case is covered on the other side of the boundary, where the workload
// reads its own lease directory — see redact.FromEnviron. Both halves exist
// because output is captured on both sides.
func (s Spec) SecretValues() []string {
	var out []string
	for _, f := range s.SecretFiles {
		out = append(out, redact.Values(f.Content)...)
	}
	out = append(out, sensitiveEnvValues(s.Env)...)
	return out
}

// Redactor returns a redact.Set over SecretValues, or nil when this Spec
// carries no credential — which lets a driver install it unconditionally.
func (s Spec) Redactor() *redact.Set {
	return redact.New(s.SecretValues()...)
}

// sensitiveEnvValues resolves the names in redact.EnvKey against env and
// returns their values.
//
// Later entries win, because Spec.Env is built by appending the lease's
// variables onto an inherited base and the exec semantics every driver relies
// on take the last assignment.
func sensitiveEnvValues(env []string) []string {
	if len(env) == 0 {
		return nil
	}
	lookup := make(map[string]string, len(env))
	for _, kv := range env {
		if eq := strings.IndexByte(kv, '='); eq > 0 {
			lookup[kv[:eq]] = kv[eq+1:]
		}
	}
	declared := lookup[redact.EnvKey]
	if declared == "" {
		return nil
	}
	var out []string
	for _, name := range strings.Split(declared, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if v, ok := lookup[name]; ok && v != "" {
			out = append(out, v)
		}
	}
	return out
}
