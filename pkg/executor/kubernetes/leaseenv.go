package kubernetes

// leaseenv.go delivers a workload's environment into its Pod by reference.
//
// # The exposure it removes
//
// Every value in Spec.Env used to land in the Pod object as a plain `value:`,
// and Spec.Env is where a lease puts the credentials it delivers as
// environment: every key of an env secret — including the harness login,
// CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY, which is the only way a Pod gets
// one — GITHUB_TOKEN and GH_TOKEN for a grant over every repository, an egress
// grant's proxy URLs, and the egress session's http://<id>:<token>@host:port in
// all four proxy variables. A Pod object is readable by every identity with
// `get pods` in the namespace, printed by every `kubectl describe`, and written
// to the API server's audit log. The threat model recorded it as not mitigated.
//
// Now the values travel in the run's lease Secret — cloop-lease-<handle>, the
// object secretfiles.go already creates for credential files — one key per
// variable, and the harness container names each with an explicit
// valueFrom.secretKeyRef. The Pod object carries the names and the reference;
// the kubelet resolves the values into the container's environment when it
// creates the container, and the API server never stores them in the Pod.
//
// # Every value, not only the sensitive ones
//
// redact.EnvKey says which values a lease declared sensitive, and those would
// be the minimum to move. Everything moves instead, because that closes a class
// rather than a list: a variable a future grant forgets to declare is protected
// anyway, and a constraint like CLOOP_GITHUB_REPO_ALLOWLIST loses nothing by
// being read from a Secret.
//
// GIT_CONFIG_COUNT is the one exception, and it is not a value the Spec gets to
// keep: buildPod numbers its own git configuration — the workspace trust and
// the CA bundle — after the Spec's entries and writes the total itself, as a
// plain value, because a count of entries is not a credential.
//
// # Not envFrom
//
// envFrom would import every key of the Secret as an environment variable —
// the d<N>.<file> keys too, putting a kubeconfig or a GitHub token file into the
// environment of every process the harness spawns, which is the copy a file
// delivery exists to avoid. One explicit reference per variable imports exactly
// the Spec's environment and nothing else.
//
// # When the Secret has to exist
//
// A secretKeyRef is resolved when the kubelet creates the container, not when
// the Pod is admitted, so the Secret has to outlive the moment the harness
// container starts — which, behind a workspace fetch, can be minutes after the
// Pod does. finish keeps it until then (see record.harnessStarted), and a
// container the kubelet cannot create because the Secret is gone fails the run
// by name instead of leaving it pending forever (see configerror.go).

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// envSecretKeyPrefix namespaces the environment's keys in the lease Secret.
//
// The Secret also holds credential files under d<N>.<name> (secretFileKey), and
// the two must not collide; they cannot, because a file key starts with "d" and
// a digit. The prefix also keeps the reference legible: `kubectl describe pod`
// prints <set to the key 'env.GITHUB_TOKEN' in secret 'cloop-lease-…'>, which
// says both where the value lives and that it is the environment, not a file.
const envSecretKeyPrefix = "env."

// maxSecretKeyLen is the API server's cap on a Secret data key.
const maxSecretKeyLen = 253

// gitConfigCountVar is the one Spec variable buildPod rewrites rather than
// forwards. See the file comment.
const gitConfigCountVar = "GIT_CONFIG_COUNT"

// envSecretKey renders the Secret key one variable is stored under.
func envSecretKey(name string) string { return envSecretKeyPrefix + name }

// leaseEnvVar is one variable the harness reads from the lease Secret.
type leaseEnvVar struct {
	name  string
	value string
	key   string
}

// String renders the variable without its value, so a %v on a plan cannot put
// a live credential into a log line — the same promise executor.SecretFile
// makes for file content.
func (v leaseEnvVar) String() string {
	return fmt.Sprintf("env %s from key %s (%d bytes) [redacted]", v.name, v.key, len(v.value))
}

// GoString mirrors String so %#v cannot print the value either.
func (v leaseEnvVar) GoString() string { return v.String() }

// leaseEnvPlan is the single derivation of which variables travel in the lease
// Secret and under which keys.
//
// It exists for the reason secretFilePlan does: the Secret's data and the Pod's
// references are built by two different functions, called from two different
// places — the create path and the pure buildPod — and a disagreement between
// them would fail nothing at admission. The kubelet would refuse to create the
// harness container over a key the Secret does not carry, long after Start had
// reported success.
type leaseEnvPlan struct {
	// vars are the Spec's variables, sorted by name, GIT_CONFIG_COUNT
	// excluded.
	vars []leaseEnvVar
	// gitConfigCount is the GIT_CONFIG_COUNT the Spec declared, and
	// hasGitConfigCount whether it declared one at all.
	gitConfigCount    int
	hasGitConfigCount bool
}

// planLeaseEnv validates a Spec's environment and works out where each value
// goes. A nil plan and nil error mean there is no environment at all.
//
// The checks are the ones buildPod always made, with the messages it always
// made them with: K=V form, a name Kubernetes accepts, each name once — the API
// server rejects a duplicate with a validation error that does not name it —
// and a GIT_CONFIG_COUNT that is a count, because buildPod numbers its own
// entries after it.
func planLeaseEnv(env []string) (*leaseEnvPlan, error) {
	if len(env) == 0 {
		return nil, nil
	}
	plan := &leaseEnvPlan{vars: make([]leaseEnvVar, 0, len(env))}
	seen := make(map[string]struct{}, len(env))
	for n, kv := range env {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			// Not quoted back: an entry with no name may be a value that lost
			// it, and the value is the one thing that must not reach an error
			// string. Its position is enough to find it.
			return nil, fmt.Errorf("%w: env entry %d of %d (%d bytes) is not in K=V form",
				executor.ErrInvalidSpec, n+1, len(env), len(kv))
		}
		name, value := kv[:i], kv[i+1:]
		if !validEnvName(name) {
			return nil, fmt.Errorf("%w: env name %q is not a valid Kubernetes env var name", executor.ErrInvalidSpec, name)
		}
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("%w: env %q is set more than once", executor.ErrInvalidSpec, name)
		}
		seen[name] = struct{}{}

		if name == gitConfigCountVar {
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || n < 0 {
				return nil, fmt.Errorf("%w: GIT_CONFIG_COUNT %q in the workload's environment is not a count",
					executor.ErrInvalidSpec, value)
			}
			plan.gitConfigCount, plan.hasGitConfigCount = n, true
			continue
		}
		key := envSecretKey(name)
		if len(key) > maxSecretKeyLen || !validSecretKeyName(key) {
			// validEnvName admits only characters a Secret key allows, so
			// this is the length cap in practice. Refused here, naming the
			// variable, rather than by the API server naming a field path.
			return nil, fmt.Errorf("%w: env name %q is too long to be carried in a Secret "+
				"(a key may be at most %d characters)", executor.ErrInvalidSpec, name, maxSecretKeyLen)
		}
		plan.vars = append(plan.vars, leaseEnvVar{name: name, value: value, key: key})
	}
	// Deterministic order so two identical Specs produce identical Pods, which
	// is what makes buildPod testable by golden comparison.
	sort.Slice(plan.vars, func(a, b int) bool { return plan.vars[a].name < plan.vars[b].name })
	return plan, nil
}

// leaseEnvData renders the Secret entries carrying a Spec's environment, keyed
// by the plan. Nil when there are none.
func leaseEnvData(env []string) (map[string][]byte, error) {
	plan, err := planLeaseEnv(env)
	if err != nil || plan == nil || len(plan.vars) == 0 {
		return nil, err
	}
	data := make(map[string][]byte, len(plan.vars))
	for _, v := range plan.vars {
		// []byte(""), never nil: encoding/json renders a nil slice as null,
		// and an empty value is a legitimate thing for a variable to hold.
		data[v.key] = append([]byte{}, v.value...)
	}
	return data, nil
}

// harnessEnv renders the harness container's environment: every Spec variable
// by reference to the lease Secret, then the driver's own git configuration —
// gitPairs, numbered after the Spec's GIT_CONFIG_* entries — as plain values,
// with GIT_CONFIG_COUNT covering both.
//
// The plain values are what buildPod itself decided from configuration that is
// not secret: a path the workspace volume is mounted at, a CA bundle's path and
// the URL it is for. Everything the Spec carried — which is everything a lease
// carried — arrives through secretName.
func harnessEnv(secretName string, env []string, gitPairs [][2]string) ([]envVar, error) {
	plan, err := planLeaseEnv(env)
	if err != nil {
		return nil, err
	}
	if plan == nil {
		plan = &leaseEnvPlan{}
	}

	out := make([]envVar, 0, len(plan.vars)+2*len(gitPairs)+1)
	if len(plan.vars) > 0 {
		name := strings.TrimSpace(secretName)
		if name == "" {
			// The values exist and there is nowhere to read them from. Writing
			// them inline instead is the exposure this file exists to remove,
			// so this is fatal — and a spec error, because the caller built a
			// request that cannot be honoured.
			return nil, fmt.Errorf("%w: %d environment variable(s) to deliver but no Secret to "+
				"read them from", executor.ErrInvalidSpec, len(plan.vars))
		}
		if err := validateDNSSubdomain(name, "secret lease secret"); err != nil {
			return nil, fmt.Errorf("%w: %v", executor.ErrInvalidSpec, err)
		}
		for _, v := range plan.vars {
			out = append(out, envVar{
				Name: v.name,
				ValueFrom: &envVarSource{SecretKeyRef: &secretKeySelector{
					Name: name,
					Key:  v.key,
					// Explicitly not optional. An optional reference to a
					// missing key starts the container without the variable
					// — a harness that runs and fails to authenticate for a
					// reason nothing names. A required one holds the
					// container, and configerror.go turns that into a failure
					// that names the Secret.
					Optional: boolPtr(false),
				}},
			})
		}
	}

	n := plan.gitConfigCount
	for i, kv := range gitPairs {
		idx := strconv.Itoa(n + i)
		out = append(out,
			envVar{Name: "GIT_CONFIG_KEY_" + idx, Value: kv[0]},
			envVar{Name: "GIT_CONFIG_VALUE_" + idx, Value: kv[1]})
	}
	if len(gitPairs) > 0 || plan.hasGitConfigCount {
		out = append(out, envVar{Name: gitConfigCountVar, Value: strconv.Itoa(n + len(gitPairs))})
	}

	// A Spec that already carried GIT_CONFIG_KEY_<n> without counting it would
	// collide with the driver's own entry at that index. The API server
	// rejects a duplicate name with a message that does not say which.
	seen := make(map[string]struct{}, len(out))
	for _, e := range out {
		if _, dup := seen[e.Name]; dup {
			return nil, fmt.Errorf("%w: env %q is set more than once", executor.ErrInvalidSpec, e.Name)
		}
		seen[e.Name] = struct{}{}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}
