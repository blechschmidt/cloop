package kubernetes

// rbac.go is the one statement of the authority this driver needs in the
// workload namespace: the rules of the executor Role.
//
// It used to be written out by hand wherever an operator needed telling — the
// Helm chart, preflight's remedy, and the hints on four different refusals —
// and the copies had drifted. Preflight still told an operator to grant
// secrets [create delete] long after replacing a GitHub App token in a running
// Pod (Task 20375) made patch necessary, and the chart's own comment counted
// eleven rules while the Role it described granted twelve verbs. Nothing
// noticed, because nothing compared them: the CI check on the installed Role
// asserted the Pod verbs and the denial of Secret reads, and was silent on
// everything else — so an added patch on networkpolicies, which is the
// authority to widen a running sandbox's firewall, would have shipped.
//
// Now the remedies render from executorRole, and rbac_test.go renders the
// chart with `helm template` and requires its Role to grant exactly these verbs
// on exactly these resources, in both directions: nothing the driver calls is
// missing, and nothing it does not call is granted.

import (
	"fmt"
	"strings"
)

// roleRule is one rule of the executor Role.
type roleRule struct {
	// Group is the API group; "" is the core group.
	Group    string
	Resource string
	Verbs    []string
}

// executorRole is every rule the driver needs, and nothing else. Each verb is
// one client.go call:
//
//	pods            create  createPod            start a run
//	pods            get     getPod               poll one workload, and confirm an adopted one
//	pods            list    listPods             the orphan sweep
//	pods            watch   watchPod             follow phase transitions
//	pods            delete  deletePod            stop, kill, revoke and clean up
//	pods/log        get     followLogs           stream the run's output
//	secrets         create  createSecret         a run's credentials and environment, and a workspace fetch's token
//	secrets         patch   patchSecretData      replace a GitHub App token before GitHub's hour ends
//	secrets         delete  deleteSecret         take them back
//	networkpolicies create  createNetworkPolicy  the Pod's egress allowlist, before the Pod
//	networkpolicies delete  deleteNetworkPolicy  remove it once the Pod is gone
//	networkpolicies list    listNetworkPolicies  the orphan sweep, and the preflight check
//
// What is absent is as deliberate as what is present. No read verb on Secrets:
// the driver never reads one back, so an executor that could enumerate the
// namespace's other credentials is authority nothing here would use. No update
// or patch on Pods or NetworkPolicies: a Pod is never mutated after it is
// created, and a policy that could be patched is a running sandbox's firewall
// that could be widened without touching the sandbox. And no pods/exec: a live
// shell into a sandbox (attach.go) is an operator's opt-in, granted in their own
// Role, never by default.
var executorRole = []roleRule{
	{Resource: "pods", Verbs: []string{"create", "get", "list", "watch", "delete"}},
	{Resource: "pods/log", Verbs: []string{"get"}},
	{Resource: "secrets", Verbs: []string{"create", "patch", "delete"}},
	{Group: "networking.k8s.io", Resource: "networkpolicies", Verbs: []string{"create", "delete", "list"}},
}

// roleRuleFor returns the rule for resource. It panics on a resource the table
// does not name, because every caller passes a literal and a typo there is a
// remedy that would tell an operator to grant nothing.
func roleRuleFor(resource string) roleRule {
	for _, r := range executorRole {
		if r.Resource == resource {
			return r
		}
	}
	panic("kubernetes: no executor Role rule for " + resource)
}

// yaml renders the rule as a Role rule an operator can paste, indented to sit
// under `rules:`.
func (r roleRule) yaml() string {
	quoted := make([]string, len(r.Verbs))
	for i, v := range r.Verbs {
		quoted[i] = fmt.Sprintf("%q", v)
	}
	return fmt.Sprintf("  - apiGroups: [%q]\n    resources: [%q]\n    verbs: [%s]",
		r.Group, r.Resource, strings.Join(quoted, ", "))
}

// inline renders the rule on one line, for a remedy inside a sentence.
func (r roleRule) inline() string {
	quoted := make([]string, len(r.Verbs))
	for i, v := range r.Verbs {
		quoted[i] = fmt.Sprintf("%q", v)
	}
	return fmt.Sprintf("- apiGroups: [%q] resources: [%q] verbs: [%s]",
		r.Group, r.Resource, strings.Join(quoted, ", "))
}

// brief renders the rule as "resource: [verb verb]", qualified by its group
// when it has one.
func (r roleRule) brief() string {
	name := r.Resource
	if r.Group != "" {
		name = r.Group + " " + name
	}
	return fmt.Sprintf("%s: [%s]", name, strings.Join(r.Verbs, " "))
}

// plain renders the rule as "resource: verb, verb", for prose.
func (r roleRule) plain() string {
	name := r.Resource
	if r.Group != "" {
		name = r.Group + " " + name
	}
	return fmt.Sprintf("%s: %s", name, strings.Join(r.Verbs, ", "))
}

// secretsRuleYAML is the secrets rule, for the refusals of a Secret create.
func secretsRuleYAML() string { return roleRuleFor("secrets").yaml() }

// secretsRuleRationale is what an operator reviewing that rule asks first, and
// the answer: no read verb.
const secretsRuleRationale = "create, patch and delete only: the driver writes a run's credentials and " +
	"environment, replaces a GitHub App token in them before it expires, and removes them again, and " +
	"never reads a Secret back"
