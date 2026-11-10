package kubecontroller

// rbac.go is the whole of the controller's authority in the cluster, as Role
// rules: what kube.go calls and nothing more. rbac_test.go drives the
// controller through scale-up, scale-down, collection, leader election and
// Events against the fake API server, and holds every call it records to
// these rules — so a new call without a rule, or a rule nothing calls, fails
// the test.
//
// Two of them are worth reading twice. Secrets: the controller creates and
// deletes its runners' Secrets and lists and watches them by label to collect
// orphans, and reads one Secret by name, the pool credential; it never updates
// or patches one. Pods: create and delete, get, list and watch — no exec,
// no attach, no log, nothing that reaches inside a runner. The single gets
// confirm with the API server, not the cache, that an object is gone before
// the controller deletes what it leaves behind. PersistentVolumeClaims (Task
// 20484): runner volumes it creates, claims and releases by merge-patching
// their metadata against the version it read — never their spec — and
// deletes under reclaimPolicy Delete.

import (
	"strings"
)

// Rule is one Role rule.
type Rule struct {
	APIGroups []string
	Resources []string
	Verbs     []string
}

// RequiredRules are the rules the controller's ServiceAccount needs in the
// namespace it serves (a ClusterRole across all of them with --all-namespaces).
// The Lease rule belongs in the namespace the controller elects its leader in.
func RequiredRules() []Rule {
	return []Rule{
		{APIGroups: []string{Group}, Resources: []string{Plural}, Verbs: []string{"list", "watch"}},
		{APIGroups: []string{Group}, Resources: []string{Plural + "/status"}, Verbs: []string{"update"}},
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch", "create", "delete"}},
		{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list", "watch", "create", "delete"}},
		{APIGroups: []string{""}, Resources: []string{"persistentvolumeclaims"}, Verbs: []string{"list", "watch", "create", "patch", "delete"}},
		{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: []string{"create"}},
		{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, Verbs: []string{"get", "create", "update"}},
	}
}

// RulesYAML renders RequiredRules as the rules: list of a Role.
func RulesYAML() string {
	var b strings.Builder
	b.WriteString("rules:\n")
	quote := func(xs []string) string {
		q := make([]string, len(xs))
		for i, x := range xs {
			q[i] = `"` + x + `"`
		}
		return "[" + strings.Join(q, ", ") + "]"
	}
	for _, r := range RequiredRules() {
		b.WriteString("  - apiGroups: " + quote(r.APIGroups) + "\n")
		b.WriteString("    resources: " + quote(r.Resources) + "\n")
		b.WriteString("    verbs: " + quote(r.Verbs) + "\n")
	}
	return b.String()
}
