package executor

// networktenant.go names the network a workload belongs to (Task 20502).
//
// Two runs of different projects on one executor must not reach each other.
// A container driver keeps them apart by giving each project a network of its
// own, and to do that it needs to know which project a workload is — the same
// answer on the hub's own host and on an edge device, where the workload's
// directory is a path the hub never saw. The label the hub stamps on every
// dispatch (uiSpec sets "project" to the project's directory on the hub)
// travels to a device unchanged, so it is the identity; the workload's
// directory stands in only for a Spec built without the label.
//
// A feature is its project: PolicyProjectPath maps a feature's worktree onto
// its parent wherever the control plane installed the mapping, so a feature's
// run shares its project's network on the hub. A device has no mapping and
// keeps a feature on a network of its own — narrower, never wider.

import (
	"path"
	"strings"
)

// NetworkTenant returns the isolation domain of a workload's network: its
// project's directory on the hub, cleaned, or "" for a workload that names no
// project. Workloads with different tenants never share a network.
func NetworkTenant(spec Spec) string {
	p := strings.TrimSpace(spec.Labels["project"])
	if p == "" {
		p = strings.TrimSpace(spec.WorkDir)
	}
	if p == "" {
		return ""
	}
	return path.Clean(PolicyProjectPath(path.Clean(p)))
}
