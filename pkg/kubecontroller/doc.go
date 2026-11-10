// Package kubecontroller is the executor controller (Task 20483): a process
// that runs in a Kubernetes cluster and keeps the ephemeral runners of cloop
// executor pools there, as `cloop executor controller`.
//
// An operator creates an ExecutorPool (cloop.dev/v1alpha1, namespaced) naming
// a hub, the Secret that holds the pool's controller credential, how many
// runners to keep and what their Pods are made of. The controller opens the
// pool's demand feed on the hub and keeps it open; when runs queue for the
// pool it starts runner Pods, each carrying a just-in-time runner
// configuration the hub minted for it in a Secret the Pod owns; each runner
// runs `cloop executor agent --ephemeral`, enrolls, takes one run and exits;
// the controller deletes the finished Pod and its Secret. When the demand
// falls it asks the hub to retire idle runners — the hub, never the
// controller, decides a runner is idle, so a busy runner is never stopped.
//
// The module has no client-go, and the controller does not add it: it talks
// to the API server through the Kubernetes executor driver's own hand-rolled
// client (kubernetes.APIClient), with list+watch informers, a work queue and a
// Lease-based leader election of its own — a few hundred lines in place of a
// dependency tree that would grow the one binary every edge device also runs.
//
// It keeps no state of its own: everything it knows is rebuilt, at every
// start, from the API server and the hub.
//
// The files, in the order a reader wants them: types.go and validate.go (the
// resource, and the CRD's rules repeated in Go), crds/ (the CRD), reconcile.go
// (what one pass does), runner.go (what a runner Pod is — the security
// boundary), hub.go (the hub's endpoints and the feed), controller.go (the
// wiring), informer.go, queue.go and leader.go (the machinery), kube.go and
// rbac.go (every API call, and the rules they need).
package kubecontroller
