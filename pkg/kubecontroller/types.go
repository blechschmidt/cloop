package kubecontroller

// types.go is the ExecutorPool custom resource as the controller reads and
// writes it: cloop.dev/v1alpha1, namespaced, with a status subresource.
//
// Hand-written, like the Kubernetes driver's Pod types, because the module has
// no apimachinery: the JSON tags are the contract with the CRD schema in
// crds/, and crd_test.go holds the two to the same set of fields.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// The resource's identity.
const (
	Group      = "cloop.dev"
	Version    = "v1alpha1"
	APIVersion = Group + "/" + Version
	Kind       = "ExecutorPool"
	Plural     = "executorpools"
	// CRDName is the CustomResourceDefinition's name.
	CRDName = Plural + "." + Group
)

// Defaults the API server applies from the CRD schema, and Normalize applies
// again for an object that reached the controller without them.
const (
	DefaultCredentialKey  = "credential"
	DefaultScaleDownDelay = "5m"
)

// ExecutorPool is one pool of ephemeral runners the controller keeps.
type ExecutorPool struct {
	APIVersion string             `json:"apiVersion,omitempty"`
	Kind       string             `json:"kind,omitempty"`
	Metadata   ObjectMeta         `json:"metadata"`
	Spec       ExecutorPoolSpec   `json:"spec"`
	Status     ExecutorPoolStatus `json:"status,omitempty"`
}

// Key is the pool's work-queue key: namespace/name.
func (p *ExecutorPool) Key() string { return p.Metadata.Namespace + "/" + p.Metadata.Name }

// ExecutorPoolList is what a list of the resource decodes into.
type ExecutorPoolList struct {
	Metadata ListMeta       `json:"metadata"`
	Items    []ExecutorPool `json:"items"`
}

// ExecutorPoolSpec is what an operator writes.
type ExecutorPoolSpec struct {
	// HubURL is the hub's https base URL: https://cloop.example.com. The
	// controller reaches the pool-controller endpoints under it, and its
	// runners the agent endpoint the hub names for it.
	HubURL string `json:"hubURL"`
	// HubCAPin pins the hub's TLS key: one or more sha256:<base64> SPKI
	// fingerprints, comma-separated to stage a rotation — the pin `cloop
	// executor enroll` and the hub's pool dialog print. Checked after the
	// certificate chain, never instead of it.
	HubCAPin string `json:"hubCAPin,omitempty"`
	// HubCABundle is the PEM of the certificate authorities the hub's
	// certificate chains to, when the system store does not know them — a
	// private CA. When set it is the only trust the controller extends to the
	// hub; its runners take it as --ca-file, in addition to the system store,
	// and HubCAPin is what holds them to the hub's key.
	HubCABundle string `json:"hubCABundle,omitempty"`
	// PoolCredentialSecretRef names the Secret, in the pool's namespace,
	// holding the pool's controller credential (cloop_pool1_…).
	PoolCredentialSecretRef SecretKeyRef `json:"poolCredentialSecretRef"`
	// MinRunners is the idle target: runners kept started beyond the demand,
	// so a run never waits for a Pod to start. Zero scales to nothing.
	MinRunners int `json:"minRunners,omitempty"`
	// MaxRunners bounds the runners this pool starts. The hub's pool has a
	// max_runners of its own, and the lower of the two holds.
	MaxRunners int `json:"maxRunners"`
	// ScaleDownDelay is how long a runner must have been idle before the
	// controller retires it to scale down: a Go duration, "5m" by default.
	ScaleDownDelay string `json:"scaleDownDelay,omitempty"`
	// RunnerLabels are Kubernetes labels put on every runner Pod and its
	// Secret, for policies and monitoring that select them. What runs where is
	// the hub pool's labels' business, not these.
	RunnerLabels map[string]string `json:"runnerLabels,omitempty"`
	// Template is what the runner Pods are made of.
	Template RunnerTemplate `json:"template,omitempty"`
	// Persistence gives runners PersistentVolumeClaims that outlive them
	// (Task 20484): a project's workspace and caches, kept for its next run.
	// Nil, or not enabled, starts every runner on emptyDirs alone.
	Persistence *Persistence `json:"persistence,omitempty"`
}

// Persistence is what a pool's runner volumes are (Task 20484).
//
// The controller keeps up to MaxClaims PersistentVolumeClaims per pool,
// named by a stable ordinal the way a StatefulSet's volumeClaimTemplates are
// — <pool>-storage-<n> — and mounts a free one into each runner Pod it starts.
// A claim is never mounted by two runner Pods at once: the controller claims
// it with an annotation, by compare-and-swap on its resourceVersion, and
// releases it only once the Pod that held it has terminated. A volume records
// the project whose data it holds; it is handed back, unwiped, only to a
// runner the hub will give only that project's runs, and wiped by an init
// container before any other runner uses it. Credentials never reach it:
// runners keep homes and leased files on memory-backed emptyDirs.
type Persistence struct {
	// Enabled turns runner volumes on.
	Enabled bool `json:"enabled"`
	// StorageClassName is the StorageClass of the claims; empty is the
	// cluster's default class.
	StorageClassName string `json:"storageClassName,omitempty"`
	// Size is each claim's request, such as 20Gi. Required when enabled.
	Size Quantity `json:"size,omitempty"`
	// AccessModes are the claims' access modes: ReadWriteOnce by default;
	// ReadWriteOncePod has the kubelet refuse a second Pod as well.
	AccessModes []string `json:"accessModes,omitempty"`
	// Mounts are what a runner keeps on its volume: workspace (the project's
	// checkout), gitCache (a git object cache) and toolCache (package-manager
	// caches). All three by default.
	Mounts []string `json:"mounts,omitempty"`
	// ReclaimPolicy says what becomes of claims the pool no longer needs —
	// past maxClaims, or with persistence turned off — and of all of them
	// when the pool is deleted: Delete (the default) deletes them; Retain
	// keeps them with the record of the project whose data they hold.
	ReclaimPolicy string `json:"reclaimPolicy,omitempty"`
	// MaxClaims bounds the claims the pool keeps, one per runner at most at a
	// time; more keep more projects' workspaces. Defaults to maxRunners, and
	// may not be fewer.
	MaxClaims int `json:"maxClaims,omitempty"`
	// MinFree is the free space a runner starts with — the hub's disk floor,
	// 1Gi by default. A volume under it has its caches, and then its
	// workspace, cleared before the runner starts; one still under it after
	// that is reported full and not used.
	MinFree Quantity `json:"minFree,omitempty"`
}

// Persistence defaults and values.
const (
	DefaultPersistenceMinFree = "1Gi"
	ReclaimDelete             = "Delete"
	ReclaimRetain             = "Retain"
	MountWorkspace            = "workspace"
	MountGitCache             = "gitCache"
	MountToolCache            = "toolCache"
	AccessReadWriteOnce       = "ReadWriteOnce"
	AccessReadWriteOncePod    = "ReadWriteOncePod"
	AccessReadWriteMany       = "ReadWriteMany"
)

// On reports whether runner volumes are enabled.
func (p *Persistence) On() bool { return p != nil && p.Enabled }

// SecretKeyRef names one key of a Secret in the pool's namespace.
type SecretKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key,omitempty"`
}

// RunnerTemplate is the subset of a Pod an operator may shape. Everything that
// confines the runner — its security contexts, its service account token, its
// read-only root — is the controller's and not here.
type RunnerTemplate struct {
	// Image is the runner image; empty is cloop's signed harness image,
	// resolved to the digest its registry serves and verified.
	Image string `json:"image,omitempty"`
	// ImagePullPolicy is Always, IfNotPresent or Never.
	ImagePullPolicy string `json:"imagePullPolicy,omitempty"`
	// ImagePullSecrets name Secrets with registry logins for the kubelet.
	ImagePullSecrets []LocalObjectReference `json:"imagePullSecrets,omitempty"`
	// RuntimeClassName selects a RuntimeClass: gVisor, Kata.
	RuntimeClassName string `json:"runtimeClassName,omitempty"`
	// Resources are the runner container's requests and limits.
	Resources ResourceRequirements `json:"resources,omitempty"`
	// NodeSelector, Tolerations and Affinity place the runner Pods.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	Tolerations  []Toleration      `json:"tolerations,omitempty"`
	// Affinity is a core/v1 Affinity, passed to the Pod as it is written; the
	// API server validates it when the Pod is created.
	Affinity json.RawMessage `json:"affinity,omitempty"`
	// ServiceAccountName runs the Pod as that ServiceAccount — for workload
	// identity, say. Its token is not mounted unless
	// AutomountServiceAccountToken asks for it; never the controller's own
	// account (Options.ServiceAccount).
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// AutomountServiceAccountToken mounts ServiceAccountName's API token in
	// the runner (Task 20485). Off unless set: a runner runs model-authored
	// code, and an API credential is nothing it needs to take a run. A pool
	// that sets it must name a ServiceAccount other than the namespace's
	// default, whose authority is then the runner's.
	AutomountServiceAccountToken bool `json:"automountServiceAccountToken,omitempty"`
	// Env sets variables on the runner from Secrets, by reference only: the
	// controller never reads them, and they appear nowhere but in the Secret.
	Env []SecretEnvVar `json:"env,omitempty"`
}

// LocalObjectReference names an object in the same namespace.
type LocalObjectReference struct {
	Name string `json:"name"`
}

// ResourceRequirements are a container's requests and limits.
type ResourceRequirements struct {
	Requests map[string]Quantity `json:"requests,omitempty"`
	Limits   map[string]Quantity `json:"limits,omitempty"`
}

// Quantity is a Kubernetes quantity, which the API may write as a string or a
// number. Kept as the string the operator wrote.
type Quantity string

// UnmarshalJSON accepts "500m", "2Gi" and 2.
func (q *Quantity) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*q = Quantity(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("a quantity is a string or a number: %w", err)
	}
	*q = Quantity(n.String())
	return nil
}

// Toleration is a core/v1 Toleration.
type Toleration struct {
	Key               string `json:"key,omitempty"`
	Operator          string `json:"operator,omitempty"`
	Value             string `json:"value,omitempty"`
	Effect            string `json:"effect,omitempty"`
	TolerationSeconds *int64 `json:"tolerationSeconds,omitempty"`
}

// SecretEnvVar is a variable taken from a Secret.
type SecretEnvVar struct {
	Name         string       `json:"name"`
	SecretKeyRef SecretKeyRef `json:"secretKeyRef"`
}

// ExecutorPoolStatus is what the controller reports.
type ExecutorPoolStatus struct {
	// ObservedGeneration is the spec generation this status describes.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// PoolID and PoolName are the hub's pool behind the credential.
	PoolID   string `json:"poolID,omitempty"`
	PoolName string `json:"poolName,omitempty"`
	// Image is the image the controller starts runners from, digest-pinned
	// when it resolved one.
	Image string `json:"image,omitempty"`
	// DesiredRunners is clamp(minRunners, minRunners + busy + queued,
	// maxRunners).
	DesiredRunners int `json:"desiredRunners"`
	// Runners counts the runner Pods that are starting or running; the hub's
	// record splits them into pending, idle and busy.
	Runners        int `json:"runners"`
	PendingRunners int `json:"pendingRunners"`
	IdleRunners    int `json:"idleRunners"`
	BusyRunners    int `json:"busyRunners"`
	// QueuedRuns is the hub's demand: queued runs this pool could take.
	QueuedRuns int `json:"queuedRuns"`
	// LastHubContact is when the hub last answered the demand feed.
	LastHubContact string `json:"lastHubContact,omitempty"`
	// Storage counts the pool's runner volumes and their bytes (Task 20484);
	// absent for a pool without any.
	Storage *StorageStatus `json:"storage,omitempty"`
	// Conditions: Ready, Degraded, Invalid.
	Conditions []Condition `json:"conditions,omitempty"`
}

// StorageStatus is what the controller knows of a pool's runner volumes.
type StorageStatus struct {
	// Claims counts the pool's PersistentVolumeClaims; Bound and Pending
	// split them by phase; InUse are held by a runner Pod; Full were found
	// under minFree even after clearing; Retained are kept past maxClaims
	// (or with persistence off) under reclaimPolicy Retain.
	Claims   int `json:"claims"`
	Bound    int `json:"bound"`
	Pending  int `json:"pending"`
	InUse    int `json:"inUse"`
	Full     int `json:"full"`
	Retained int `json:"retained"`
	// BytesUsed and BytesCapacity sum each claim's last measurement, made by
	// the runner that last used it, or by its init container.
	BytesUsed     int64 `json:"bytesUsed"`
	BytesCapacity int64 `json:"bytesCapacity"`
}

// Condition types.
const (
	ConditionReady    = "Ready"
	ConditionDegraded = "Degraded"
	ConditionInvalid  = "Invalid"
)

// Condition statuses.
const (
	ConditionTrue    = "True"
	ConditionFalse   = "False"
	ConditionUnknown = "Unknown"
)

// Condition is a metav1.Condition.
type Condition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	ObservedGeneration int64  `json:"observedGeneration,omitempty"`
	LastTransitionTime string `json:"lastTransitionTime"`
	Reason             string `json:"reason"`
	Message            string `json:"message"`
}

// condition returns the condition of type t, or nil.
func (s *ExecutorPoolStatus) condition(t string) *Condition {
	for i := range s.Conditions {
		if s.Conditions[i].Type == t {
			return &s.Conditions[i]
		}
	}
	return nil
}

// ObjectMeta is the part of metav1.ObjectMeta the controller reads and writes.
type ObjectMeta struct {
	Name              string            `json:"name,omitempty"`
	GenerateName      string            `json:"generateName,omitempty"`
	Namespace         string            `json:"namespace,omitempty"`
	UID               string            `json:"uid,omitempty"`
	ResourceVersion   string            `json:"resourceVersion,omitempty"`
	Generation        int64             `json:"generation,omitempty"`
	CreationTimestamp string            `json:"creationTimestamp,omitempty"`
	DeletionTimestamp string            `json:"deletionTimestamp,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	OwnerReferences   []OwnerReference  `json:"ownerReferences,omitempty"`
}

// ListMeta is a list's metadata.
type ListMeta struct {
	ResourceVersion string `json:"resourceVersion,omitempty"`
	Continue        string `json:"continue,omitempty"`
}

// OwnerReference is a metav1.OwnerReference. BlockOwnerDeletion is left
// unset on purpose: setting it needs update on the owner's finalizers
// subresource wherever OwnerReferencesPermissionEnforcement is on, a verb the
// controller has no other use for.
type OwnerReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller *bool  `json:"controller,omitempty"`
}

// controllerOf returns the UID of the controlling owner, "" when none.
func controllerOf(m ObjectMeta) string {
	for _, r := range m.OwnerReferences {
		if r.Controller != nil && *r.Controller {
			return r.UID
		}
	}
	return ""
}

// trimMessage bounds a message for a condition or an Event, keeping it one
// paragraph.
func trimMessage(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	const max = 1024
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}
