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
	// private CA. When set it is the only trust the controller and its
	// runners extend to the hub.
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
}

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
	// identity, say. Its token is never mounted.
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
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
	// Conditions: Ready, Degraded, Invalid.
	Conditions []Condition `json:"conditions,omitempty"`
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
