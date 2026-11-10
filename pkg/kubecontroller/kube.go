package kubecontroller

// kube.go is everything the controller says to the Kubernetes API: the paths,
// the few object types it reads and writes, and one method per call.
//
// The transport is the Kubernetes executor driver's hand-rolled client
// (kubernetes.APIClient), not client-go: the module has none, and this binary
// is the one every edge device and every hub also runs, so the controller
// pays for its fifteen calls in structs rather than in a client library's
// dependency tree. The calls are the whole of the controller's authority, and
// rbac.go lists exactly the rule each needs — rbac_test.go holds the two
// equal against the fake API server's record of what was called.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

// API groups and paths.
const (
	coreV1         = "/api/v1"
	coordinationV1 = "/apis/coordination.k8s.io/v1"
	poolsV1alpha1  = "/apis/" + Group + "/" + Version
)

func nsPath(prefix, namespace, resource string) string {
	return prefix + "/namespaces/" + url.PathEscape(namespace) + "/" + resource
}

func objPath(prefix, namespace, resource, name string) string {
	return nsPath(prefix, namespace, resource) + "/" + url.PathEscape(name)
}

// Pod is the part of a core/v1 Pod the controller writes and reads.
type Pod struct {
	APIVersion string     `json:"apiVersion,omitempty"`
	Kind       string     `json:"kind,omitempty"`
	Metadata   ObjectMeta `json:"metadata"`
	Spec       PodSpec    `json:"spec"`
	Status     PodStatus  `json:"status,omitempty"`
}

// PodList is a list of Pods.
type PodList struct {
	Metadata ListMeta `json:"metadata"`
	Items    []Pod    `json:"items"`
}

// PodSpec is the part of a PodSpec a runner Pod sets.
type PodSpec struct {
	RestartPolicy                 string                 `json:"restartPolicy,omitempty"`
	ServiceAccountName            string                 `json:"serviceAccountName,omitempty"`
	AutomountServiceAccountToken  *bool                  `json:"automountServiceAccountToken,omitempty"`
	EnableServiceLinks            *bool                  `json:"enableServiceLinks,omitempty"`
	RuntimeClassName              *string                `json:"runtimeClassName,omitempty"`
	NodeSelector                  map[string]string      `json:"nodeSelector,omitempty"`
	Tolerations                   []Toleration           `json:"tolerations,omitempty"`
	Affinity                      json.RawMessage        `json:"affinity,omitempty"`
	ImagePullSecrets              []LocalObjectReference `json:"imagePullSecrets,omitempty"`
	TerminationGracePeriodSeconds *int64                 `json:"terminationGracePeriodSeconds,omitempty"`
	SecurityContext               *PodSecurityContext    `json:"securityContext,omitempty"`
	InitContainers                []Container            `json:"initContainers,omitempty"`
	Containers                    []Container            `json:"containers"`
	Volumes                       []Volume               `json:"volumes,omitempty"`
	HostNetwork                   bool                   `json:"hostNetwork,omitempty"`
	HostPID                       bool                   `json:"hostPID,omitempty"`
	HostIPC                       bool                   `json:"hostIPC,omitempty"`
}

// SeccompProfile is a seccomp profile reference.
type SeccompProfile struct {
	Type string `json:"type"`
}

// PodSecurityContext is a Pod's security context.
type PodSecurityContext struct {
	RunAsNonRoot        *bool           `json:"runAsNonRoot,omitempty"`
	RunAsUser           *int64          `json:"runAsUser,omitempty"`
	RunAsGroup          *int64          `json:"runAsGroup,omitempty"`
	FSGroup             *int64          `json:"fsGroup,omitempty"`
	FSGroupChangePolicy *string         `json:"fsGroupChangePolicy,omitempty"`
	SeccompProfile      *SeccompProfile `json:"seccompProfile,omitempty"`
}

// Capabilities are a container's Linux capabilities.
type Capabilities struct {
	Add  []string `json:"add,omitempty"`
	Drop []string `json:"drop,omitempty"`
}

// SecurityContext is a container's security context.
type SecurityContext struct {
	RunAsNonRoot             *bool           `json:"runAsNonRoot,omitempty"`
	RunAsUser                *int64          `json:"runAsUser,omitempty"`
	RunAsGroup               *int64          `json:"runAsGroup,omitempty"`
	Privileged               *bool           `json:"privileged,omitempty"`
	AllowPrivilegeEscalation *bool           `json:"allowPrivilegeEscalation,omitempty"`
	ReadOnlyRootFilesystem   *bool           `json:"readOnlyRootFilesystem,omitempty"`
	Capabilities             *Capabilities   `json:"capabilities,omitempty"`
	SeccompProfile           *SeccompProfile `json:"seccompProfile,omitempty"`
}

// EnvVar is a container variable, by value or from a Secret.
type EnvVar struct {
	Name      string        `json:"name"`
	Value     string        `json:"value,omitempty"`
	ValueFrom *EnvVarSource `json:"valueFrom,omitempty"`
}

// EnvVarSource takes a variable from a Secret.
type EnvVarSource struct {
	SecretKeyRef *SecretKeySelector `json:"secretKeyRef,omitempty"`
}

// SecretKeySelector names a Secret's key.
type SecretKeySelector struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// VolumeMount mounts a volume in a container.
type VolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
}

// Container is the part of a container a runner Pod sets.
type Container struct {
	Name                     string              `json:"name"`
	Image                    string              `json:"image"`
	ImagePullPolicy          string              `json:"imagePullPolicy,omitempty"`
	Command                  []string            `json:"command,omitempty"`
	Args                     []string            `json:"args,omitempty"`
	Env                      []EnvVar            `json:"env,omitempty"`
	Resources                *ContainerResources `json:"resources,omitempty"`
	VolumeMounts             []VolumeMount       `json:"volumeMounts,omitempty"`
	SecurityContext          *SecurityContext    `json:"securityContext,omitempty"`
	TerminationMessagePath   string              `json:"terminationMessagePath,omitempty"`
	TerminationMessagePolicy string              `json:"terminationMessagePolicy,omitempty"`
}

// ContainerResources are a container's requests and limits.
type ContainerResources struct {
	Requests map[string]string `json:"requests,omitempty"`
	Limits   map[string]string `json:"limits,omitempty"`
}

// Volume is a Pod volume: an emptyDir, a Secret, or a runner's claim.
type Volume struct {
	Name                  string          `json:"name"`
	EmptyDir              *EmptyDirSource `json:"emptyDir,omitempty"`
	Secret                *SecretVolume   `json:"secret,omitempty"`
	PersistentVolumeClaim *ClaimVolume    `json:"persistentVolumeClaim,omitempty"`
}

// ClaimVolume mounts a PersistentVolumeClaim.
type ClaimVolume struct {
	ClaimName string `json:"claimName"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
}

// EmptyDirSource is an emptyDir.
type EmptyDirSource struct {
	Medium    string `json:"medium,omitempty"`
	SizeLimit string `json:"sizeLimit,omitempty"`
}

// SecretVolume projects a Secret's keys as files.
type SecretVolume struct {
	SecretName  string `json:"secretName"`
	DefaultMode *int32 `json:"defaultMode,omitempty"`
	Optional    *bool  `json:"optional,omitempty"`
}

// PodStatus is the part of a Pod's status the controller reads.
type PodStatus struct {
	Phase                 string            `json:"phase,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	Message               string            `json:"message,omitempty"`
	Conditions            []PodCondition    `json:"conditions,omitempty"`
	InitContainerStatuses []ContainerStatus `json:"initContainerStatuses,omitempty"`
	ContainerStatuses     []ContainerStatus `json:"containerStatuses,omitempty"`
}

// PodCondition is one of a Pod's conditions: PodScheduled says why a Pod
// waits for a node — an unbound claim among the reasons.
type PodCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// ContainerStatus is one container's state.
type ContainerStatus struct {
	Name  string         `json:"name"`
	State ContainerState `json:"state,omitempty"`
}

// ContainerState is a container's current state.
type ContainerState struct {
	Waiting    *ContainerStateWaiting    `json:"waiting,omitempty"`
	Terminated *ContainerStateTerminated `json:"terminated,omitempty"`
}

// ContainerStateWaiting is a container that has not started.
type ContainerStateWaiting struct {
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// ContainerStateTerminated is a container that ended.
type ContainerStateTerminated struct {
	ExitCode int    `json:"exitCode"`
	Reason   string `json:"reason,omitempty"`
	Message  string `json:"message,omitempty"`
}

// Pod phases.
const (
	PodPending   = "Pending"
	PodRunning   = "Running"
	PodSucceeded = "Succeeded"
	PodFailed    = "Failed"
)

// Secret is a core/v1 Secret. Data is set only on what the controller writes
// and on the one Secret it reads, the pool credential; a listed runner Secret
// is decoded into secretMeta, so its token is never held.
type Secret struct {
	APIVersion string            `json:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty"`
	Metadata   ObjectMeta        `json:"metadata"`
	Type       string            `json:"type,omitempty"`
	Data       map[string][]byte `json:"data,omitempty"`
	Immutable  *bool             `json:"immutable,omitempty"`
}

// secretMeta is a listed Secret: its metadata, never its data.
type secretMeta struct {
	Metadata ObjectMeta `json:"metadata"`
}

// PersistentVolumeClaim is the part of a core/v1 PersistentVolumeClaim the
// controller writes and reads (Task 20484). It is created whole, and only
// ever changed afterwards by a merge patch of its metadata: a PUT of this
// partial view would clear what it does not model — the volume the binder
// chose, the protection finalizer.
type PersistentVolumeClaim struct {
	APIVersion string     `json:"apiVersion,omitempty"`
	Kind       string     `json:"kind,omitempty"`
	Metadata   ObjectMeta `json:"metadata"`
	Spec       ClaimSpec  `json:"spec"`
	Status     ClaimState `json:"status,omitempty"`
}

// ClaimSpec is a claim's spec.
type ClaimSpec struct {
	AccessModes      []string             `json:"accessModes,omitempty"`
	StorageClassName *string              `json:"storageClassName,omitempty"`
	VolumeMode       string               `json:"volumeMode,omitempty"`
	Resources        ClaimResources       `json:"resources,omitempty"`
	VolumeName       string               `json:"volumeName,omitempty"`
	DataSource       *ObjectReferenceLite `json:"dataSource,omitempty"`
}

// ObjectReferenceLite is a typed local reference: a claim's data source.
type ObjectReferenceLite struct {
	APIGroup *string `json:"apiGroup,omitempty"`
	Kind     string  `json:"kind"`
	Name     string  `json:"name"`
}

// ClaimResources are a claim's requests.
type ClaimResources struct {
	Requests map[string]string `json:"requests,omitempty"`
}

// ClaimState is a claim's status.
type ClaimState struct {
	Phase    string            `json:"phase,omitempty"`
	Capacity map[string]string `json:"capacity,omitempty"`
}

// Claim phases.
const (
	ClaimPending = "Pending"
	ClaimBound   = "Bound"
	ClaimLost    = "Lost"
)

// Lease is a coordination.k8s.io/v1 Lease.
type Lease struct {
	APIVersion string     `json:"apiVersion,omitempty"`
	Kind       string     `json:"kind,omitempty"`
	Metadata   ObjectMeta `json:"metadata"`
	Spec       LeaseSpec  `json:"spec"`
}

// LeaseSpec is a Lease's spec.
type LeaseSpec struct {
	HolderIdentity       *string `json:"holderIdentity,omitempty"`
	LeaseDurationSeconds *int32  `json:"leaseDurationSeconds,omitempty"`
	AcquireTime          *string `json:"acquireTime,omitempty"`
	RenewTime            *string `json:"renewTime,omitempty"`
	LeaseTransitions     *int32  `json:"leaseTransitions,omitempty"`
}

// microTime renders t as a metav1.MicroTime.
func microTime(t time.Time) *string {
	s := t.UTC().Format("2006-01-02T15:04:05.000000Z07:00")
	return &s
}

// Event is a core/v1 Event.
type Event struct {
	APIVersion         string          `json:"apiVersion"`
	Kind               string          `json:"kind"`
	Metadata           ObjectMeta      `json:"metadata"`
	InvolvedObject     ObjectReference `json:"involvedObject"`
	Reason             string          `json:"reason"`
	Message            string          `json:"message"`
	Type               string          `json:"type"`
	Source             EventSource     `json:"source"`
	FirstTimestamp     string          `json:"firstTimestamp"`
	LastTimestamp      string          `json:"lastTimestamp"`
	Count              int32           `json:"count"`
	ReportingComponent string          `json:"reportingComponent,omitempty"`
	ReportingInstance  string          `json:"reportingInstance,omitempty"`
}

// ObjectReference names an object an Event is about.
type ObjectReference struct {
	APIVersion      string `json:"apiVersion,omitempty"`
	Kind            string `json:"kind,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	Name            string `json:"name,omitempty"`
	UID             string `json:"uid,omitempty"`
	ResourceVersion string `json:"resourceVersion,omitempty"`
}

// EventSource names the component reporting an Event.
type EventSource struct {
	Component string `json:"component,omitempty"`
}

// watchEvent is one frame of a watch stream.
type watchEvent struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

// kubeAPI is the controller's calls.
type kubeAPI struct {
	c *kubernetes.APIClient
}

// resource is one kind the controller lists and watches in a namespace.
type resource struct {
	prefix, name string
}

var (
	resPools   = resource{poolsV1alpha1, Plural}
	resPods    = resource{coreV1, "pods"}
	resSecrets = resource{coreV1, "secrets"}
	resClaims  = resource{coreV1, "persistentvolumeclaims"}
)

// list lists a resource in namespace ("" for every namespace), decoding the
// raw items, and returns the list's resourceVersion.
func (k *kubeAPI) list(ctx context.Context, r resource, namespace, selector string) ([]json.RawMessage, string, error) {
	q := url.Values{}
	if selector != "" {
		q.Set("labelSelector", selector)
	}
	var items []json.RawMessage
	rv := ""
	for {
		var out struct {
			Metadata ListMeta          `json:"metadata"`
			Items    []json.RawMessage `json:"items"`
		}
		q.Set("limit", "500")
		if err := k.c.Do(ctx, http.MethodGet, k.collection(r, namespace), q, nil, &out); err != nil {
			return nil, "", err
		}
		items = append(items, out.Items...)
		rv = out.Metadata.ResourceVersion
		if out.Metadata.Continue == "" {
			return items, rv, nil
		}
		q.Set("continue", out.Metadata.Continue)
	}
}

// collection is the path of r's collection in namespace, or across every
// namespace for "".
func (k *kubeAPI) collection(r resource, namespace string) string {
	if namespace == "" {
		return r.prefix + "/" + r.name
	}
	return nsPath(r.prefix, namespace, r.name)
}

// watch opens a watch of r from resourceVersion.
func (k *kubeAPI) watch(ctx context.Context, r resource, namespace, selector, resourceVersion string, timeout time.Duration) (io.ReadCloser, error) {
	q := url.Values{}
	q.Set("watch", "true")
	q.Set("allowWatchBookmarks", "true")
	q.Set("resourceVersion", resourceVersion)
	q.Set("timeoutSeconds", strconv.Itoa(int(timeout/time.Second)))
	if selector != "" {
		q.Set("labelSelector", selector)
	}
	return k.c.Stream(ctx, k.collection(r, namespace), q)
}

// updatePoolStatus writes a pool's status through the status subresource,
// guarded by its resourceVersion.
func (k *kubeAPI) updatePoolStatus(ctx context.Context, p *ExecutorPool) (*ExecutorPool, error) {
	body := *p
	body.APIVersion, body.Kind = APIVersion, Kind
	var out ExecutorPool
	err := k.c.Do(ctx, http.MethodPut, objPath(poolsV1alpha1, p.Metadata.Namespace, Plural, p.Metadata.Name)+"/status",
		nil, &body, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// getPod reads one Pod.
func (k *kubeAPI) getPod(ctx context.Context, namespace, name string) (*Pod, error) {
	var out Pod
	if err := k.c.Do(ctx, http.MethodGet, objPath(coreV1, namespace, "pods", name), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// createPod creates a Pod and returns the server's view of it.
func (k *kubeAPI) createPod(ctx context.Context, p *Pod) (*Pod, error) {
	var out Pod
	if err := k.c.Do(ctx, http.MethodPost, nsPath(coreV1, p.Metadata.Namespace, "pods"), nil, p, &out); err != nil {
		return nil, err
	}
	if out.Metadata.UID == "" {
		return nil, fmt.Errorf("kubecontroller: the API server accepted Pod %s but returned no uid", p.Metadata.Name)
	}
	return &out, nil
}

// deleteOptions is a DELETE's body.
type deleteOptions struct {
	APIVersion         string         `json:"apiVersion"`
	Kind               string         `json:"kind"`
	GracePeriodSeconds *int64         `json:"gracePeriodSeconds,omitempty"`
	PropagationPolicy  string         `json:"propagationPolicy,omitempty"`
	Preconditions      *preconditions `json:"preconditions,omitempty"`
}

// preconditions make a delete apply to one incarnation of an object only.
type preconditions struct {
	UID string `json:"uid,omitempty"`
}

// deletePod deletes the Pod with uid (when given). A Pod already gone is
// success.
func (k *kubeAPI) deletePod(ctx context.Context, namespace, name, uid string) error {
	return k.delete(ctx, objPath(coreV1, namespace, "pods", name), uid)
}

// deleteSecret deletes the Secret with uid (when given). A Secret already
// gone is success.
func (k *kubeAPI) deleteSecret(ctx context.Context, namespace, name, uid string) error {
	return k.delete(ctx, objPath(coreV1, namespace, "secrets", name), uid)
}

func (k *kubeAPI) delete(ctx context.Context, path, uid string) error {
	body := deleteOptions{APIVersion: "v1", Kind: "DeleteOptions", PropagationPolicy: "Background"}
	if uid != "" {
		body.Preconditions = &preconditions{UID: uid}
	}
	err := k.c.Do(ctx, http.MethodDelete, path, nil, body, nil)
	if kubernetes.IsNotFound(err) || kubernetes.IsConflict(err) {
		// Gone, or a different object of that name now: either way the one
		// meant is not there to delete.
		return nil
	}
	return err
}

// createSecret creates a Secret. Nothing of the response is decoded: the API
// server echoes the data back.
func (k *kubeAPI) createSecret(ctx context.Context, s *Secret) error {
	return k.c.Do(ctx, http.MethodPost, nsPath(coreV1, s.Metadata.Namespace, "secrets"), nil, s, nil)
}

// getSecretKey reads one key of a Secret: the pool credential.
func (k *kubeAPI) getSecretKey(ctx context.Context, namespace, name, key string) ([]byte, string, error) {
	var out Secret
	if err := k.c.Do(ctx, http.MethodGet, objPath(coreV1, namespace, "secrets", name), nil, nil, &out); err != nil {
		return nil, "", err
	}
	v, ok := out.Data[key]
	for k2, other := range out.Data {
		if k2 != key {
			zeroBytes(other)
		}
	}
	if !ok {
		return nil, out.Metadata.ResourceVersion, fmt.Errorf("kubecontroller: Secret %s/%s has no key %q", namespace, name, key)
	}
	return v, out.Metadata.ResourceVersion, nil
}

// secretExists reports whether a Secret exists, decoding its metadata only:
// a runner's Secret holds its token, which this check has no use for.
func (k *kubeAPI) secretExists(ctx context.Context, namespace, name string) (bool, error) {
	var out secretMeta
	err := k.c.Do(ctx, http.MethodGet, objPath(coreV1, namespace, "secrets", name), nil, nil, &out)
	switch {
	case err == nil:
		return true, nil
	case kubernetes.IsNotFound(err):
		return false, nil
	}
	return false, err
}

// createClaim creates a PersistentVolumeClaim and returns the server's view.
func (k *kubeAPI) createClaim(ctx context.Context, c *PersistentVolumeClaim) (*PersistentVolumeClaim, error) {
	c.APIVersion, c.Kind = "v1", "PersistentVolumeClaim"
	var out PersistentVolumeClaim
	if err := k.c.Do(ctx, http.MethodPost, nsPath(coreV1, c.Metadata.Namespace, "persistentvolumeclaims"), nil, c,
		&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// patchClaimMeta merge-patches a claim's metadata, guarded by
// resourceVersion: the API server applies it only to the version the
// controller read, and answers 409 Conflict to any other — the
// compare-and-swap that keeps two reconcilers from claiming one volume.
// labels and annotations set a key to its value, or remove it for nil;
// owners, when not nil, replaces the ownerReferences.
func (k *kubeAPI) patchClaimMeta(ctx context.Context, namespace, name, resourceVersion string,
	annotations map[string]*string, labels map[string]*string, owners *[]OwnerReference) (*PersistentVolumeClaim, error) {
	if resourceVersion == "" {
		return nil, fmt.Errorf("kubecontroller: a claim's metadata is only changed against the version read")
	}
	return k.patchClaim(ctx, namespace, name, resourceVersion, annotations, labels, owners)
}

// patchClaimMetaUnguarded is patchClaimMeta with no resourceVersion: for the
// one caller that may — giving back, seconds after taking it, a claim no rival
// can have released and taken again within claimGrace (storage.go unclaim).
func (k *kubeAPI) patchClaimMetaUnguarded(ctx context.Context, namespace, name string,
	annotations map[string]*string) (*PersistentVolumeClaim, error) {
	return k.patchClaim(ctx, namespace, name, "", annotations, nil, nil)
}

func (k *kubeAPI) patchClaim(ctx context.Context, namespace, name, resourceVersion string,
	annotations map[string]*string, labels map[string]*string, owners *[]OwnerReference) (*PersistentVolumeClaim, error) {
	meta := map[string]any{}
	if resourceVersion != "" {
		meta["resourceVersion"] = resourceVersion
	}
	if len(annotations) > 0 {
		meta["annotations"] = annotations
	}
	if len(labels) > 0 {
		meta["labels"] = labels
	}
	if owners != nil {
		refs := *owners
		if refs == nil {
			refs = []OwnerReference{}
		}
		meta["ownerReferences"] = refs
	}
	body, err := json.Marshal(map[string]any{"metadata": meta})
	if err != nil {
		return nil, err
	}
	var out PersistentVolumeClaim
	if err := k.c.Patch(ctx, objPath(coreV1, namespace, "persistentvolumeclaims", name), "application/merge-patch+json",
		body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// deleteClaim deletes the claim with uid. One already gone is success.
func (k *kubeAPI) deleteClaim(ctx context.Context, namespace, name, uid string) error {
	return k.delete(ctx, objPath(coreV1, namespace, "persistentvolumeclaims", name), uid)
}

// getLease reads a Lease.
func (k *kubeAPI) getLease(ctx context.Context, namespace, name string) (*Lease, error) {
	var out Lease
	if err := k.c.Do(ctx, http.MethodGet, objPath(coordinationV1, namespace, "leases", name), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// createLease creates a Lease.
func (k *kubeAPI) createLease(ctx context.Context, l *Lease) (*Lease, error) {
	l.APIVersion, l.Kind = "coordination.k8s.io/v1", "Lease"
	var out Lease
	if err := k.c.Do(ctx, http.MethodPost, nsPath(coordinationV1, l.Metadata.Namespace, "leases"), nil, l, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// updateLease replaces a Lease, guarded by its resourceVersion.
func (k *kubeAPI) updateLease(ctx context.Context, l *Lease) (*Lease, error) {
	l.APIVersion, l.Kind = "coordination.k8s.io/v1", "Lease"
	var out Lease
	if err := k.c.Do(ctx, http.MethodPut, objPath(coordinationV1, l.Metadata.Namespace, "leases", l.Metadata.Name),
		nil, l, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// createEvent records an Event.
func (k *kubeAPI) createEvent(ctx context.Context, e *Event) error {
	return k.c.Do(ctx, http.MethodPost, nsPath(coreV1, e.Metadata.Namespace, "events"), nil, e, nil)
}

// zeroBytes overwrites b.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ptr returns a pointer to v.
func ptr[T any](v T) *T { return &v }
