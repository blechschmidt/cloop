package kubernetes

// pod.go holds the Pod JSON types this driver needs and buildPod, the pure
// function that turns an executor.Spec plus the executor's options into the
// object POSTed to the API server.
//
// buildPod is the security boundary of this package, the way argv.go is for
// the container driver: everything that confines a workload — the security
// contexts, the dropped capabilities, the disabled ServiceAccount token, the
// read-only root filesystem — is decided here, in one pure function with no
// I/O, so it can be asserted on exhaustively in tests rather than inferred
// from a live cluster.
//
// The confinement applied to every Pod, unconditionally:
//
//   - restartPolicy: Never. A harness that exits must stay exited; a
//     restarting Pod would silently re-run a task whose side effects already
//     landed.
//   - automountServiceAccountToken: false. Without this the kubelet mounts a
//     token for the namespace's default ServiceAccount into the container,
//     handing model-authored code an in-cluster API credential nobody chose
//     to grant it. This is the single most important line in the file.
//   - runAsNonRoot with an explicit UID/GID, at both Pod and container scope.
//   - readOnlyRootFilesystem, with writable emptyDir volumes mounted at the
//     workspace and /tmp so a build still works.
//   - allowPrivilegeEscalation: false, so a setuid binary in the image cannot
//     undo the UID choice.
//   - capabilities.drop: ALL.
//   - seccompProfile: RuntimeDefault, at both scopes.
//
// None of these are options. An operator who needs them relaxed is asking for
// a different executor, not a flag on this one.
//
// A Pod may carry a second container: the workspace provisioner, which runs as
// an initContainer when Spec.Workspace asks for a git tree. It is confined by
// the same confinedSecurityContext the harness gets — one function, so the two
// cannot drift.
//
// No credential is ever a value in the object this file builds. The workspace
// token reaches the provisioner through valueFrom.secretKeyRef; a lease's files
// are a projected Secret volume; and every variable of Spec.Env — which is
// where a lease puts the credentials it delivers as environment — is a
// secretKeyRef into the run's lease Secret (leaseenv.go). Each property is
// asserted against the marshalled JSON: workspace_test.go for the token,
// secretfiles_test.go for the files, leaseenv_test.go for the environment.

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// Label keys applied to every Pod this driver creates. The GC sweep selects
// on ExecutorID plus the presence of TaskID, so both are always set — a Pod
// with no task is labelled "none" rather than left unlabelled, which would
// make it invisible to reconciliation.
const (
	LabelManaged    = "cloop.dev/managed"
	LabelExecutorID = "cloop.dev/executor-id"
	LabelTaskID     = "cloop.dev/task-id"
	LabelHandleID   = "cloop.dev/handle-id"
	LabelProject    = "cloop.dev/project"

	// AnnotationProjectPath carries the untruncated project path. Label
	// values are capped at 63 characters and constrained to a small
	// alphabet, so a path only survives intact as an annotation.
	AnnotationProjectPath = "cloop.dev/project-path"
	// AnnotationArgv records the command, for an operator reading
	// `kubectl describe pod`.
	AnnotationArgv = "cloop.dev/argv"
	// AnnotationSandboxHash records the .cloop/sandbox.yaml content hash the
	// Pod was shaped by. An annotation rather than a label: it is for reading,
	// not selecting, and a 64-character hash exceeds the label value cap.
	AnnotationSandboxHash = "cloop.dev/sandbox-hash"
)

// LabelEgress declares whether this workload is supposed to reach the network:
// "deny" when the project's sandbox spec asked for no egress, "allow"
// otherwise.
//
// It is a *label*, unlike the sandbox hash, precisely so a NetworkPolicy can
// select on it. A Pod spec has no field that turns egress off; only a
// NetworkPolicy does, so the driver states the intent in the one place an
// enforcement mechanism can read it.
//
// What enforces it depends on configuration, and the difference is worth being
// exact about. With executors.kubernetes.egress_filter enabled, this driver
// creates the policy itself — one per Pod, selecting that Pod by its handle-id
// label, denying everything when this label reads "deny" (see
// networkpolicy.go). Without it, nothing here enforces anything: the label is
// documentation for an operator's own namespace-wide default-deny policy, and a
// namespace without one leaves every Pod with the cluster's full egress.
//
// The alternative was to refuse every sandbox spec that omits
// capabilities.network on Kubernetes, which is nearly all of them — a
// guarantee bought by making the executor unusable is not a trade worth making
// silently either.
const LabelEgress = "cloop.dev/egress"

const (
	// ContainerName is the harness container's name. Fixed, because the log
	// endpoint needs to name a container and a Pod with exactly one of them
	// gains nothing from a configurable name.
	ContainerName = "harness"

	// InitContainerName is the workspace provisioner's name. It is a *second*
	// named container in the Pod, so anything that reads a container status by
	// name — podWaitingDetail, classifyPod, the log endpoint — must keep
	// selecting ContainerName and not "the only one".
	InitContainerName = "workspace"

	// PodWorkspace is where the writable workspace volume is mounted, and the
	// container's working directory when the Spec does not override it.
	//
	// Unlike the container driver this is *not* a bind mount of a host path:
	// there is no host to bind from. Either the Spec's Workspace says how the
	// tree gets here (kind git, provisioned by the init container below) or it
	// says "none" and the workload genuinely wants an empty directory.
	PodWorkspace = "/workspace"

	// workspaceVolume and tmpVolume are the two writable mounts that make
	// readOnlyRootFilesystem survivable.
	workspaceVolume = "workspace"
	tmpVolume       = "tmp"

	// DefaultRunAsUser is the UID/GID the harness runs as. 65532 is the
	// "nonroot" user in distroless and Chainguard images, so the default
	// works with the images an operator is most likely to reach for.
	DefaultRunAsUser  int64 = 65532
	DefaultRunAsGroup int64 = 65532

	// maxLabelValue is Kubernetes' hard cap on a label value.
	maxLabelValue = 63
	// maxGenerateName leaves room for the five random characters the API
	// server appends, within the 63-character name limit.
	maxGenerateName = 63 - 6
)

// The environment the workspace init container reads its credential from.
//
// These names are the contract between this driver and `cloop workspace
// provision`, which reads them from here rather than repeating the literals —
// the driver that emits the argv owns the names. They are here rather
// than in pkg/executor because they are a *delivery* detail — the remote agent
// runs the same plan by handing GitCredentialEnv straight to a child process
// and needs no environment names at all — and because the Pod object is where
// the names have to be spelled out.
const (
	// EnvWorkspaceToken carries the credential. It is *only* ever set through
	// valueFrom.secretKeyRef: a value: entry here would put the token into the
	// Pod object, which anybody with `get pods` in the namespace can read, and
	// into every audit log and `kubectl describe` that follows.
	//
	// It carries the bare token rather than a rendered "Basic <b64>"
	// Authorization header. Base64 is not protection — the header form is
	// exactly as recoverable — so the choice is decided by which one keeps a
	// single construction path: the provisioner rebuilds an
	// executor.GitCredential and calls executor.GitCredentialEnv, the same
	// function the remote agent calls, so the header is rendered by one piece
	// of code for every driver. Delivering a pre-rendered header would mean a
	// second renderer that could drift from the first.
	EnvWorkspaceToken = "CLOOP_WORKSPACE_TOKEN"
	// EnvWorkspaceUser carries the basic-auth username. For a forge token it
	// is the literal "x-access-token"; with a git proxy interposed it is the
	// proxy session's id, which is how the proxy finds the session. Neither is
	// secret, but whenever there is a credential the value comes from the same
	// per-run Secret as the token, so the pair is never split across objects.
	EnvWorkspaceUser = "CLOOP_WORKSPACE_USER"

	// defaultWorkspaceUser matches secretbroker.GitHubUsername. It is
	// duplicated rather than imported: this package must not depend on the
	// hub's secret store (see the credential-source interface in
	// pkg/executor), and the CLI defaults to the same literal when the
	// variable is absent, so a mismatch cannot be silent.
	defaultWorkspaceUser = "x-access-token"

	// cloopCommand is the fallback program name for the init container when
	// the harness's own argv[0] does not name an absolute cloop binary.
	//
	// The container driver has ContainerCloopPath = /usr/local/bin/cloop, but
	// that constant exists because that driver *bind-mounts* the control
	// plane's binary at a path it chooses. Nothing is bind-mounted here, so
	// where cloop lives is the image's business, and hardcoding a path would
	// make the init container fail on an image whose harness container works
	// perfectly. A bare name is resolved by the kubelet against the image's
	// PATH — exactly what happens to the harness container when a Spec's
	// argv[0] is bare.
	cloopCommand = "cloop"
)

// --- API types --------------------------------------------------------
//
// Only the fields this driver sets or reads are modelled. Unknown fields in a
// server response are dropped by encoding/json, which is what we want: the
// driver must not start behaving differently because a cluster runs a newer
// API version.

type objectMeta struct {
	Name              string            `json:"name,omitempty"`
	GenerateName      string            `json:"generateName,omitempty"`
	Namespace         string            `json:"namespace,omitempty"`
	UID               string            `json:"uid,omitempty"`
	ResourceVersion   string            `json:"resourceVersion,omitempty"`
	CreationTimestamp string            `json:"creationTimestamp,omitempty"`
	DeletionTimestamp string            `json:"deletionTimestamp,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	OwnerReferences   []ownerReference  `json:"ownerReferences,omitempty"`
}

// ownerReference makes the cluster's own garbage collector responsible for an
// object, so that cleanup no longer depends on this process being alive.
//
// It is the answer to the one gap the driver could not close any other way. The
// per-run Secrets hold live credential material and are deleted explicitly when
// the init container finishes — but a control plane killed in between left them
// in the namespace with nothing to reap them, because reaping needs `list
// secrets` and this driver deliberately holds no read access to Secrets at all.
// An ownerReference inverts that: the Secret names the Pod that owns it, and
// when the Pod goes — deleted by the driver, by the orphan sweep, by a node
// eviction, or by an operator with kubectl — the API server's GC deletes the
// Secret without anyone having to look at it. No read authority, no polling, no
// dependence on the hub surviving.
//
// # Why no Controller, and no BlockOwnerDeletion
//
// Both are deliberately left false. Controller is a claim of exclusive
// management used by controllers that adopt objects; nothing here adopts.
// BlockOwnerDeletion is the one that matters for RBAC: setting it true makes
// the API server's OwnerReferencesPermissionEnforcement admission plugin
// require `update` on the owner's finalizers subresource — pods/finalizers —
// which is authority this Role does not have and must not gain to keep the
// no-mutation property the chart documents. Left false, setting an
// ownerReference on create needs no verb beyond the `create` already held.
type ownerReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	// Both are emitted explicitly rather than omitted. They default to false
	// server-side either way, but an operator reading the object should see
	// what this driver decided rather than have to know the default.
	Controller         bool `json:"controller"`
	BlockOwnerDeletion bool `json:"blockOwnerDeletion"`
}

// podOwnerReference builds the reference every per-run object carries.
//
// It returns false when the API server's response carried no UID. That should
// not happen — a created Pod always has one — but an ownerReference with an
// empty UID is rejected by the API server with a validation error that names
// the dependent object rather than the missing UID, so the caller checks and
// creates the dependent unowned instead of failing a run over it.
func podOwnerReference(p *pod) (ownerReference, bool) {
	if p == nil {
		return ownerReference{}, false
	}
	uid := strings.TrimSpace(p.Metadata.UID)
	name := strings.TrimSpace(p.Metadata.Name)
	if uid == "" || name == "" {
		return ownerReference{}, false
	}
	return ownerReference{
		APIVersion:         "v1",
		Kind:               "Pod",
		Name:               name,
		UID:                uid,
		Controller:         false,
		BlockOwnerDeletion: false,
	}, true
}

type pod struct {
	APIVersion string     `json:"apiVersion,omitempty"`
	Kind       string     `json:"kind,omitempty"`
	Metadata   objectMeta `json:"metadata"`
	Spec       podSpec    `json:"spec"`
	Status     podStatus  `json:"status,omitempty"`
}

type podList struct {
	Metadata struct {
		ResourceVersion string `json:"resourceVersion,omitempty"`
	} `json:"metadata"`
	Items []pod `json:"items"`
}

type podSpec struct {
	RestartPolicy                 string            `json:"restartPolicy,omitempty"`
	ServiceAccountName            string            `json:"serviceAccountName,omitempty"`
	AutomountServiceAccountToken  *bool             `json:"automountServiceAccountToken,omitempty"`
	ActiveDeadlineSeconds         *int64            `json:"activeDeadlineSeconds,omitempty"`
	TerminationGracePeriodSeconds *int64            `json:"terminationGracePeriodSeconds,omitempty"`
	NodeSelector                  map[string]string `json:"nodeSelector,omitempty"`
	Tolerations                   []toleration      `json:"tolerations,omitempty"`
	// RuntimeClassName selects a node-level RuntimeClass — the Kubernetes
	// spelling of "run this Pod under Kata rather than runc". Omitted when
	// empty so the cluster's default handler stays in effect.
	RuntimeClassName string              `json:"runtimeClassName,omitempty"`
	ImagePullSecrets []localObjectRef    `json:"imagePullSecrets,omitempty"`
	SecurityContext  *podSecurityContext `json:"securityContext,omitempty"`
	// InitContainers run to completion, in order, before Containers start.
	// Exactly one is ever set here — the workspace provisioner — and only when
	// the Spec asks for a tree to be fetched.
	InitContainers     []container             `json:"initContainers,omitempty"`
	Containers         []container             `json:"containers"`
	Volumes            []volume                `json:"volumes,omitempty"`
	EnableServiceLinks *bool                   `json:"enableServiceLinks,omitempty"`
	DNSPolicy          string                  `json:"dnsPolicy,omitempty"`
	HostNetwork        *bool                   `json:"hostNetwork,omitempty"`
	Priority           *int32                  `json:"priority,omitempty"`
	PriorityClassName  string                  `json:"priorityClassName,omitempty"`
	Affinity           *map[string]interface{} `json:"affinity,omitempty"`
}

type localObjectRef struct {
	Name string `json:"name"`
}

type toleration struct {
	Key               string `json:"key,omitempty"`
	Operator          string `json:"operator,omitempty"`
	Value             string `json:"value,omitempty"`
	Effect            string `json:"effect,omitempty"`
	TolerationSeconds *int64 `json:"tolerationSeconds,omitempty"`
}

type seccompProfile struct {
	Type string `json:"type"`
}

type podSecurityContext struct {
	RunAsNonRoot   *bool           `json:"runAsNonRoot,omitempty"`
	RunAsUser      *int64          `json:"runAsUser,omitempty"`
	RunAsGroup     *int64          `json:"runAsGroup,omitempty"`
	FSGroup        *int64          `json:"fsGroup,omitempty"`
	SeccompProfile *seccompProfile `json:"seccompProfile,omitempty"`
}

type capabilities struct {
	Drop []string `json:"drop,omitempty"`
	Add  []string `json:"add,omitempty"`
}

type containerSecurityContext struct {
	RunAsNonRoot             *bool           `json:"runAsNonRoot,omitempty"`
	RunAsUser                *int64          `json:"runAsUser,omitempty"`
	RunAsGroup               *int64          `json:"runAsGroup,omitempty"`
	AllowPrivilegeEscalation *bool           `json:"allowPrivilegeEscalation,omitempty"`
	ReadOnlyRootFilesystem   *bool           `json:"readOnlyRootFilesystem,omitempty"`
	Privileged               *bool           `json:"privileged,omitempty"`
	Capabilities             *capabilities   `json:"capabilities,omitempty"`
	SeccompProfile           *seccompProfile `json:"seccompProfile,omitempty"`
}

type envVar struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	// ValueFrom sources the value from elsewhere in the cluster instead of
	// spelling it out in the Pod. It is the only way a credential is allowed
	// into a container here: the workspace token (EnvWorkspaceToken) and every
	// variable of Spec.Env (leaseenv.go) arrive this way.
	ValueFrom *envVarSource `json:"valueFrom,omitempty"`
}

// envVarSource is the indirection. Only the Secret case is modelled: a
// ConfigMap or a field reference would be a value the driver could just as
// well have written inline, so neither has a caller.
//
// It is deliberately not envFrom, which would import every key of a Secret —
// the lease Secret's credential *files* among them — as environment variables.
// Each variable names its own key.
type envVarSource struct {
	SecretKeyRef *secretKeySelector `json:"secretKeyRef,omitempty"`
}

type secretKeySelector struct {
	Name string `json:"name"`
	Key  string `json:"key"`
	// Optional is set explicitly false on every reference to the lease
	// Secret. It is the server's default either way, but the decision is
	// load-bearing — an optional reference to a missing key starts the
	// container without the variable, and a harness missing its credential
	// fails for a reason nothing names — so the object states it rather than
	// leaving an operator to know the default.
	Optional *bool `json:"optional,omitempty"`
}

type resourceList map[string]string

type resourceRequirements struct {
	Requests resourceList `json:"requests,omitempty"`
	Limits   resourceList `json:"limits,omitempty"`
}

type volumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
	// SubPath mounts one directory *within* the volume at MountPath. It is
	// how a per-project sandbox's workspace-relative mount is expressed here:
	// the container driver binds <workdir>/<source>, and the kubelet mounts
	// the same sub-path of the workspace volume, so one spec means the same
	// thing on both.
	SubPath string `json:"subPath,omitempty"`
}

type emptyDirSource struct {
	Medium    string `json:"medium,omitempty"`
	SizeLimit string `json:"sizeLimit,omitempty"`
}

type volume struct {
	Name     string          `json:"name"`
	EmptyDir *emptyDirSource `json:"emptyDir,omitempty"`
	// Secret projects a Secret's keys as files. It is how a lease's credential
	// files reach the workload — see secretfiles.go — and the kubelet backs
	// such a volume with tmpfs, so the material never touches a node's disk.
	Secret *secretSource `json:"secret,omitempty"`
	// ConfigMap projects a ConfigMap's keys as files. Its one use is the CA
	// bundle a workload's git verifies the hub's git proxy against — public
	// material, which is why it is not a Secret. See cabundle.go.
	ConfigMap *configMapSource `json:"configMap,omitempty"`
}

// configMapSource projects a ConfigMap as a directory of files.
type configMapSource struct {
	Name        string      `json:"name"`
	Items       []keyToPath `json:"items,omitempty"`
	DefaultMode *int32      `json:"defaultMode,omitempty"`
	// Optional is always false, for the reason secretSource's is: a missing
	// bundle must hold the Pod at ContainerCreating, not start a workload
	// whose first fetch fails on a certificate.
	Optional *bool `json:"optional,omitempty"`
}

// secretSource projects a Secret as a directory of files.
//
// Items is not optional in practice: without it the kubelet writes every key in
// the Secret, under the key's own name. This driver stores one lease's files
// under prefixed keys so that two directories cannot collide, so the mapping
// back to the bare name the workload expects has to be spelled out.
type secretSource struct {
	SecretName string      `json:"secretName"`
	Items      []keyToPath `json:"items,omitempty"`
	// DefaultMode is the permission bits the kubelet creates the files with,
	// as a decimal number in JSON. See secretFileMode for why it is 0400 and
	// not the 0600 executor.SecretFile asks for.
	DefaultMode *int32 `json:"defaultMode,omitempty"`
	// Optional is deliberately always false. A missing Secret must park the
	// Pod in ContainerCreating, not start a workload whose credential
	// directory is silently empty — which is the exact failure mode
	// Spec.SecretFiles exists to remove.
	Optional *bool `json:"optional,omitempty"`
}

// keyToPath maps one Secret key onto the file name it is written as.
type keyToPath struct {
	Key  string `json:"key"`
	Path string `json:"path"`
	// Mode overrides the volume's defaultMode for this one file. Set only for
	// a file that has to be executed; see secretExecFileMode.
	Mode *int32 `json:"mode,omitempty"`
}

type container struct {
	Name            string                    `json:"name"`
	Image           string                    `json:"image"`
	ImagePullPolicy string                    `json:"imagePullPolicy,omitempty"`
	Command         []string                  `json:"command,omitempty"`
	Args            []string                  `json:"args,omitempty"`
	WorkingDir      string                    `json:"workingDir,omitempty"`
	Env             []envVar                  `json:"env,omitempty"`
	Resources       resourceRequirements      `json:"resources,omitempty"`
	VolumeMounts    []volumeMount             `json:"volumeMounts,omitempty"`
	SecurityContext *containerSecurityContext `json:"securityContext,omitempty"`
	TTY             *bool                     `json:"tty,omitempty"`
}

type podStatus struct {
	Phase     string `json:"phase,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Message   string `json:"message,omitempty"`
	StartTime string `json:"startTime,omitempty"`
	// PodIP is the address the Pod holds on the cluster network. Nothing in the
	// harness path reads it — a harness Pod is reached through its log stream,
	// never dialled — and it exists for the enforcement probe, which has to
	// give one throwaway Pod an address to aim at without inventing a Service
	// to resolve it by name. See netpolprobe.go.
	PodIP string `json:"podIP,omitempty"`
	// InitContainerStatuses is how the driver learns that provisioning
	// finished. It is a separate list from ContainerStatuses, so code that
	// only reads the latter sees a Pod that is Pending with no container
	// status at all for the whole of the fetch.
	InitContainerStatuses []containerStatus `json:"initContainerStatuses,omitempty"`
	ContainerStatuses     []containerStatus `json:"containerStatuses,omitempty"`
	Conditions            []podCondition    `json:"conditions,omitempty"`
}

type podCondition struct {
	Type    string `json:"type,omitempty"`
	Status  string `json:"status,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type containerStatus struct {
	Name         string         `json:"name,omitempty"`
	Ready        bool           `json:"ready,omitempty"`
	RestartCount int            `json:"restartCount,omitempty"`
	State        containerState `json:"state,omitempty"`
}

type containerState struct {
	Waiting    *stateWaiting    `json:"waiting,omitempty"`
	Running    *stateRunning    `json:"running,omitempty"`
	Terminated *stateTerminated `json:"terminated,omitempty"`
}

type stateWaiting struct {
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type stateRunning struct {
	StartedAt string `json:"startedAt,omitempty"`
}

type stateTerminated struct {
	ExitCode   int    `json:"exitCode"`
	Signal     int    `json:"signal,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Message    string `json:"message,omitempty"`
	FinishedAt string `json:"finishedAt,omitempty"`
}

// Pod phases, as strings so no enum mapping is needed.
const (
	phasePending   = "Pending"
	phaseRunning   = "Running"
	phaseSucceeded = "Succeeded"
	phaseFailed    = "Failed"
	phaseUnknown   = "Unknown"
)

// terminalPhase reports whether the Pod will not transition again.
func terminalPhase(p string) bool { return p == phaseSucceeded || p == phaseFailed }

// harnessStatus returns the harness container's status, if the kubelet has
// reported one yet.
func (p *pod) harnessStatus() *containerStatus {
	if p == nil {
		return nil
	}
	for i := range p.Status.ContainerStatuses {
		if p.Status.ContainerStatuses[i].Name == ContainerName {
			return &p.Status.ContainerStatuses[i]
		}
	}
	if len(p.Status.ContainerStatuses) == 1 {
		return &p.Status.ContainerStatuses[0]
	}
	return nil
}

// workspaceInitStatus returns the provisioner's status, if the kubelet has
// reported one. Unlike harnessStatus there is no "the only one" fallback: an
// unnamed init container status is not something to guess at, because acting
// on it deletes the credential Secret.
func (p *pod) workspaceInitStatus() *containerStatus {
	if p == nil {
		return nil
	}
	for i := range p.Status.InitContainerStatuses {
		if p.Status.InitContainerStatuses[i].Name == InitContainerName {
			return &p.Status.InitContainerStatuses[i]
		}
	}
	return nil
}

// --- build ------------------------------------------------------------

// podRequest is everything buildPod needs. It is a struct rather than a long
// parameter list so a new confinement knob cannot be added at a call site
// without appearing here.
type podRequest struct {
	ExecutorID string
	HandleID   string
	Namespace  string
	Image      string
	// ImagePullPolicy is "" (cluster default), "Always", "IfNotPresent" or
	// "Never".
	ImagePullPolicy    string
	ServiceAccountName string
	ImagePullSecrets   []string
	NodeSelector       map[string]string
	Tolerations        []Toleration
	// RuntimeClass names a RuntimeClass to run the Pod under. Empty leaves
	// the cluster default. A Kata class here is what makes the Pod a VM.
	RuntimeClass string

	Argv []string
	// Env is the Spec's environment. None of it is written into the Pod:
	// every variable becomes a secretKeyRef into the Secret named by
	// LeaseSecretName, which the caller creates from the same list. See
	// leaseenv.go.
	Env     []string
	WorkDir string
	Labels  map[string]string

	CPURequest    string
	CPULimit      string
	MemoryRequest string
	MemoryLimit   string
	// EphemeralStorageLimit bounds the writable emptyDir plus the container's
	// logs, which is the closest Kubernetes analogue to a disk quota.
	EphemeralStorageLimit string
	// WorkspaceSizeLimit bounds the workspace emptyDir specifically.
	WorkspaceSizeLimit string

	ActiveDeadlineSeconds         int64
	TerminationGracePeriodSeconds int64

	RunAsUser  int64
	RunAsGroup int64

	// SandboxMounts re-expose sub-paths of the workspace volume elsewhere in
	// the container, from the project's .cloop/sandbox.yaml.
	SandboxMounts []executor.SpecMount
	// SandboxHash is the spec's content hash, recorded as an annotation so a
	// Pod can be traced back to the file that shaped it.
	SandboxHash string
	// DisableNetwork marks the Pod as one that should not reach the network.
	// See LabelEgress for what this driver can and cannot enforce.
	DisableNetwork bool

	// EgressScope is the project's own request to confine its reach, from
	// .cloop/sandbox.yaml's capabilities.egress. It is resolved against the
	// executor's configured filter by EgressFilter.forScope, and can only ever
	// narrow — including turning an executor with no filter at all into one
	// that installs a policy for this Pod alone.
	//
	// Placement has already refused this Pod if the scope needs a filter and
	// the executor could not prove it enforces one, so by the time a scope
	// arrives here the object about to be built is known to bite.
	EgressScope executor.EgressScope

	// EgressRules is the firewall the hub composed for this Pod from the rule
	// sets stored in the control plane (Task 20363); it supersedes EgressScope.
	// Start has proven it fits inside this executor's filter and the device's,
	// and refused it unless the cluster is known to enforce NetworkPolicy.
	EgressRules *executor.FirewallRules

	// Workspace says how the source tree gets into the workspace volume. It
	// never holds a credential — only the name of a grant — so it is safe to
	// keep in a struct that ends up in an annotation and a log line.
	Workspace executor.Workspace
	// WriteBack says how the files the harness changes get back to the hub.
	// The commit the returned range is measured against is Workspace.Ref,
	// which Spec.Validate requires to be an exact SHA whenever a write-back is
	// asked for. See buildWriteBackArgv.
	WriteBack executor.WriteBack
	// WorkspaceSecretName is the Secret the caller has already created holding
	// the leased credential, or "" for an unauthenticated fetch. buildPod does
	// not create it and cannot: it is pure. It only wires the reference.
	WorkspaceSecretName string

	// SecretFiles are the credential files a secret lease produced, which the
	// workload's environment already points at by absolute path. Only their
	// Dirs and Names are read here — the content goes into the Secret named by
	// LeaseSecretName, which the caller creates right after the Pod — but the
	// whole slice travels so that one derivation decides both the Secret's keys
	// and the volume items that map them back. See secretfiles.go.
	//
	// Anything printed from a podRequest is safe from SecretFiles: their
	// String and GoString redact the content. Env is not — it holds the values
	// themselves — so a podRequest is never formatted with %v.
	SecretFiles []executor.SecretFile
	// LeaseSecretName is the per-run Secret holding those files' bytes, every
	// value of Env and the project seed. Empty when there is none of them.
	LeaseSecretName string

	// ProjectSeed reports that the run carries the hub's project state
	// (Spec.ProjectSeed). Only its presence is read here: the bytes travel in
	// the lease Secret under projectSeedKey, which the caller creates. When it
	// is set the workspace init container places the seed after its checkout,
	// and the harness is wrapped so the run's changes come back as a
	// resultframe block at the end of the log, tagged with HandleID. See
	// projectresult.go.
	ProjectSeed bool

	// GitCABundle is the CA bundle both containers' git verifies particular
	// URLs against — the hub's git proxy, typically. See cabundle.go.
	GitCABundle GitCABundle
}

// egressLabelValue renders DisableNetwork for LabelEgress.
func egressLabelValue(disabled bool) string {
	if disabled {
		return "deny"
	}
	return "allow"
}

// buildPod assembles the Pod object. It never returns a partially-confined
// Pod: any input it cannot express safely is an error.
func buildPod(req podRequest) (*pod, error) {
	if len(req.Argv) == 0 {
		return nil, fmt.Errorf("%w: argv is empty", executor.ErrInvalidSpec)
	}
	if strings.TrimSpace(req.Image) == "" {
		return nil, fmt.Errorf("%w: kubernetes executor requires an image", executor.ErrInvalidSpec)
	}
	if strings.TrimSpace(req.Namespace) == "" {
		return nil, fmt.Errorf("%w: kubernetes executor requires a namespace", executor.ErrInvalidSpec)
	}

	// The workspace volume's root is owned by root — an emptyDir is, whatever
	// runAsUser says — and git refuses a work tree another user owns, so the
	// harness's own git trusts exactly that path. Root is the one owner that
	// check protects nothing against (gitprovision.RootOwnedTrust, which cloop's
	// own git applies by itself). Then the CA bundle, scoped per URL.
	//
	// Those two are the only plain values in the harness's environment. Every
	// variable of the Spec's own is a reference into the lease Secret, so no
	// credential it carries is in the object anyone with `get pods` can read.
	harnessGit := append([][2]string{{"safe.directory", PodWorkspace}}, req.GitCABundle.gitConfigPairs()...)
	env, err := harnessEnv(req.LeaseSecretName, req.Env, harnessGit)
	if err != nil {
		return nil, err
	}

	runAsUser := req.RunAsUser
	if runAsUser <= 0 {
		runAsUser = DefaultRunAsUser
	}
	runAsGroup := req.RunAsGroup
	if runAsGroup <= 0 {
		runAsGroup = DefaultRunAsGroup
	}
	// runAsNonRoot plus UID 0 is a contradiction the kubelet resolves by
	// refusing to start the Pod, with an error that reads like an image
	// problem. Catch it here where the cause is obvious.
	if runAsUser == 0 {
		return nil, fmt.Errorf("%w: run_as_user must not be 0 — this executor always sets runAsNonRoot",
			executor.ErrInvalidSpec)
	}

	workDir := strings.TrimSpace(req.WorkDir)
	if workDir == "" {
		workDir = PodWorkspace
	}
	if !strings.HasPrefix(workDir, "/") {
		return nil, fmt.Errorf("%w: work_dir %q must be an absolute path inside the Pod", executor.ErrInvalidSpec, workDir)
	}

	// The workspace is checked before anything is built, because the answer
	// changes what the Pod *is* — one container or two — and a half-decided
	// Pod is the thing this function exists not to produce.
	if err := req.Workspace.Validate(); err != nil {
		return nil, err
	}
	if req.Workspace.Kind == executor.WorkspaceBind {
		// bind means "the tree is already at WorkDir because the executor
		// shares the control plane's filesystem". This one does not: WorkDir
		// names a path inside a Pod on a node, backed by an emptyDir. Accepting
		// it would start the harness in an empty directory and produce a run
		// that looks fine and operated on nothing — the exact failure
		// Spec.Workspace was added to make impossible.
		return nil, fmt.Errorf("%w: workspace kind %q needs an executor that shares the control "+
			"plane's filesystem, and a Pod does not — use kind git with a repo, or kind none for "+
			"an intentionally empty tree", executor.ErrInvalidSpec, executor.WorkspaceBind)
	}
	if req.Workspace.Kind.KeepsWorkDir() {
		// The promise this kind makes is that the directory survives between
		// dispatches, so a repository the harness cloned for one task is still
		// there for the next. A Pod's working tree is an emptyDir that dies with
		// the Pod. The project itself could be re-established in a fresh one —
		// a seed now travels with every run (projectresult.go) — but everything
		// else the previous run left there could not, and the next run would
		// find it gone without being told. So this is refused rather than
		// approximated.
		return nil, fmt.Errorf("%w: workspace kind %q keeps the working directory on the "+
			"executor between runs, and a Pod's is an emptyDir that does not outlive it — "+
			"give the project a git remote so its tree can be fetched per run, or bind it to "+
			"a remote agent, which does keep one", executor.ErrInvalidSpec, req.Workspace.Kind)
	}

	// The seed is placed by the workspace init container, which exists only
	// for a fetched tree, and read from the lease Secret, which the caller has
	// to have created for it. Either missing is a Pod whose harness would start
	// in a directory with no project — refused here, before it exists.
	if req.ProjectSeed {
		if err := checkSeedDelivery(req); err != nil {
			return nil, err
		}
	}

	labels := map[string]string{
		LabelManaged:    "true",
		LabelExecutorID: sanitizeLabelValue(req.ExecutorID),
		LabelHandleID:   sanitizeLabelValue(req.HandleID),
		LabelTaskID:     sanitizeLabelValue(taskIDFrom(req.Labels)),
		LabelProject:    sanitizeLabelValue(projectSlug(req.Labels["project"])),
		LabelEgress:     egressLabelValue(req.DisableNetwork),
	}
	annotations := map[string]string{
		AnnotationArgv: firstLine(strings.Join(req.Argv, " ")),
	}
	if p := strings.TrimSpace(req.Labels["project"]); p != "" {
		annotations[AnnotationProjectPath] = p
	}

	truePtr, falsePtr := boolPtr(true), boolPtr(false)
	seccomp := &seccompProfile{Type: "RuntimeDefault"}

	// A project's own disk allowance is more specific than the executor's
	// configured default, so it wins — the same precedence Spec.ResourceLimits
	// gets over Options elsewhere in this driver.
	workspaceSize := strings.TrimSpace(req.WorkspaceSizeLimit)
	if q := quantityFromMB(req.Workspace.SizeLimitMB); q != "" {
		workspaceSize = q
	}

	spec := podSpec{
		RestartPolicy:      "Never",
		ServiceAccountName: strings.TrimSpace(req.ServiceAccountName),
		// The whole point: no in-cluster API credential is mounted, even
		// when a ServiceAccount is named for image-pull or PSA purposes.
		AutomountServiceAccountToken: falsePtr,
		// Service-link env vars leak the namespace's Service topology into
		// the workload's environment for free. Nothing needs them here.
		EnableServiceLinks: falsePtr,
		HostNetwork:        falsePtr,
		NodeSelector:       copyStringMap(req.NodeSelector),
		RuntimeClassName:   strings.TrimSpace(req.RuntimeClass),
		SecurityContext: &podSecurityContext{
			RunAsNonRoot:   truePtr,
			RunAsUser:      &runAsUser,
			RunAsGroup:     &runAsGroup,
			FSGroup:        &runAsGroup,
			SeccompProfile: seccomp,
		},
		Volumes: []volume{
			{Name: workspaceVolume, EmptyDir: &emptyDirSource{SizeLimit: workspaceSize}},
			{Name: tmpVolume, EmptyDir: &emptyDirSource{}},
		},
	}
	if req.ActiveDeadlineSeconds > 0 {
		d := req.ActiveDeadlineSeconds
		spec.ActiveDeadlineSeconds = &d
	}
	if req.TerminationGracePeriodSeconds >= 0 {
		g := req.TerminationGracePeriodSeconds
		spec.TerminationGracePeriodSeconds = &g
	}
	for _, name := range req.ImagePullSecrets {
		if n := strings.TrimSpace(name); n != "" {
			spec.ImagePullSecrets = append(spec.ImagePullSecrets, localObjectRef{Name: n})
		}
	}
	for _, t := range req.Tolerations {
		spec.Tolerations = append(spec.Tolerations, t.toAPI())
	}

	res := resourceRequirements{}
	if v := strings.TrimSpace(req.CPURequest); v != "" {
		res.ensureRequests()["cpu"] = v
	}
	if v := strings.TrimSpace(req.MemoryRequest); v != "" {
		res.ensureRequests()["memory"] = v
	}
	if v := strings.TrimSpace(req.CPULimit); v != "" {
		res.ensureLimits()["cpu"] = v
	}
	if v := strings.TrimSpace(req.MemoryLimit); v != "" {
		res.ensureLimits()["memory"] = v
	}
	if v := strings.TrimSpace(req.EphemeralStorageLimit); v != "" {
		res.ensureLimits()["ephemeral-storage"] = v
	}

	// The workspace mount must cover the working directory, or a
	// readOnlyRootFilesystem container cannot write where it runs.
	mounts := []volumeMount{
		{Name: workspaceVolume, MountPath: PodWorkspace},
		{Name: tmpVolume, MountPath: "/tmp"},
	}
	if workDir != PodWorkspace && !strings.HasPrefix(workDir, PodWorkspace+"/") {
		return nil, fmt.Errorf("%w: work_dir %q is outside the writable workspace at %s — "+
			"the Pod's root filesystem is read-only, so nothing else is writable",
			executor.ErrInvalidSpec, workDir, PodWorkspace)
	}

	// Per-project sandbox mounts. Each becomes a subPath on the workspace
	// volume, which is precisely the containment executor.SpecMount promises:
	// the kubelet resolves the sub-path inside the volume, so a source that
	// somehow escaped validation still cannot name anything outside it.
	if err := executor.ValidateSpecMounts(req.SandboxMounts); err != nil {
		return nil, err
	}
	for _, m := range req.SandboxMounts {
		target := strings.TrimSpace(m.Target)
		if target == PodWorkspace || target == "/tmp" {
			return nil, fmt.Errorf("%w: sandbox mount target %q would shadow the %s volume",
				executor.ErrInvalidSpec, target, target)
		}
		mounts = append(mounts, volumeMount{
			Name:      workspaceVolume,
			MountPath: target,
			SubPath:   strings.TrimSpace(m.Source),
			ReadOnly:  m.ReadOnly,
		})
	}
	if h := strings.TrimSpace(req.SandboxHash); h != "" {
		annotations[AnnotationSandboxHash] = sanitizeLabelValue(h)
	}

	// A secret lease's credential files, projected from the Secret the caller
	// created before this Pod. They go to the harness container and to nothing
	// else — the workspace provisioner below builds its own mount list and has
	// no business holding a credential its git fetch does not use.
	secretVolumes, secretMounts, err := secretFileVolumes(req.LeaseSecretName, req.SecretFiles)
	if err != nil {
		return nil, err
	}
	for _, m := range secretMounts {
		// The lease directory is /run/cloop/cloop-lease-<hex>, so a collision
		// with the writable volumes cannot happen in practice. Checked anyway,
		// because the failure it would produce — a workspace shadowed by a
		// read-only credential directory — reads as an empty checkout rather
		// than as a mount problem.
		if m.MountPath == PodWorkspace || m.MountPath == "/tmp" {
			return nil, fmt.Errorf("%w: secret lease directory %q would shadow the %s volume",
				executor.ErrInvalidSpec, m.MountPath, m.MountPath)
		}
		if req.ProjectSeed && (m.MountPath == seedMountDir || m.MountPath == dispatchMountDir) {
			return nil, fmt.Errorf("%w: secret lease directory %q would shadow the directory the "+
				"project seed is delivered through", executor.ErrInvalidSpec, m.MountPath)
		}
	}
	spec.Volumes = append(spec.Volumes, secretVolumes...)
	mounts = append(mounts, secretMounts...)

	// The project seed's two volumes. The Secret volume carrying it is mounted
	// in the init container alone (buildWorkspaceInitContainer); the harness
	// gets the copy the init container leaves, read-only, which is what the
	// wrapper measures the run's changes against.
	if req.ProjectSeed {
		spec.Volumes = append(spec.Volumes, seedVolumes(req.LeaseSecretName)...)
		mounts = append(mounts, volumeMount{Name: dispatchVolume, MountPath: dispatchMountDir, ReadOnly: true})
	}

	// The CA bundle, in both containers: the provisioner fetches through the
	// proxy and the harness pushes through it. Scoped per URL in the
	// environment, so every other host keeps the image's trust store.
	gitCAPairs := req.GitCABundle.gitConfigPairs()
	if len(gitCAPairs) > 0 {
		spec.Volumes = append(spec.Volumes, req.GitCABundle.volume())
		mounts = append(mounts, req.GitCABundle.mount())
	}

	// The harness argv, possibly wrapped so the work it produces — the files it
	// changed, the project state it recorded — survives the Pod. See
	// buildWriteBackArgv for why a wrapper is the only place a Kubernetes Pod
	// can run anything after its main container.
	harnessArgv, err := buildWriteBackArgv(req, workDir)
	if err != nil {
		return nil, err
	}
	// The write-back's credential goes to the harness container, because that
	// is where the push runs — but it reaches `cloop workspace writeback`
	// before the harness is spawned and is removed from the environment there,
	// so the harness itself never sees it. See cmd/workspace_writeback_cmd.go.
	if req.WriteBack.Mode == executor.WriteBackPush {
		wbEnv, err := workspaceCredentialEnv(req)
		if err != nil {
			return nil, err
		}
		env = append(env, wbEnv...)
	}

	spec.Containers = []container{{
		Name:            ContainerName,
		Image:           strings.TrimSpace(req.Image),
		ImagePullPolicy: strings.TrimSpace(req.ImagePullPolicy),
		Command:         []string{harnessArgv[0]},
		Args:            append([]string(nil), harnessArgv[1:]...),
		WorkingDir:      workDir,
		Env:             env,
		Resources:       res,
		VolumeMounts:    mounts,
		SecurityContext: confinedSecurityContext(runAsUser, runAsGroup),
	}}

	if req.Workspace.NeedsProvisioning() {
		provisioner, err := buildWorkspaceInitContainer(req, workDir, runAsUser, runAsGroup, res)
		if err != nil {
			return nil, err
		}
		spec.InitContainers = []container{*provisioner}
	}

	return &pod{
		APIVersion: "v1",
		Kind:       "Pod",
		Metadata: objectMeta{
			GenerateName: generateNameFor(req.Labels["project"], req.ExecutorID),
			Namespace:    req.Namespace,
			Labels:       labels,
			Annotations:  annotations,
		},
		Spec: spec,
	}, nil
}

// confinedSecurityContext is the container-scoped confinement, in one place.
//
// It is a function rather than two struct literals because the Pod now has two
// containers and they must be confined identically. A workspace provisioner
// that ran with one capability more than the harness would be a way to do
// privileged work in a Pod that reads as hardened — and the drift would be
// invisible, because the two literals would sit two hundred lines apart and
// each look correct on its own.
func confinedSecurityContext(runAsUser, runAsGroup int64) *containerSecurityContext {
	return &containerSecurityContext{
		RunAsNonRoot:             boolPtr(true),
		RunAsUser:                &runAsUser,
		RunAsGroup:               &runAsGroup,
		AllowPrivilegeEscalation: boolPtr(false),
		ReadOnlyRootFilesystem:   boolPtr(true),
		Privileged:               boolPtr(false),
		Capabilities:             &capabilities{Drop: []string{"ALL"}},
		SeccompProfile:           &seccompProfile{Type: "RuntimeDefault"},
	}
}

// buildWorkspaceInitContainer renders the container that fetches the source
// tree before the harness starts.
//
// Four decisions are worth stating, because each had a plausible alternative:
//
//   - It uses the *harness image*, not a git image. A second image would need
//     its own entry in the operator's registry allowlist, its own digest pin,
//     and its own trip through the image trust policy — three places for the
//     provenance of the thing that handles a credential to diverge from the
//     provenance of everything else. Reusing the harness image means the
//     policy that already approved it approves this too, and there is nothing
//     extra to configure.
//   - It provisions into workDir, not into PodWorkspace. When a Spec puts the
//     harness in a sub-directory of the workspace volume, cloning into the
//     volume root would leave the harness's actual working directory empty —
//     the original bug, reproduced one level down. workDir is already
//     guaranteed by the caller to be inside the workspace volume.
//   - It does *not* inherit req.Env. The harness's environment carries
//     brokered provider keys and whatever else the run needs; a git fetch has
//     no business with any of it, and the narrower the environment the fewer
//     ways a hostile repository's hooks can reach something interesting.
//   - Its resources mirror the harness's. Kubernetes takes a Pod's effective
//     request as max(init containers, sum(containers)), so matching costs
//     nothing at schedule time — and a namespace whose ResourceQuota demands
//     limits would otherwise reject the whole Pod for the one container that
//     had none.
func buildWorkspaceInitContainer(req podRequest, workDir string, runAsUser, runAsGroup int64,
	res resourceRequirements) (*container, error) {

	w := req.Workspace
	// GitPlan is not used to build the argv — the provisioning steps run
	// inside the container, from the same plan, by `cloop workspace provision`
	// — but calling it here rejects a workspace that could not produce one
	// before the Pod is created, where the error still reaches the caller
	// instead of a container log nobody is watching.
	if _, err := w.GitPlan(workDir); err != nil {
		return nil, err
	}

	argv := []string{
		workspaceCommand(req.Argv), "workspace", "provision",
		"--dir", workDir,
		"--repo", strings.TrimSpace(w.Repo),
	}
	if ref := strings.TrimSpace(w.Ref); ref != "" {
		argv = append(argv, "--ref", ref)
	}
	if w.Depth > 0 {
		argv = append(argv, "--depth", strconv.Itoa(w.Depth))
	}
	if w.SizeLimitMB > 0 {
		// The emptyDir sizeLimit is enforced by the kubelet, which evicts the
		// Pod when it is exceeded. Telling the provisioner the same number lets
		// it fail the fetch with an explanation instead, which is the
		// difference between "the repository is bigger than the allowance" and
		// a Pod that vanishes mid-run.
		argv = append(argv, "--size-limit-mb", strconv.Itoa(w.SizeLimitMB))
	}
	if req.ProjectSeed {
		// The project, placed into the checkout once it exists, and a copy of
		// it left where the harness's wrapper reads the run's changes back
		// against. Paths, never the bytes: an argv is readable by everyone who
		// can `get pods`.
		argv = append(argv, "--seed", seedMountDir+"/"+seedFileName,
			"--seed-copy", dispatchMountDir+"/"+seedFileName)
	}

	env, err := workspaceCredentialEnv(req)
	if err != nil {
		return nil, err
	}
	mounts := []volumeMount{
		{Name: workspaceVolume, MountPath: PodWorkspace},
		// git needs somewhere to write its temporaries, and the root
		// filesystem is read-only for this container exactly as it is for
		// the harness.
		{Name: tmpVolume, MountPath: "/tmp"},
	}
	if req.ProjectSeed {
		// The seed from the lease Secret, read-only and in this container
		// only; and the dispatch volume, writable here so the copy can be
		// left in it, and read-only in the harness.
		mounts = append(mounts,
			volumeMount{Name: seedVolume, MountPath: seedMountDir, ReadOnly: true},
			volumeMount{Name: dispatchVolume, MountPath: dispatchMountDir})
	}
	// The fetch is the first thing to reach the git proxy, so it needs the
	// bundle as much as the harness does. Plain values: a CA path and the URLs
	// it is for are not credentials.
	if pairs := req.GitCABundle.gitConfigPairs(); len(pairs) > 0 {
		caEnv, err := withGitConfig(nil, pairs)
		if err != nil {
			return nil, err
		}
		for _, kv := range caEnv {
			k, v, _ := strings.Cut(kv, "=")
			env = append(env, envVar{Name: k, Value: v})
		}
		mounts = append(mounts, req.GitCABundle.mount())
	}

	return &container{
		Name:            InitContainerName,
		Image:           strings.TrimSpace(req.Image),
		ImagePullPolicy: strings.TrimSpace(req.ImagePullPolicy),
		Command:         []string{argv[0]},
		Args:            append([]string(nil), argv[1:]...),
		// The volume root, not workDir: `cloop workspace provision` creates
		// the target directory, and a workingDir that does not exist yet is a
		// container the kubelet refuses to start.
		WorkingDir:      PodWorkspace,
		Env:             env,
		Resources:       res,
		VolumeMounts:    mounts,
		SecurityContext: confinedSecurityContext(runAsUser, runAsGroup),
	}, nil
}

// workspaceCommand picks the program the init container runs.
//
// The harness container is started with the Spec's argv[0] verbatim, so the
// most reliable statement anyone has made about where cloop lives in this image
// is that argv. When it is an absolute path to a binary called cloop, use it:
// the operator has already told us. Otherwise fall back to the bare name and
// let the kubelet resolve it against the image's PATH.
//
// The base-name check is what stops a Spec like {"/bin/sh", "-c", ...} — which
// names an interpreter, not the harness — from producing
// `/bin/sh workspace provision`, a failure whose message would point at the
// workspace subsystem for a reason that has nothing to do with it.
func workspaceCommand(argv []string) string {
	if len(argv) == 0 {
		return cloopCommand
	}
	first := strings.TrimSpace(argv[0])
	if strings.HasPrefix(first, "/") && path.Base(first) == cloopCommand {
		return first
	}
	return cloopCommand
}

// workspaceCredentialEnv renders the environment carrying the brokered git
// credential into a container.
//
// One function for both the provisioner and the harness wrapper, because they
// need the identical thing: the fetch and the push authenticate against the
// same host with the same grant. The credential itself never appears in the
// object this file builds — only a secretKeyRef — which is a property asserted
// directly against the marshalled JSON in workspace_test.go.
//
// The username comes from the Secret too, whenever there is one (Task 20349).
// It used to be the fixed literal "x-access-token", which is right for a forge
// token and wrong for a git proxy session: the proxy looks a session up by its
// basic-auth username, which is the session id, so with the proxy on every
// private workspace fetch on Kubernetes was refused with a 401. The session id
// is not a secret, but it is half of a credential pair, and carrying the pair in
// one object keeps the Pod spec free of either half.
func workspaceCredentialEnv(req podRequest) ([]envVar, error) {
	name := strings.TrimSpace(req.WorkspaceSecretName)
	if name == "" {
		return []envVar{{Name: EnvWorkspaceUser, Value: defaultWorkspaceUser}}, nil
	}
	if err := validateDNSSubdomain(name, "workspace secret"); err != nil {
		return nil, fmt.Errorf("%w: %v", executor.ErrInvalidSpec, err)
	}
	return []envVar{
		{
			Name: EnvWorkspaceUser,
			ValueFrom: &envVarSource{SecretKeyRef: &secretKeySelector{
				Name: name,
				Key:  EnvWorkspaceUser,
			}},
		},
		{
			Name: EnvWorkspaceToken,
			ValueFrom: &envVarSource{SecretKeyRef: &secretKeySelector{
				Name: name,
				Key:  EnvWorkspaceToken,
			}},
		},
	}, nil
}

// buildWriteBackArgv returns the harness container's command, wrapped when the
// Spec asks for the work to be returned.
//
// # Why a wrapper
//
// Kubernetes gives a Pod no place to run anything after its main container.
// restartPolicy is Never, init containers run strictly before, a sidecar cannot
// observe another container's exit, and a second Pod cannot see the emptyDir
// that dies with the first. The only moment between "the harness has stopped
// writing" and "the workspace volume no longer exists" is inside the harness
// container itself — so when a write-back is asked for, `cloop workspace
// writeback` becomes the entry point and the real command follows a "--".
//
// The wrapper runs the harness, forwards its output and its signals, waits,
// commits, pushes, and exits with the harness's own status. Three properties
// are preserved deliberately, because each one silently breaking would be worse
// than not wrapping at all:
//
//   - the exit code, which is how the hub decides whether the task failed;
//   - SIGTERM delivery, so the kubelet's shutdown reaches the harness rather
//     than only the wrapper, and the tree is settled before the write-back;
//   - AnnotationArgv, which keeps naming the *real* command, so an operator
//     reading `kubectl describe pod` sees what they dispatched.
//
// The wrapper's own binary comes from the same image and the same argv[0]
// inference the init container uses, so nothing extra has to be installed or
// configured — see workspaceCommand.
//
// A seeded run is wrapped too, write-back or not (Task 20402): the project state
// it records in its copy of the project is the other half of its work product,
// and the wrapper reads it back after the harness and prints it as the last
// thing in the log, which is the one channel home a Pod has.
func buildWriteBackArgv(req podRequest, workDir string) ([]string, error) {
	original := append([]string(nil), req.Argv...)
	wb := req.WriteBack
	if !wb.Enabled() {
		if !req.ProjectSeed {
			return original, nil
		}
		argv := append([]string{workspaceCommand(req.Argv), "workspace", "writeback", "--dir", workDir},
			projectResultFlags(req)...)
		argv = append(argv, "--")
		return append(argv, original...), nil
	}
	if err := wb.Validate(); err != nil {
		return nil, err
	}
	if wb.Mode != executor.WriteBackPush {
		// A bundle would be written to a file inside a Pod that is about to
		// stop existing, and this driver has no way to read it back — its only
		// channel out of a finished Pod is the log stream. Refusing at build
		// time keeps that from becoming a run that reports a bundle nobody can
		// collect.
		return nil, fmt.Errorf("%w: this executor can only write back by pushing; mode %q needs "+
			"a transport that can carry bytes back from the sandbox, which a Pod's log stream "+
			"is not", executor.ErrInvalidSpec, wb.Mode)
	}
	if req.Workspace.Kind != executor.WorkspaceGit {
		return nil, fmt.Errorf("%w: a write-back needs a git workspace to have a branch and an "+
			"origin, and this workload's workspace is %q", executor.ErrInvalidSpec,
			req.Workspace.Kind)
	}
	// The base is the commit the init container checks out, which is exactly
	// Workspace.Ref: Spec.Validate refuses a write-back whose workspace is
	// pinned to anything less precise, so the two sides cannot disagree about
	// what "the changes this task made" is measured against.
	base := strings.TrimSpace(req.Workspace.Ref)
	if err := executor.ValidateCommitSHA(base); err != nil {
		return nil, fmt.Errorf("%w: a write-back needs the workspace pinned to an exact commit, "+
			"and this one's ref is %q: %v", executor.ErrInvalidSpec, req.Workspace.Ref, err)
	}

	argv := []string{
		workspaceCommand(req.Argv), "workspace", "writeback",
		"--dir", workDir,
		"--repo", strings.TrimSpace(req.Workspace.Repo),
		"--branch", strings.TrimSpace(wb.Branch),
		"--base", base,
		"--push",
	}
	if msg := strings.TrimSpace(wb.Message); msg != "" {
		argv = append(argv, "--message", msg)
	}
	if req.ProjectSeed {
		argv = append(argv, projectResultFlags(req)...)
	}
	// "--" so nothing in the harness's own command line can be read as a flag
	// of the wrapper. Without it a harness invoked as `claude --push …` would
	// be parsed partly by cobra.
	argv = append(argv, "--")
	return append(argv, original...), nil
}

func (r *resourceRequirements) ensureRequests() resourceList {
	if r.Requests == nil {
		r.Requests = resourceList{}
	}
	return r.Requests
}

func (r *resourceRequirements) ensureLimits() resourceList {
	if r.Limits == nil {
		r.Limits = resourceList{}
	}
	return r.Limits
}

// validEnvName mirrors Kubernetes' C_IDENTIFIER-ish check for env var names.
func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_', r == '.':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// Toleration is the operator-facing form of a Pod toleration, parsed from
// config. It exists separately from the API type so pkg/config can validate
// one without importing JSON tags it does not care about.
type Toleration struct {
	Key      string `yaml:"key,omitempty" json:"key,omitempty"`
	Operator string `yaml:"operator,omitempty" json:"operator,omitempty"`
	Value    string `yaml:"value,omitempty" json:"value,omitempty"`
	Effect   string `yaml:"effect,omitempty" json:"effect,omitempty"`
	// Seconds is tolerationSeconds; 0 means unset.
	Seconds int64 `yaml:"seconds,omitempty" json:"seconds,omitempty"`
}

func (t Toleration) toAPI() toleration {
	out := toleration{
		Key:      strings.TrimSpace(t.Key),
		Operator: strings.TrimSpace(t.Operator),
		Value:    strings.TrimSpace(t.Value),
		Effect:   strings.TrimSpace(t.Effect),
	}
	if out.Operator == "" {
		// Kubernetes defaults an empty operator to Equal, which with an empty
		// Value silently means "tolerate only the empty value". Being explicit
		// avoids a toleration that looks right and matches nothing.
		if out.Value == "" {
			out.Operator = "Exists"
		} else {
			out.Operator = "Equal"
		}
	}
	if t.Seconds > 0 {
		s := t.Seconds
		out.TolerationSeconds = &s
	}
	return out
}

// Validate checks a toleration against the API's own rules, so a typo is
// caught by `cloop config set` rather than by a Pod that never schedules.
func (t Toleration) Validate() error {
	op := strings.TrimSpace(t.Operator)
	switch op {
	case "", "Equal", "Exists":
	default:
		return fmt.Errorf("toleration operator must be \"Equal\" or \"Exists\" (got %q)", t.Operator)
	}
	switch strings.TrimSpace(t.Effect) {
	case "", "NoSchedule", "PreferNoSchedule", "NoExecute":
	default:
		return fmt.Errorf("toleration effect must be \"NoSchedule\", \"PreferNoSchedule\" or \"NoExecute\" (got %q)", t.Effect)
	}
	if op == "Exists" && strings.TrimSpace(t.Value) != "" {
		return fmt.Errorf("toleration with operator \"Exists\" must not set a value (got %q)", t.Value)
	}
	if strings.TrimSpace(t.Key) == "" && op != "Exists" && op != "" {
		return fmt.Errorf("toleration with an empty key requires operator \"Exists\"")
	}
	if t.Seconds < 0 {
		return fmt.Errorf("toleration seconds must be >= 0 (got %d)", t.Seconds)
	}
	return nil
}

// --- naming -----------------------------------------------------------

// generateNameFor builds the generateName prefix: cloop-<project>-<executor>-.
//
// generateName rather than a name we choose is what makes concurrent starts
// safe: the API server appends five random characters under the uniqueness
// constraint, so two simultaneous runs of the same project cannot collide the
// way a client-generated name can.
func generateNameFor(projectPath, executorID string) string {
	parts := []string{"cloop"}
	if slug := projectSlug(projectPath); slug != "" && slug != "project" {
		parts = append(parts, slug)
	}
	if slug := sanitizeDNSLabel(executorID); slug != "" {
		parts = append(parts, slug)
	}
	name := strings.Join(parts, "-")
	if len(name) > maxGenerateName {
		name = strings.TrimRight(name[:maxGenerateName], "-")
	}
	return name + "-"
}

// projectSlug reduces a project path to its DNS-safe base name.
func projectSlug(projectPath string) string {
	p := strings.TrimSpace(projectPath)
	if p == "" {
		return "project"
	}
	p = strings.TrimRight(p, "/")
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	slug := sanitizeDNSLabel(p)
	if slug == "" {
		return "project"
	}
	return slug
}

// sanitizeDNSLabel maps arbitrary text onto RFC 1123: lowercase alphanumerics
// and dashes, starting and ending with an alphanumeric.
func sanitizeDNSLabel(s string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
		if b.Len() >= 24 {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}

// sanitizeLabelValue makes an arbitrary string usable as a label value:
// at most 63 characters of [A-Za-z0-9_.-], beginning and ending
// alphanumeric. An empty result becomes "none" rather than "", because an
// empty value would drop the Pod out of the GC selector that requires the
// label to exist.
func sanitizeLabelValue(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
		if b.Len() >= maxLabelValue {
			break
		}
	}
	out := strings.Trim(b.String(), "-_.")
	if out == "" {
		return "none"
	}
	return out
}

// taskIDFrom pulls the task identifier out of a Spec's labels. The Web UI
// labels workloads with "task_id" where one exists; "task" is accepted as an
// alias so a caller that used the shorter key is not silently unlabelled.
func taskIDFrom(labels map[string]string) string {
	for _, key := range []string{"task_id", "task", "taskid"} {
		if v := strings.TrimSpace(labels[key]); v != "" {
			return v
		}
	}
	return "none"
}

// executorLabelSelector selects every Pod this executor owns. Requiring the
// task-id label to *exist* (rather than equal something) is what keeps the
// sweep to Pods this driver created: a hand-made Pod that happens to carry a
// matching executor-id but no task-id is not ours to delete.
func executorLabelSelector(executorID string) string {
	return fmt.Sprintf("%s=true,%s=%s,%s",
		LabelManaged, LabelExecutorID, sanitizeLabelValue(executorID), LabelTaskID)
}

func boolPtr(b bool) *bool { return &b }

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// quantityFromMillis renders a CPU allowance in Kubernetes' millicore form.
func quantityFromMillis(millis int) string {
	if millis <= 0 {
		return ""
	}
	return strconv.Itoa(millis) + "m"
}

// quantityFromMB renders a memory or storage allowance in mebibytes.
func quantityFromMB(mb int) string {
	if mb <= 0 {
		return ""
	}
	return strconv.Itoa(mb) + "Mi"
}
