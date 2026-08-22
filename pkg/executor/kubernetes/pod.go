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

import (
	"fmt"
	"sort"
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
// select on it — and that is also the honest limit of what this driver can do.
// A Pod spec has no field that turns egress off; only a NetworkPolicy does, and
// that is a namespace-scoped object owned by the cluster operator. So the
// driver states the intent in the one place the enforcement mechanism can read
// it, and the operator installs the companion default-deny policy (see
// docs/executors.md). Without that policy the label is documentation.
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

	// PodWorkspace is where the writable workspace volume is mounted, and the
	// container's working directory when the Spec does not override it.
	//
	// Unlike the container driver this is *not* a bind mount of a host path:
	// there is no host to bind from. A Kubernetes workload starts with an
	// empty workspace and is expected to populate it (git clone, an artifact
	// fetch) using brokered credentials.
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
	RestartPolicy                 string                  `json:"restartPolicy,omitempty"`
	ServiceAccountName            string                  `json:"serviceAccountName,omitempty"`
	AutomountServiceAccountToken  *bool                   `json:"automountServiceAccountToken,omitempty"`
	ActiveDeadlineSeconds         *int64                  `json:"activeDeadlineSeconds,omitempty"`
	TerminationGracePeriodSeconds *int64                  `json:"terminationGracePeriodSeconds,omitempty"`
	NodeSelector                  map[string]string       `json:"nodeSelector,omitempty"`
	Tolerations                   []toleration            `json:"tolerations,omitempty"`
	ImagePullSecrets              []localObjectRef        `json:"imagePullSecrets,omitempty"`
	SecurityContext               *podSecurityContext     `json:"securityContext,omitempty"`
	Containers                    []container             `json:"containers"`
	Volumes                       []volume                `json:"volumes,omitempty"`
	EnableServiceLinks            *bool                   `json:"enableServiceLinks,omitempty"`
	DNSPolicy                     string                  `json:"dnsPolicy,omitempty"`
	HostNetwork                   *bool                   `json:"hostNetwork,omitempty"`
	Priority                      *int32                  `json:"priority,omitempty"`
	PriorityClassName             string                  `json:"priorityClassName,omitempty"`
	Affinity                      *map[string]interface{} `json:"affinity,omitempty"`
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
	Phase             string            `json:"phase,omitempty"`
	Reason            string            `json:"reason,omitempty"`
	Message           string            `json:"message,omitempty"`
	StartTime         string            `json:"startTime,omitempty"`
	ContainerStatuses []containerStatus `json:"containerStatuses,omitempty"`
	Conditions        []podCondition    `json:"conditions,omitempty"`
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

	Argv    []string
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

	env, err := buildEnv(req.Env)
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
		SecurityContext: &podSecurityContext{
			RunAsNonRoot:   truePtr,
			RunAsUser:      &runAsUser,
			RunAsGroup:     &runAsGroup,
			FSGroup:        &runAsGroup,
			SeccompProfile: seccomp,
		},
		Volumes: []volume{
			{Name: workspaceVolume, EmptyDir: &emptyDirSource{SizeLimit: strings.TrimSpace(req.WorkspaceSizeLimit)}},
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

	spec.Containers = []container{{
		Name:            ContainerName,
		Image:           strings.TrimSpace(req.Image),
		ImagePullPolicy: strings.TrimSpace(req.ImagePullPolicy),
		Command:         []string{req.Argv[0]},
		Args:            append([]string(nil), req.Argv[1:]...),
		WorkingDir:      workDir,
		Env:             env,
		Resources:       res,
		VolumeMounts:    mounts,
		SecurityContext: &containerSecurityContext{
			RunAsNonRoot:             truePtr,
			RunAsUser:                &runAsUser,
			RunAsGroup:               &runAsGroup,
			AllowPrivilegeEscalation: falsePtr,
			ReadOnlyRootFilesystem:   truePtr,
			Privileged:               falsePtr,
			Capabilities:             &capabilities{Drop: []string{"ALL"}},
			SeccompProfile:           seccomp,
		},
	}}

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

// buildEnv converts K=V strings into the API's env list.
//
// Values land in the Pod object, which anyone with `get pods` in the
// namespace can read. That is a real exposure and the reason the driver
// refuses to forward the control plane's own environment implicitly (a nil
// Spec.Env yields nothing here, unlike os/exec). Callers pass what the
// workload needs; the README says so, and `cloop executor test` repeats it.
func buildEnv(kvs []string) ([]envVar, error) {
	if len(kvs) == 0 {
		return nil, nil
	}
	out := make([]envVar, 0, len(kvs))
	seen := make(map[string]struct{}, len(kvs))
	for _, kv := range kvs {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			return nil, fmt.Errorf("%w: env %q is not in K=V form", executor.ErrInvalidSpec, kv)
		}
		name := kv[:i]
		if !validEnvName(name) {
			return nil, fmt.Errorf("%w: env name %q is not a valid Kubernetes env var name", executor.ErrInvalidSpec, name)
		}
		if _, dup := seen[name]; dup {
			// The API server rejects duplicates with a validation error that
			// does not name the variable; say which one here.
			return nil, fmt.Errorf("%w: env %q is set more than once", executor.ErrInvalidSpec, name)
		}
		seen[name] = struct{}{}
		out = append(out, envVar{Name: name, Value: kv[i+1:]})
	}
	// Deterministic order so two identical Specs produce identical Pods,
	// which is what makes buildPod testable by golden comparison.
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
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
