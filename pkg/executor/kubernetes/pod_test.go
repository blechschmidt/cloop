package kubernetes

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// baseRequest is a minimally-valid podRequest for tests that only care about
// one field.
func baseRequest() podRequest {
	return podRequest{
		ExecutorID: "k8s",
		HandleID:   "k-abc123",
		Namespace:  "cloop",
		Image:      "ghcr.io/example/harness@sha256:" + strings.Repeat("a", 64),
		Argv:       []string{"cloop", "run"},
		Labels:     map[string]string{"project": "/srv/app", "task_id": "42"},
	}
}

// TestBuildPod_ConfinementIsUnconditional is the security-critical test: the
// hardening in buildPod must not depend on any option. If a future change
// makes one of these configurable, this fails.
func TestBuildPod_ConfinementIsUnconditional(t *testing.T) {
	p, err := buildPod(baseRequest())
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}

	if p.Spec.RestartPolicy != "Never" {
		t.Errorf("restartPolicy = %q, want Never — a restarting Pod re-runs a task whose side effects already landed",
			p.Spec.RestartPolicy)
	}
	if p.Spec.AutomountServiceAccountToken == nil || *p.Spec.AutomountServiceAccountToken {
		t.Error("automountServiceAccountToken must be explicitly false; otherwise the kubelet " +
			"hands model-authored code an in-cluster API credential nobody granted it")
	}
	if p.Spec.EnableServiceLinks == nil || *p.Spec.EnableServiceLinks {
		t.Error("enableServiceLinks must be false so the namespace's Service topology does not leak into the environment")
	}
	if p.Spec.HostNetwork == nil || *p.Spec.HostNetwork {
		t.Error("hostNetwork must be explicitly false")
	}

	psc := p.Spec.SecurityContext
	if psc == nil {
		t.Fatal("pod securityContext is nil")
	}
	if psc.RunAsNonRoot == nil || !*psc.RunAsNonRoot {
		t.Error("pod runAsNonRoot must be true")
	}
	if psc.RunAsUser == nil || *psc.RunAsUser != DefaultRunAsUser {
		t.Errorf("pod runAsUser = %v, want %d", psc.RunAsUser, DefaultRunAsUser)
	}
	if psc.SeccompProfile == nil || psc.SeccompProfile.Type != "RuntimeDefault" {
		t.Error("pod seccompProfile must be RuntimeDefault")
	}

	if len(p.Spec.Containers) != 1 {
		t.Fatalf("got %d containers, want exactly 1", len(p.Spec.Containers))
	}
	c := p.Spec.Containers[0]
	if c.Name != ContainerName {
		t.Errorf("container name = %q, want %q (the log endpoint names it)", c.Name, ContainerName)
	}
	csc := c.SecurityContext
	if csc == nil {
		t.Fatal("container securityContext is nil")
	}
	for name, got := range map[string]*bool{
		"runAsNonRoot":           csc.RunAsNonRoot,
		"readOnlyRootFilesystem": csc.ReadOnlyRootFilesystem,
	} {
		if got == nil || !*got {
			t.Errorf("container %s must be true", name)
		}
	}
	for name, got := range map[string]*bool{
		"allowPrivilegeEscalation": csc.AllowPrivilegeEscalation,
		"privileged":               csc.Privileged,
	} {
		if got == nil || *got {
			t.Errorf("container %s must be explicitly false", name)
		}
	}
	if csc.Capabilities == nil || len(csc.Capabilities.Drop) != 1 || csc.Capabilities.Drop[0] != "ALL" {
		t.Errorf("container capabilities = %+v, want drop: [ALL]", csc.Capabilities)
	}
	if len(csc.Capabilities.Add) != 0 {
		t.Errorf("container capabilities.add = %v, want none", csc.Capabilities.Add)
	}
	if csc.SeccompProfile == nil || csc.SeccompProfile.Type != "RuntimeDefault" {
		t.Error("container seccompProfile must be RuntimeDefault")
	}
}

// TestBuildPod_ReadOnlyRootIsSurvivable: readOnlyRootFilesystem without a
// writable mount at the working directory produces a Pod that starts and then
// fails on the first write, which is the least debuggable failure available.
func TestBuildPod_ReadOnlyRootIsSurvivable(t *testing.T) {
	p, err := buildPod(baseRequest())
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	c := p.Spec.Containers[0]
	if c.WorkingDir != PodWorkspace {
		t.Errorf("workingDir = %q, want %q", c.WorkingDir, PodWorkspace)
	}
	mounted := map[string]bool{}
	for _, m := range c.VolumeMounts {
		mounted[m.MountPath] = true
		if m.ReadOnly {
			t.Errorf("mount %s is read-only; the workspace and /tmp must be writable", m.MountPath)
		}
	}
	for _, want := range []string{PodWorkspace, "/tmp"} {
		if !mounted[want] {
			t.Errorf("no writable volume mounted at %s", want)
		}
	}
	if len(p.Spec.Volumes) != 2 {
		t.Fatalf("got %d volumes, want 2", len(p.Spec.Volumes))
	}
	for _, v := range p.Spec.Volumes {
		if v.EmptyDir == nil {
			t.Errorf("volume %q is not an emptyDir; a Pod must not mount host paths", v.Name)
		}
	}
}

// TestBuildPod_Labels checks that the two labels the GC sweep selects on are
// always present. An unlabelled Pod is invisible to reconciliation and leaks
// forever.
func TestBuildPod_Labels(t *testing.T) {
	cases := map[string]map[string]string{
		"explicit task_id": {"project": "/srv/app", "task_id": "42"},
		"task alias":       {"project": "/srv/app", "task": "7"},
		"no task at all":   {"project": "/srv/app"},
		"no labels at all": nil,
	}
	for name, labels := range cases {
		t.Run(name, func(t *testing.T) {
			req := baseRequest()
			req.Labels = labels
			p, err := buildPod(req)
			if err != nil {
				t.Fatalf("buildPod: %v", err)
			}
			for _, key := range []string{LabelManaged, LabelExecutorID, LabelTaskID, LabelHandleID} {
				if v := p.Metadata.Labels[key]; v == "" {
					t.Errorf("label %s is empty; the reconcile sweep selects on it", key)
				}
			}
			if got := p.Metadata.Labels[LabelExecutorID]; got != "k8s" {
				t.Errorf("executor-id label = %q, want k8s", got)
			}
		})
	}
}

// TestBuildPod_LabelValuesAreLegal: Kubernetes rejects a Pod whose label
// values are not [A-Za-z0-9_.-]{0,63} starting and ending alphanumeric, and a
// project path is neither.
func TestBuildPod_LabelValuesAreLegal(t *testing.T) {
	req := baseRequest()
	req.ExecutorID = "my executor/with:junk"
	req.Labels = map[string]string{
		"project": "/very/deep/path/with spaces/and-a-really-long-directory-name-that-exceeds-the-limit",
		"task_id": strings.Repeat("9", 200),
	}
	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	for k, v := range p.Metadata.Labels {
		if len(v) > maxLabelValue {
			t.Errorf("label %s = %q is %d chars, over the %d limit", k, v, len(v), maxLabelValue)
		}
		if v == "" {
			t.Errorf("label %s is empty", k)
		}
		if strings.ContainsAny(v, "/ :") {
			t.Errorf("label %s = %q contains characters Kubernetes rejects", k, v)
		}
		if first := v[0]; !isAlnum(rune(first)) {
			t.Errorf("label %s = %q must start alphanumeric", k, v)
		}
		if last := v[len(v)-1]; !isAlnum(rune(last)) {
			t.Errorf("label %s = %q must end alphanumeric", k, v)
		}
	}
	// The untruncated path survives as an annotation, which has no such limit.
	if p.Metadata.Annotations[AnnotationProjectPath] != req.Labels["project"] {
		t.Error("the full project path must survive as an annotation even when the label is truncated")
	}
}

func isAlnum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

func TestGenerateNameFor(t *testing.T) {
	cases := []struct {
		project, executor string
		wantPrefix        string
	}{
		{"/srv/app", "k8s", "cloop-app-k8s-"},
		{"", "k8s", "cloop-k8s-"},
		{"/srv/My App!", "prod-cluster", "cloop-my-app-prod-cluster-"},
	}
	for _, tc := range cases {
		got := generateNameFor(tc.project, tc.executor)
		if got != tc.wantPrefix {
			t.Errorf("generateNameFor(%q, %q) = %q, want %q", tc.project, tc.executor, got, tc.wantPrefix)
		}
		if !strings.HasSuffix(got, "-") {
			t.Errorf("generateName %q must end in '-' so the API server's suffix reads as a separate segment", got)
		}
	}

	// The API server appends five characters; the total must stay within the
	// 63-character name limit.
	long := generateNameFor("/srv/"+strings.Repeat("x", 200), strings.Repeat("y", 200))
	if len(long)+5 > 63 {
		t.Errorf("generateName %q (%d chars) leaves no room for the API server's suffix", long, len(long))
	}
}

// TestBuildPod_ResourceRequirements checks that quantities land where the API
// expects and that unset ones are omitted rather than sent as "".
func TestBuildPod_ResourceRequirements(t *testing.T) {
	req := baseRequest()
	req.CPURequest = "250m"
	req.CPULimit = "2"
	req.MemoryRequest = "512Mi"
	req.MemoryLimit = "4Gi"
	req.EphemeralStorageLimit = "10Gi"

	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	res := p.Spec.Containers[0].Resources
	if res.Requests["cpu"] != "250m" || res.Requests["memory"] != "512Mi" {
		t.Errorf("requests = %v", res.Requests)
	}
	if res.Limits["cpu"] != "2" || res.Limits["memory"] != "4Gi" || res.Limits["ephemeral-storage"] != "10Gi" {
		t.Errorf("limits = %v", res.Limits)
	}

	// Unset limits must not appear in the JSON at all: an empty-string
	// quantity is a validation error, not "no limit".
	bare, err := buildPod(baseRequest())
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	data, err := json.Marshal(bare)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), `"resources":{"requests"`) || strings.Contains(string(data), `""`) {
		t.Errorf("bare pod JSON carries empty quantities: %s", data)
	}
}

func TestBuildPod_SchedulingAndPullSecrets(t *testing.T) {
	req := baseRequest()
	req.NodeSelector = map[string]string{"cloop.dev/pool": "untrusted"}
	req.Tolerations = []Toleration{{Key: "cloop.dev/untrusted", Operator: "Exists", Effect: "NoSchedule"}}
	req.ImagePullSecrets = []string{"ghcr-auth", "  ", "quay-auth"}
	req.ServiceAccountName = "cloop-runner"
	req.ActiveDeadlineSeconds = 3600
	req.TerminationGracePeriodSeconds = 45

	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	if p.Spec.NodeSelector["cloop.dev/pool"] != "untrusted" {
		t.Errorf("nodeSelector = %v", p.Spec.NodeSelector)
	}
	if len(p.Spec.Tolerations) != 1 || p.Spec.Tolerations[0].Effect != "NoSchedule" {
		t.Errorf("tolerations = %+v", p.Spec.Tolerations)
	}
	// The blank entry must be dropped: an empty Secret name fails the Pod
	// create with a validation error that names the index, not the value.
	if len(p.Spec.ImagePullSecrets) != 2 {
		t.Errorf("imagePullSecrets = %+v, want the blank entry dropped", p.Spec.ImagePullSecrets)
	}
	if p.Spec.ServiceAccountName != "cloop-runner" {
		t.Errorf("serviceAccountName = %q", p.Spec.ServiceAccountName)
	}
	// Naming a ServiceAccount must not re-enable its token mount.
	if p.Spec.AutomountServiceAccountToken == nil || *p.Spec.AutomountServiceAccountToken {
		t.Error("naming a ServiceAccount must not mount its token")
	}
	if p.Spec.ActiveDeadlineSeconds == nil || *p.Spec.ActiveDeadlineSeconds != 3600 {
		t.Errorf("activeDeadlineSeconds = %v, want 3600", p.Spec.ActiveDeadlineSeconds)
	}
	if p.Spec.TerminationGracePeriodSeconds == nil || *p.Spec.TerminationGracePeriodSeconds != 45 {
		t.Errorf("terminationGracePeriodSeconds = %v, want 45", p.Spec.TerminationGracePeriodSeconds)
	}
}

// TestBuildPod_ZeroDeadlineIsOmitted: cloop removed the implicit task timeout
// (Task 20148), so zero must mean "unbounded", not "deadline of 0 seconds"
// (which the API server reads as an immediate failure).
func TestBuildPod_ZeroDeadlineIsOmitted(t *testing.T) {
	p, err := buildPod(baseRequest())
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	if p.Spec.ActiveDeadlineSeconds != nil {
		t.Errorf("activeDeadlineSeconds = %v, want omitted", *p.Spec.ActiveDeadlineSeconds)
	}
}

func TestBuildPod_ArgvSplit(t *testing.T) {
	req := baseRequest()
	req.Argv = []string{"/usr/local/bin/cloop", "run", "--auto-evolve"}
	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	c := p.Spec.Containers[0]
	// command/args rather than a shell string: no quoting, no injection.
	if len(c.Command) != 1 || c.Command[0] != "/usr/local/bin/cloop" {
		t.Errorf("command = %v, want the program only", c.Command)
	}
	if len(c.Args) != 2 || c.Args[0] != "run" || c.Args[1] != "--auto-evolve" {
		t.Errorf("args = %v", c.Args)
	}
}

func TestBuildPod_Rejects(t *testing.T) {
	cases := map[string]struct {
		mutate func(*podRequest)
		want   string
	}{
		"empty argv":       {func(r *podRequest) { r.Argv = nil }, "argv is empty"},
		"empty image":      {func(r *podRequest) { r.Image = "" }, "requires an image"},
		"empty namespace":  {func(r *podRequest) { r.Namespace = "" }, "requires a namespace"},
		"root uid":         {func(r *podRequest) { r.RunAsUser = 0; r.RunAsGroup = 0 }, ""},
		"relative workdir": {func(r *podRequest) { r.WorkDir = "relative/path" }, "must be an absolute path"},
		"workdir outside workspace": {
			func(r *podRequest) { r.WorkDir = "/etc" },
			"outside the writable workspace",
		},
		"env without =": {func(r *podRequest) { r.Env = []string{"BROKEN"} }, "not in K=V form"},
		"bad env name":  {func(r *podRequest) { r.Env = []string{"a-b=1"} }, "not a valid Kubernetes env var name"},
		"duplicate env": {func(r *podRequest) { r.Env = []string{"A=1", "A=2"} }, "set more than once"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := baseRequest()
			tc.mutate(&req)
			_, err := buildPod(req)
			if name == "root uid" {
				// RunAsUser 0 means "unset" and falls back to the default
				// non-root UID, so this must succeed with 65532.
				if err != nil {
					t.Fatalf("buildPod: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("buildPod(%s) = nil error, want one", name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			if !errors.Is(err, executor.ErrInvalidSpec) {
				t.Errorf("error %v does not wrap ErrInvalidSpec", err)
			}
		})
	}
}

// TestBuildPod_EnvIsDeterministic keeps two identical Specs producing
// identical Pods, which is what makes the object diffable in review and this
// package testable by comparison.
func TestBuildPod_EnvIsDeterministic(t *testing.T) {
	req := baseRequest()
	req.Env = []string{"ZED=1", "ALPHA=2", "MIKE=3"}
	first, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	second, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	a, _ := json.Marshal(first.Spec.Containers[0].Env)
	b, _ := json.Marshal(second.Spec.Containers[0].Env)
	if string(a) != string(b) {
		t.Errorf("env ordering is not deterministic: %s vs %s", a, b)
	}
	if first.Spec.Containers[0].Env[0].Name != "ALPHA" {
		t.Errorf("env is not sorted: %s", a)
	}
}

// TestBuildPod_NilEnvForwardsNothing is the divergence from os/exec that
// matters: a nil Env must not inherit the control plane's environment, which
// would put every credential the server holds into an object readable by
// anyone with `get pods`.
func TestBuildPod_NilEnvForwardsNothing(t *testing.T) {
	req := baseRequest()
	req.Env = nil
	p, err := buildPod(req)
	if err != nil {
		t.Fatalf("buildPod: %v", err)
	}
	if len(p.Spec.Containers[0].Env) != 0 {
		t.Errorf("nil Spec.Env produced %d env vars; it must produce none", len(p.Spec.Containers[0].Env))
	}
}

func TestTolerationDefaultsAndValidation(t *testing.T) {
	// An empty operator with an empty value defaults to Equal in Kubernetes,
	// which matches only the empty value — a toleration that looks right and
	// tolerates nothing.
	got := Toleration{Key: "cloop.dev/untrusted", Effect: "NoSchedule"}.toAPI()
	if got.Operator != "Exists" {
		t.Errorf("valueless toleration operator = %q, want Exists", got.Operator)
	}
	got = Toleration{Key: "pool", Value: "untrusted", Effect: "NoSchedule"}.toAPI()
	if got.Operator != "Equal" {
		t.Errorf("valued toleration operator = %q, want Equal", got.Operator)
	}
	if got = (Toleration{Key: "k", Operator: "Exists", Seconds: 30}).toAPI(); got.TolerationSeconds == nil ||
		*got.TolerationSeconds != 30 {
		t.Errorf("tolerationSeconds = %v, want 30", got.TolerationSeconds)
	}

	valid := []Toleration{
		{Key: "k", Operator: "Exists", Effect: "NoSchedule"},
		{Key: "k", Operator: "Equal", Value: "v", Effect: "NoExecute", Seconds: 60},
		{Operator: "Exists"},
		{},
	}
	for i, tol := range valid {
		if err := tol.Validate(); err != nil {
			t.Errorf("valid[%d] %+v: %v", i, tol, err)
		}
	}
	invalid := map[string]Toleration{
		"bad operator":  {Operator: "Matches"},
		"bad effect":    {Key: "k", Operator: "Exists", Effect: "Maybe"},
		"exists+value":  {Key: "k", Operator: "Exists", Value: "v"},
		"empty key eq":  {Operator: "Equal", Value: "v"},
		"negative secs": {Key: "k", Operator: "Exists", Seconds: -1},
	}
	for name, tol := range invalid {
		if err := tol.Validate(); err == nil {
			t.Errorf("%s: Validate() = nil, want an error", name)
		}
	}
}

func TestClassifyPod(t *testing.T) {
	terminated := func(code int, reason string, signal int) *pod {
		return &pod{Status: podStatus{
			Phase: phaseFailed,
			ContainerStatuses: []containerStatus{{
				Name:  ContainerName,
				State: containerState{Terminated: &stateTerminated{ExitCode: code, Reason: reason, Signal: signal}},
			}},
		}}
	}

	cases := []struct {
		name      string
		in        *pod
		wantState executor.State
		wantCode  int
		wantMsg   string
	}{
		{
			name: "clean exit",
			in: &pod{Status: podStatus{Phase: phaseSucceeded, ContainerStatuses: []containerStatus{{
				Name:  ContainerName,
				State: containerState{Terminated: &stateTerminated{ExitCode: 0}},
			}}}},
			wantState: executor.StateExited, wantCode: 0,
		},
		{
			name:      "oom is a kill, not an exit 137",
			in:        terminated(137, "OOMKilled", 0),
			wantState: executor.StateKilled, wantCode: 137, wantMsg: "memory limit",
		},
		{
			name:      "deadline exceeded",
			in:        &pod{Status: podStatus{Phase: phaseFailed, Reason: "DeadlineExceeded"}},
			wantState: executor.StateKilled, wantCode: -1, wantMsg: "activeDeadlineSeconds",
		},
		{
			name:      "evicted",
			in:        &pod{Status: podStatus{Phase: phaseFailed, Reason: "Evicted", Message: "node had disk pressure"}},
			wantState: executor.StateKilled, wantCode: -1, wantMsg: "evicted",
		},
		{
			name:      "command not found",
			in:        terminated(127, "Error", 0),
			wantState: executor.StateFailed, wantCode: 127, wantMsg: "not found in the image",
		},
		{
			name:      "not executable",
			in:        terminated(126, "Error", 0),
			wantState: executor.StateFailed, wantCode: 126, wantMsg: "executable",
		},
		{
			name:      "sigterm",
			in:        terminated(143, "Error", 0),
			wantState: executor.StateKilled, wantCode: 143, wantMsg: "SIGTERM",
		},
		{
			name:      "ordinary failure keeps its exit code",
			in:        terminated(3, "Error", 0),
			wantState: executor.StateExited, wantCode: 3,
		},
		{
			name: "image pull failure never ran the container",
			in: &pod{Status: podStatus{Phase: phaseFailed, ContainerStatuses: []containerStatus{{
				Name: ContainerName,
				State: containerState{Waiting: &stateWaiting{
					Reason: "ImagePullBackOff", Message: "manifest unknown",
				}},
			}}}},
			wantState: executor.StateFailed, wantCode: -1, wantMsg: "never started",
		},
		{
			name:      "failed with no container status at all",
			in:        &pod{Status: podStatus{Phase: phaseFailed, Message: "no nodes available"}},
			wantState: executor.StateFailed, wantCode: -1, wantMsg: "no nodes available",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, code, msg := classifyPod(tc.in)
			if state != tc.wantState {
				t.Errorf("state = %q, want %q", state, tc.wantState)
			}
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d", code, tc.wantCode)
			}
			if tc.wantMsg != "" && !strings.Contains(msg, tc.wantMsg) {
				t.Errorf("message %q does not mention %q", msg, tc.wantMsg)
			}
		})
	}
}

func TestExecutorLabelSelector(t *testing.T) {
	sel := executorLabelSelector("k8s")
	for _, want := range []string{
		LabelManaged + "=true",
		LabelExecutorID + "=k8s",
		LabelTaskID,
	} {
		if !strings.Contains(sel, want) {
			t.Errorf("selector %q is missing %q", sel, want)
		}
	}
	// The task-id term must be an existence check, not an equality one: the
	// sweep has to match every task, not one.
	if strings.Contains(sel, LabelTaskID+"=") {
		t.Errorf("selector %q pins task-id to a value; it must only require the label to exist", sel)
	}
}

func TestQuantityHelpers(t *testing.T) {
	if got := quantityFromMillis(1500); got != "1500m" {
		t.Errorf("quantityFromMillis(1500) = %q", got)
	}
	if got := quantityFromMillis(0); got != "" {
		t.Errorf("quantityFromMillis(0) = %q, want empty so it is omitted", got)
	}
	if got := quantityFromMB(512); got != "512Mi" {
		t.Errorf("quantityFromMB(512) = %q", got)
	}
	if got := quantityFromMB(-1); got != "" {
		t.Errorf("quantityFromMB(-1) = %q, want empty", got)
	}
}
