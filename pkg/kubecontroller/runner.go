package kubecontroller

// runner.go builds what one runner is in the cluster: a Pod running
// `cloop executor agent --ephemeral`, and the Secret, owned by that Pod, that
// holds its just-in-time configuration.
//
// buildRunnerPod is the security boundary of this package, the way buildPod is
// the Kubernetes driver's: everything that confines a runner is decided here,
// in a pure function, and asserted on in runner_test.go. A runner Pod meets
// the restricted Pod Security Standard and then some, whatever its template
// says:
//
//   - runAsNonRoot with an explicit UID and GID, at Pod and container scope;
//   - allowPrivilegeEscalation: false, privileged: false, capabilities.drop:
//     ALL, seccompProfile: RuntimeDefault;
//   - readOnlyRootFilesystem, with emptyDir volumes for the runner's state and
//     /tmp;
//   - automountServiceAccountToken: false even with a serviceAccountName — a
//     runner runs model-authored code, and an API credential is nothing it
//     was given; workload identity webhooks project their own tokens;
//   - no host namespaces, no host paths, enableServiceLinks: false;
//   - restartPolicy: Never: a runner takes one run, and a restarted one would
//     try to redeem a spent token.
//
// No credential is a value in the Pod. The runner token, the hub's address and
// its pin travel in the per-runner Secret, mounted read-only and owned by the
// Pod, so the API server's garbage collector deletes it with the Pod even when
// the controller is gone; the template's extra variables are secretKeyRefs.

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// Labels and annotations the controller puts on what it creates.
const (
	LabelName      = "app.kubernetes.io/name"
	LabelManagedBy = "app.kubernetes.io/managed-by"
	// ManagedBy is the managed-by value the controller's watches select.
	ManagedBy = "cloop-executor-controller"
	// RunnerName is the name label of a runner Pod; RunnerConfigName of its
	// Secret.
	RunnerName       = "cloop-runner"
	RunnerConfigName = "cloop-runner-config"
	// LabelPool names the ExecutorPool, for people; the controller finds a
	// runner's pool by its controlling ownerReference.
	LabelPool = "cloop.dev/executor-pool"
	// LabelRunnerPod names a Secret's Pod.
	LabelRunnerPod = "cloop.dev/runner-pod"

	// AnnotationEnrollmentID is the runner token's public ID, which the hub's
	// feed names the runner by. An annotation, because an ID may begin with a
	// character a label value may not.
	AnnotationEnrollmentID = "cloop.dev/enrollment-id"
	// AnnotationRunnerName is the hub's name for the runner.
	AnnotationRunnerName = "cloop.dev/runner-name"
	// AnnotationExpiresAt is when the runner token lapses unredeemed.
	AnnotationExpiresAt = "cloop.dev/token-expires-at"
)

// Where things are in a runner Pod.
const (
	runnerContainer       = "runner"
	configVolume          = "runner-config"
	stateVolume           = "state"
	tmpVolume             = "tmp"
	configDir             = "/var/run/cloop/runner"
	stateDir              = "/var/lib/cloop-runner"
	bundleKey             = "bundle"
	caKey                 = "ca.crt"
	runnerUID       int64 = 65532
	runnerGID       int64 = 65532
	// runnerGracePeriod is how long a stopped runner has to say goodbye to
	// the hub and wipe what it held.
	runnerGracePeriod int64 = 30
)

// runnerArgs is the runner's command line, after the program.
func runnerArgs(withCA bool) []string {
	args := []string{"executor", "agent", "--ephemeral",
		"--token-file", configDir + "/" + bundleKey,
		"--workdir-root", stateDir + "/work",
	}
	if withCA {
		args = append(args, "--ca-file", configDir+"/"+caKey)
	}
	return args
}

// runnerStorage is a runner Pod's volume (Task 20484): the claim it mounts,
// the tenant it was minted as holding, and whether its init container wipes
// the volume before the runner starts.
type runnerStorage struct {
	claim string
	holds string
	wipe  bool
	p     *Persistence
}

// storageArgs are the runner's flags for its volume: trees, caches and the
// git object cache on it; homes and leased files on the memory-backed
// emptyDir, never on it.
func storageArgs(st *runnerStorage) []string {
	args := []string{"--home-root", privateDir + "/homes", "--secret-dir", privateDir + "/secrets"}
	if st.p.hasMount(MountWorkspace) {
		args = append(args, "--workspace-root", storageDir+"/"+mountDirs[MountWorkspace])
	}
	if st.p.hasMount(MountGitCache) {
		args = append(args, "--git-cache-dir", storageDir+"/"+mountDirs[MountGitCache])
	}
	if st.p.hasMount(MountToolCache) {
		args = append(args, "--cache-dir", storageDir+"/"+mountDirs[MountToolCache])
	}
	if st.holds != "" {
		// The runner holds the hub to what its volume holds, too: a start
		// for another project's run is refused on the runner.
		args = append(args, "--holds", st.holds)
	}
	return args
}

// prepareArgs are the init container's command line, after the program.
func prepareArgs(st *runnerStorage) []string {
	args := []string{"executor", "runner-storage", "--root", storageDir,
		"--dirs", strings.Join(st.p.mountList(), ","),
		"--min-free", strconv.FormatInt(st.p.minFreeBytes(), 10),
		"--report", "/dev/termination-log"}
	if st.wipe {
		args = append(args, "--wipe")
	}
	return args
}

// runnerPodName is a fresh name for one of pool's runners.
func runnerPodName(pool *ExecutorPool) (string, error) {
	prefix := strings.TrimRight(truncate(pool.Metadata.Name, 50), "-.")
	suffix, err := randomSuffix(6)
	if err != nil {
		return "", err
	}
	return prefix + "-" + suffix, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// randomSuffix is n characters of [a-z0-9].
func randomSuffix(n int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	var b strings.Builder
	for i := 0; i < n; i++ {
		x, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", fmt.Errorf("kubecontroller: random name: %w", err)
		}
		b.WriteByte(alphabet[x.Int64()])
	}
	return b.String(), nil
}

// runnerLabels are the labels of a runner's Pod (or, with secret, Secret).
func runnerLabels(pool *ExecutorPool, secret bool, podName string) map[string]string {
	out := make(map[string]string, len(pool.Spec.RunnerLabels)+4)
	for k, v := range pool.Spec.RunnerLabels {
		out[k] = v
	}
	out[LabelManagedBy] = ManagedBy
	out[LabelName] = RunnerName
	if secret {
		out[LabelName] = RunnerConfigName
		out[LabelRunnerPod] = podName
	}
	if n := pool.Metadata.Name; len(n) <= 63 && labelValue.MatchString(n) {
		out[LabelPool] = n
	}
	return out
}

// buildRunnerPod is one runner's Pod, before the API server has seen it; st
// is its volume, nil for none.
func buildRunnerPod(pool *ExecutorPool, name, image string, st *runnerStorage) *Pod {
	t := pool.Spec.Template
	withCA := strings.TrimSpace(pool.Spec.HubCABundle) != ""
	ctrl := true
	home := stateDir + "/home"
	if st != nil {
		// With a volume, the runner's own HOME — what a workload inheriting
		// its environment uses — is memory too.
		home = privateDir
	}
	env := []EnvVar{{Name: "HOME", Value: home}}
	if st != nil {
		for _, kv := range executor.ScratchCacheEnv(scratchCacheDir) {
			k, v, _ := strings.Cut(kv, "=")
			env = append(env, EnvVar{Name: k, Value: v})
		}
	}
	if st != nil && st.p.hasMount(MountToolCache) {
		for _, kv := range executor.CacheEnv(storageDir + "/" + mountDirs[MountToolCache]) {
			k, v, _ := strings.Cut(kv, "=")
			env = append(env, EnvVar{Name: k, Value: v})
		}
	}
	extra := append([]SecretEnvVar(nil), t.Env...)
	sort.SliceStable(extra, func(i, j int) bool { return extra[i].Name < extra[j].Name })
	for _, e := range extra {
		env = append(env, EnvVar{Name: e.Name, ValueFrom: &EnvVarSource{SecretKeyRef: &SecretKeySelector{
			Name: e.SecretKeyRef.Name, Key: e.SecretKeyRef.Key}}})
	}
	var resources *ContainerResources
	if len(t.Resources.Requests) > 0 || len(t.Resources.Limits) > 0 {
		resources = &ContainerResources{Requests: quantities(t.Resources.Requests), Limits: quantities(t.Resources.Limits)}
	}
	var runtimeClass *string
	if rc := strings.TrimSpace(t.RuntimeClassName); rc != "" {
		runtimeClass = ptr(rc)
	}
	var affinity []byte
	if len(t.Affinity) > 0 && string(t.Affinity) != "null" {
		affinity = append([]byte(nil), t.Affinity...)
	}
	args := runnerArgs(withCA)
	mounts := []VolumeMount{
		{Name: configVolume, MountPath: configDir, ReadOnly: true},
		{Name: stateVolume, MountPath: stateDir},
		{Name: tmpVolume, MountPath: "/tmp"},
	}
	volumes := []Volume{
		{Name: configVolume, Secret: &SecretVolume{SecretName: name, DefaultMode: ptr(int32(0o400)),
			Optional: ptr(false)}},
		{Name: stateVolume, EmptyDir: &EmptyDirSource{}},
		{Name: tmpVolume, EmptyDir: &EmptyDirSource{}},
	}
	var annotations map[string]string
	var inits []Container
	if st != nil {
		args = append(args, storageArgs(st)...)
		mounts = append(mounts,
			VolumeMount{Name: storageVolume, MountPath: storageDir},
			VolumeMount{Name: privateVolume, MountPath: privateDir})
		volumes = append(volumes,
			Volume{Name: storageVolume, PersistentVolumeClaim: &ClaimVolume{ClaimName: st.claim}},
			Volume{Name: privateVolume, EmptyDir: &EmptyDirSource{Medium: "Memory", SizeLimit: privateSizeLimit}})
		annotations = map[string]string{AnnotationPodClaim: st.claim, AnnotationPodHolds: st.holds,
			AnnotationPodWipe: strconv.FormatBool(st.wipe)}
		inits = []Container{{
			Name:            storageInitContainer,
			Image:           image,
			ImagePullPolicy: t.ImagePullPolicy,
			Command:         []string{"cloop"},
			Args:            prepareArgs(st),
			Env:             []EnvVar{{Name: "HOME", Value: "/tmp"}},
			Resources:       resources,
			VolumeMounts:    []VolumeMount{{Name: storageVolume, MountPath: storageDir}},
			SecurityContext: restrictedContainer(),
			// The step's own report is the message; an image too old to have
			// the step fails before it can write one, and its last log lines
			// say why instead.
			TerminationMessagePath:   "/dev/termination-log",
			TerminationMessagePolicy: "FallbackToLogsOnError",
		}}
	}
	podSecurity := &PodSecurityContext{
		RunAsNonRoot:   ptr(true),
		RunAsUser:      ptr(runnerUID),
		RunAsGroup:     ptr(runnerGID),
		FSGroup:        ptr(runnerGID),
		SeccompProfile: &SeccompProfile{Type: "RuntimeDefault"},
	}
	if st != nil {
		// A kept volume holds a workspace's worth of files: the kubelet changes
		// their group only when the volume's root shows they are not the
		// runner's already, not on every Pod that mounts it.
		podSecurity.FSGroupChangePolicy = ptr("OnRootMismatch")
	}
	return &Pod{
		APIVersion: "v1",
		Kind:       "Pod",
		Metadata: ObjectMeta{
			Name:        name,
			Namespace:   pool.Metadata.Namespace,
			Labels:      runnerLabels(pool, false, name),
			Annotations: annotations,
			OwnerReferences: []OwnerReference{{APIVersion: APIVersion, Kind: Kind, Name: pool.Metadata.Name,
				UID: pool.Metadata.UID, Controller: &ctrl}},
		},
		Spec: PodSpec{
			RestartPolicy:                 "Never",
			ServiceAccountName:            strings.TrimSpace(t.ServiceAccountName),
			AutomountServiceAccountToken:  ptr(false),
			EnableServiceLinks:            ptr(false),
			RuntimeClassName:              runtimeClass,
			NodeSelector:                  copyMap(t.NodeSelector),
			Tolerations:                   append([]Toleration(nil), t.Tolerations...),
			Affinity:                      affinity,
			ImagePullSecrets:              append([]LocalObjectReference(nil), t.ImagePullSecrets...),
			TerminationGracePeriodSeconds: ptr(runnerGracePeriod),
			SecurityContext:               podSecurity,
			InitContainers:                inits,
			Containers: []Container{{
				Name:                     runnerContainer,
				Image:                    image,
				ImagePullPolicy:          t.ImagePullPolicy,
				Command:                  []string{"cloop"},
				Args:                     args,
				Env:                      env,
				Resources:                resources,
				VolumeMounts:             mounts,
				SecurityContext:          restrictedContainer(),
				TerminationMessagePath:   "/dev/termination-log",
				TerminationMessagePolicy: "File",
			}},
			Volumes: volumes,
		},
	}
}

// restrictedContainer is the security context of every container in a
// runner Pod.
func restrictedContainer() *SecurityContext {
	return &SecurityContext{
		RunAsNonRoot:             ptr(true),
		RunAsUser:                ptr(runnerUID),
		RunAsGroup:               ptr(runnerGID),
		Privileged:               ptr(false),
		AllowPrivilegeEscalation: ptr(false),
		ReadOnlyRootFilesystem:   ptr(true),
		Capabilities:             &Capabilities{Drop: []string{"ALL"}},
		SeccompProfile:           &SeccompProfile{Type: "RuntimeDefault"},
	}
}

// buildRunnerSecret is the Secret that carries cfg to the runner Pod pod —
// owned by it, so it goes when the Pod goes.
func buildRunnerSecret(pool *ExecutorPool, pod *Pod, cfg RunnerConfig, pin string) (*Secret, error) {
	b, err := remote.DecodeBundle(cfg.Bundle)
	if err != nil {
		return nil, fmt.Errorf("kubecontroller: the hub's runner configuration %s: %w", cfg.EnrollmentID, err)
	}
	if strings.TrimSpace(b.Pin) == "" {
		// The hub has no certificate of its own to pin — TLS ends in front of
		// it — so the runner pins what the controller pins.
		b.Pin = strings.TrimSpace(pin)
	}
	bundle, err := b.Encode()
	if err != nil {
		return nil, err
	}
	data := map[string][]byte{bundleKey: []byte(bundle + "\n")}
	if ca := strings.TrimSpace(pool.Spec.HubCABundle); ca != "" {
		data[caKey] = []byte(ca + "\n")
	}
	ctrl := true
	return &Secret{
		APIVersion: "v1",
		Kind:       "Secret",
		Metadata: ObjectMeta{
			Name:      pod.Metadata.Name,
			Namespace: pod.Metadata.Namespace,
			Labels:    runnerLabels(pool, true, pod.Metadata.Name),
			Annotations: map[string]string{
				AnnotationEnrollmentID: cfg.EnrollmentID,
				AnnotationRunnerName:   cfg.Name,
				AnnotationExpiresAt:    cfg.ExpiresAt.UTC().Format(time.RFC3339),
			},
			OwnerReferences: []OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: pod.Metadata.Name,
				UID: pod.Metadata.UID, Controller: &ctrl}},
		},
		Type:      "Opaque",
		Data:      data,
		Immutable: ptr(true),
	}, nil
}

func quantities(m map[string]Quantity) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = string(v)
	}
	return out
}

func copyMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
