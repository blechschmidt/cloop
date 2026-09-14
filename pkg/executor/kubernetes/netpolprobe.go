package kubernetes

// netpolprobe.go runs the experiment that settles whether this cluster enforces
// a NetworkPolicy, instead of asking someone to vouch for it.
//
// # The experiment
//
// Three Pods and one policy, in this order:
//
//  1. A target Pod serving one byte over HTTP on the pod network.
//  2. A control client Pod that fetches it with no policy in place. It must
//     SUCCEED.
//  3. A policed client Pod, carrying a label that a default-deny egress policy
//     selects, that fetches the same address. It must FAIL.
//
// Step 2 is the step that makes this a proof rather than a coincidence, and it
// is the one an obvious implementation leaves out. Without it, "the client
// could not connect" is indistinguishable from "the target never came up", "the
// image has no wget", "the node is wedged" or "the namespace already denies
// everything" — and every one of those failures would be recorded as
// *enforcement*, which is precisely the false confidence this whole mechanism
// exists to prevent. A probe that cannot fail is not evidence. So a control
// that does not succeed yields ErrProbeInconclusive, never a verdict.
//
// # Why exit codes and not exec
//
// The connection attempt is the Pod's command, and its result is the container's
// exit status read from the Pod's own status. Nothing is streamed, nothing is
// attached, and the driver needs no exec RBAC it would not otherwise hold: the
// probe uses exactly the verbs (pods, networkpolicies) the egress filter already
// requires. It also means the experiment is observable after the fact — a
// suspicious operator can re-run the same three Pods with kubectl.
//
// # Cleanup
//
// Every object is registered with the janitor the moment its creation is
// attempted, and the janitor runs from a deferred call on a context that is
// detached from the caller's. A probe interrupted by Ctrl-C, a timeout or a
// panic still removes its Pods and its deny-all policy — an orphaned default-
// deny policy in a shared namespace is an outage for whoever is scheduled there
// next, and it would be one cloop caused and did not clean up.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/netfilter"
)

// ErrProbeInconclusive is returned when the experiment could not establish its
// control — i.e. the probe proved nothing, in either direction.
//
// Distinct from a refutation on purpose, and callers must keep it distinct:
// "the probe failed" and "the cluster does not enforce policies" are different
// facts, and collapsing them would either strip a working cluster of a
// capability or hand an unenforcing one a verdict it did not earn.
var ErrProbeInconclusive = errors.New("kubernetes: network policy probe inconclusive")

const (
	// probeNamePrefix marks every object the probe creates, so an operator
	// reading `kubectl get pod,netpol` can tell a probe's leftovers from a
	// run's — and can delete them by prefix if a probe was killed with SIGKILL,
	// the one exit path no deferred cleanup covers.
	probeNamePrefix = "cloop-netpol-probe-"

	// probeImage is the default image for all three Pods.
	//
	// busybox because the experiment needs an HTTP server and an HTTP client
	// and nothing else, and busybox has both (httpd, wget) in ~4 MB. It is
	// overridable because an air-gapped cluster mirrors its own images and
	// because an operator may have an image policy that this must satisfy — see
	// ProbeOptions.Image.
	probeImage = "busybox:1.36"

	// probePort is the target's listening port. Above 1024 so the server runs
	// unprivileged, and not a port anything else in a cloop namespace uses.
	probePort = 18080

	// probeConnectTimeoutSeconds bounds the client's fetch.
	//
	// The blocked case is a *timeout*, not a refusal: a NetworkPolicy drops
	// packets rather than rejecting them, so the policed client learns nothing
	// until its own clock runs out. Short enough to keep the probe brisk, long
	// enough that a slow-but-working pod network is not misread as enforcement.
	probeConnectTimeoutSeconds = 6

	// probeDefaultTimeout bounds the whole experiment.
	probeDefaultTimeout = 3 * time.Minute

	// labelProbe marks probe objects; labelProbeRole distinguishes the policed
	// client from the control, and is what the deny-all policy selects on.
	labelProbe     = "cloop.dev/netpol-probe"
	labelProbeRole = "cloop.dev/netpol-probe-role"
)

// probePollInterval is how often a Pod's phase is re-read. The probe polls
// rather than watches because it is a short-lived CLI operation against at most
// three objects, and a poll has no stream to leak.
//
// A var so the tests can drive the experiment at memory speed instead of
// spending a real second and a half per case waiting on a fake API server.
var probePollInterval = 500 * time.Millisecond

// ProbeOptions tunes the experiment. The zero value is the intended one.
type ProbeOptions struct {
	// Image overrides the busybox image all three Pods run. It must provide
	// `sh`, `httpd` and `wget`.
	Image string

	// Timeout bounds the whole probe. Zero means probeDefaultTimeout.
	Timeout time.Duration

	// Logf, when set, narrates each step. `cloop hub doctor` wires it to the
	// terminal so an operator watching a 40-second probe can see which of the
	// three Pods it is waiting on.
	Logf func(format string, args ...any)
}

func (o ProbeOptions) image() string {
	if img := strings.TrimSpace(o.Image); img != "" {
		return img
	}
	return probeImage
}

func (o ProbeOptions) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return probeDefaultTimeout
}

func (o ProbeOptions) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

// ProbeNetworkPolicyEnforcement runs the experiment and returns what it saw.
//
// A returned verdict is always a measurement: Enforced true means a connection
// that worked stopped working when a policy was applied, and false means it did
// not stop. Anything the probe could not establish is an error wrapping
// ErrProbeInconclusive, never a verdict — see the file comment.
func (e *Executor) ProbeNetworkPolicyEnforcement(ctx context.Context, opts ProbeOptions) (ProbeVerdict, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()

	creds, cli, err := e.connect(ctx, "")
	if err != nil {
		return ProbeVerdict{}, fmt.Errorf("%w: %v", ErrProbeInconclusive, err)
	}
	defer func() {
		cli.close()
		e.opts.Credentials.Release(creds.LeaseID)
	}()

	// The same resolution Start and the orphan sweep use, so the probe lands in
	// the namespace the workloads land in. Probing somewhere else would measure
	// a NetworkPolicy nobody is governed by — and enforcement can genuinely
	// differ per namespace, which is the whole reason a verdict records one.
	namespace := e.namespaceFor(creds)
	run := probeNamePrefix + strings.ToLower(newHandleID())
	// The longest of the three names, so a run id that would produce a name the
	// API server rejects is caught before any object is created rather than
	// two Pods in. "-policed" and "-control" tie at eight characters; "-target"
	// is shorter and would pass a check the others fail.
	if err := validateDNSSubdomain(run+"-policed", "probe pod name"); err != nil {
		return ProbeVerdict{}, fmt.Errorf("%w: %v", ErrProbeInconclusive, err)
	}

	// The janitor is armed before anything is created and runs on every exit
	// path, including a panic. Registration happens *before* each create call,
	// not after: a create that times out may still have landed, and an object
	// this probe cannot prove it failed to create is one it must still try to
	// remove.
	jan := &probeJanitor{cli: cli, namespace: namespace, logf: opts.logf}
	defer jan.clean()

	image := opts.image()
	opts.logf("probing NetworkPolicy enforcement in namespace %s with %s", namespace, image)

	// --- 1. the target ----------------------------------------------------
	targetName := run + "-target"
	jan.addPod(targetName)
	if _, err := cli.createPod(ctx, namespace, buildProbeTargetPod(targetName, namespace, e.id, image, e.opts)); err != nil {
		return ProbeVerdict{}, probeSetupError("create the probe's target Pod", namespace, err)
	}
	targetIP, err := waitForPodIP(ctx, cli, namespace, targetName)
	if err != nil {
		return ProbeVerdict{}, fmt.Errorf("%w: the probe's target Pod never became reachable: %v",
			ErrProbeInconclusive, err)
	}
	opts.logf("target Pod %s is running at %s", targetName, targetIP)

	// --- 2. the control ---------------------------------------------------
	//
	// Unpoliced. If this does not connect, the experiment has no baseline and
	// the run is abandoned: see the file comment for why this is the step that
	// makes the rest evidence.
	controlName := run + "-control"
	jan.addPod(controlName)
	if _, err := cli.createPod(ctx, namespace, buildProbeClientPod(controlName, namespace, e.id, image, targetIP, false, e.opts)); err != nil {
		return ProbeVerdict{}, probeSetupError("create the probe's control Pod", namespace, err)
	}
	controlCode, err := waitForPodExit(ctx, cli, namespace, controlName)
	if err != nil {
		return ProbeVerdict{}, fmt.Errorf("%w: the probe's control Pod did not finish: %v",
			ErrProbeInconclusive, err)
	}
	if controlCode != 0 {
		return ProbeVerdict{}, fmt.Errorf("%w: the control connection failed (exit %d) before any policy "+
			"was applied, so this probe cannot tell an enforced policy from a broken one. Something "+
			"other than cloop is already blocking pod-to-pod traffic in namespace %q — an existing "+
			"default-deny NetworkPolicy, a service mesh, or a node problem. Resolve that, or probe in "+
			"a namespace where Pods can reach each other",
			ErrProbeInconclusive, controlCode, namespace)
	}
	opts.logf("control Pod %s reached the target with no policy in place", controlName)

	// --- 3. the policed client -------------------------------------------
	policyName := run
	jan.addPolicy(policyName)
	np, err := buildProbeDenyPolicy(policyName, namespace, e.id, run)
	if err != nil {
		return ProbeVerdict{}, fmt.Errorf("%w: %v", ErrProbeInconclusive, err)
	}
	if err := cli.createNetworkPolicy(ctx, namespace, np); err != nil {
		return ProbeVerdict{}, probeSetupError("create the probe's default-deny NetworkPolicy", namespace, err)
	}
	opts.logf("applied default-deny NetworkPolicy %s", policyName)

	policedName := run + "-policed"
	jan.addPod(policedName)
	policed := buildProbeClientPod(policedName, namespace, e.id, image, targetIP, true, e.opts)
	if _, err := cli.createPod(ctx, namespace, policed); err != nil {
		return ProbeVerdict{}, probeSetupError("create the probe's policed Pod", namespace, err)
	}
	policedCode, err := waitForPodExit(ctx, cli, namespace, policedName)
	if err != nil {
		return ProbeVerdict{}, fmt.Errorf("%w: the probe's policed Pod did not finish: %v",
			ErrProbeInconclusive, err)
	}

	// The measurement. The control reached the target; this Pod tried the same
	// address with a default-deny egress policy selecting it. A non-zero exit
	// is the policy working.
	verdict := ProbeVerdict{
		Enforced:     policedCode != 0,
		ObservedAt:   e.opts.now(),
		Namespace:    namespace,
		ExecutorID:   e.id,
		ProbeVersion: CurrentProbeVersion,
	}
	if verdict.Enforced {
		verdict.Detail = fmt.Sprintf("a Pod in %s reached %s:%d with no policy, and could not reach it "+
			"(exit %d) with a default-deny egress NetworkPolicy selecting it — this cluster's CNI "+
			"enforces NetworkPolicy", namespace, targetIP, probePort, policedCode)
	} else {
		verdict.Detail = fmt.Sprintf("a Pod in %s reached %s:%d with a default-deny egress NetworkPolicy "+
			"selecting it, exactly as it did without one — this cluster accepts NetworkPolicy objects "+
			"and does not enforce them (flannel behaves this way)", namespace, targetIP, probePort)
	}
	opts.logf("%s", verdict.Detail)
	return verdict, nil
}

// probeRoleValue is the label value the deny-all policy selects on. Derived
// from the run id so that two probes running at once — an operator on a laptop
// and a hub's preflight — cannot police each other's Pods.
func probeRoleValue(run string) string { return sanitizeLabelValue(run + "-policed") }

// probeSetupError explains a failed create in terms of the probe.
//
// The 403 is the one worth spelling out: the probe needs exactly the RBAC the
// egress filter itself needs, so an operator hitting this has learned something
// useful — the filter would not have worked either.
func probeSetupError(what, namespace string, err error) error {
	if ae, ok := asAPIError(err); ok && ae.Code == 403 {
		return fmt.Errorf("%w: not allowed to %s in namespace %q: %v — the probe needs the same "+
			"RBAC the egress filter needs:\n"+
			"  - apiGroups: [\"\"]\n    resources: [\"pods\"]\n    verbs: [\"create\", \"get\", \"list\", \"delete\"]\n"+
			"  - apiGroups: [\"networking.k8s.io\"]\n    resources: [\"networkpolicies\"]\n    verbs: [\"create\", \"delete\", \"list\"]",
			ErrProbeInconclusive, what, namespace, ae.Message)
	}
	return fmt.Errorf("%w: could not %s in namespace %q: %v", ErrProbeInconclusive, what, namespace, err)
}

// probeJanitor removes what the probe created, once, on any exit path.
type probeJanitor struct {
	cli       *client
	namespace string
	pods      []string
	policies  []string
	logf      func(string, ...any)
}

func (j *probeJanitor) addPod(name string)    { j.pods = append(j.pods, name) }
func (j *probeJanitor) addPolicy(name string) { j.policies = append(j.policies, name) }

// clean deletes every registered object on a fresh, detached context.
//
// Detached because the usual reason cleanup runs is that the caller's context
// is already done — a timeout, a Ctrl-C — and inheriting it would mean the
// probe reliably leaks precisely when it most needs not to. The policy goes
// first: it is the object whose survival hurts, because a default-deny policy
// left in a shared namespace denies traffic for whatever is scheduled there
// next, while a leftover Pod merely idles.
func (j *probeJanitor) clean() {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), 30*time.Second)
	defer cancel()

	for _, name := range j.policies {
		if err := j.cli.deleteNetworkPolicy(ctx, j.namespace, name); err != nil && !isNotFound(err) {
			j.warn("could not delete probe NetworkPolicy %s/%s: %v — remove it with "+
				"`kubectl -n %s delete netpol %s`, it denies egress for anything that matches it",
				j.namespace, name, err, j.namespace, name)
		}
	}
	for _, name := range j.pods {
		if err := j.cli.deletePod(ctx, j.namespace, name, 0); err != nil && !isNotFound(err) {
			j.warn("could not delete probe Pod %s/%s: %v — remove it with "+
				"`kubectl -n %s delete pod %s`", j.namespace, name, err, j.namespace, name)
		}
	}
}

func (j *probeJanitor) warn(format string, args ...any) {
	if j.logf != nil {
		j.logf(format, args...)
	}
}

// isNotFound reports whether err is the API server saying the object is already
// gone, which during cleanup is success.
func isNotFound(err error) bool {
	ae, ok := asAPIError(err)
	return ok && ae.Code == 404
}

// waitForPodIP polls until the target Pod is Running with an address, which is
// the first moment the control client has something to aim at.
func waitForPodIP(ctx context.Context, cli *client, namespace, name string) (string, error) {
	for {
		p, err := cli.getPod(ctx, namespace, name)
		if err != nil {
			return "", err
		}
		switch p.Status.Phase {
		case phaseRunning:
			if ip := strings.TrimSpace(p.Status.PodIP); ip != "" {
				return ip, nil
			}
		case phaseSucceeded, phaseFailed:
			// The server was supposed to stay up. Exiting means the image has
			// no httpd, or the command was wrong — a fault in the probe or its
			// image, not a finding about the cluster.
			return "", fmt.Errorf("it exited (%s) instead of serving: %s",
				p.Status.Phase, firstNonEmpty(terminatedMessage(p), p.Status.Message, p.Status.Reason))
		}
		if !sleepCtx(ctx, probePollInterval) {
			return "", fmt.Errorf("%w (last phase %s: %s)", ctx.Err(), p.Status.Phase,
				firstNonEmpty(waitingMessage(p), p.Status.Message, p.Status.Reason))
		}
	}
}

// waitForPodExit polls until the Pod reaches a terminal phase and returns the
// container's exit code — the probe's entire measurement apparatus.
func waitForPodExit(ctx context.Context, cli *client, namespace, name string) (int, error) {
	for {
		p, err := cli.getPod(ctx, namespace, name)
		if err != nil {
			return 0, err
		}
		if p.Status.Phase == phaseSucceeded || p.Status.Phase == phaseFailed {
			for _, cs := range p.Status.ContainerStatuses {
				if cs.State.Terminated != nil {
					return cs.State.Terminated.ExitCode, nil
				}
			}
			// Terminal with no terminated container status: the Pod was
			// evicted or deleted out from under the probe. There is no exit
			// code to read, and inventing one would invent a measurement.
			if p.Status.Phase == phaseFailed {
				return 0, fmt.Errorf("it failed without an exit code (%s): %s",
					p.Status.Reason, p.Status.Message)
			}
			return 0, nil
		}
		if !sleepCtx(ctx, probePollInterval) {
			return 0, fmt.Errorf("%w (last phase %s: %s)", ctx.Err(), p.Status.Phase,
				firstNonEmpty(waitingMessage(p), p.Status.Message, p.Status.Reason))
		}
	}
}

// waitingMessage extracts the kubelet's reason for a Pod that has not started,
// which is where "ImagePullBackOff" lives — the most common probe failure on a
// cluster that cannot reach the image registry.
func waitingMessage(p *pod) string {
	for _, cs := range append(append([]containerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
			return strings.TrimSpace(cs.State.Waiting.Reason + ": " + cs.State.Waiting.Message)
		}
	}
	return ""
}

// terminatedMessage extracts the reason a container stopped.
func terminatedMessage(p *pod) string {
	for _, cs := range p.Status.ContainerStatuses {
		if cs.State.Terminated != nil {
			return strings.TrimSpace(cs.State.Terminated.Reason + ": " + cs.State.Terminated.Message)
		}
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return "no detail reported"
}

// probeTolerations projects the executor's tolerations onto the API shape, so
// the probe lands on the same nodes a harness would. Probing nodes the real
// workloads never reach would measure the wrong half of the cluster.
func probeTolerations(opts Options) []toleration {
	var out []toleration
	for _, t := range opts.Tolerations {
		out = append(out, t.toAPI())
	}
	return out
}

// int64Ptr is the &literal the Pod spec's optional int64 fields need.
func int64Ptr(v int64) *int64 { return &v }

// pullSecretRefs projects the executor's configured pull secrets onto the Pod
// spec's reference shape, dropping blanks exactly as buildPod does.
func pullSecretRefs(names []string) []localObjectRef {
	var out []localObjectRef
	for _, name := range names {
		if n := strings.TrimSpace(name); n != "" {
			out = append(out, localObjectRef{Name: n})
		}
	}
	return out
}

// probeLabels are the labels every probe object carries.
//
// All four of the sweep's labels are here, including LabelTaskID, and that one
// is load-bearing rather than cosmetic: executorLabelSelector ends in a bare
// `cloop.dev/task-id`, which Kubernetes reads as an existence requirement, so an
// object without it is invisible to the orphan sweep. A probe Pod could survive
// that — it carries activeDeadlineSeconds and the cluster reaps it — but nothing
// in Kubernetes ever expires a NetworkPolicy. A probe killed with SIGKILL, the
// one exit path its janitor cannot cover, would otherwise leave a default-deny
// policy in the namespace permanently.
//
// The value is "probe" because there is no task: the label's job here is to make
// the object sweepable and to let an operator tell a diagnostic's leftovers from
// a run's. labelProbe carries the run id for the same reason.
func probeLabels(executorID, run string) map[string]string {
	return map[string]string{
		LabelManaged:    "true",
		LabelExecutorID: sanitizeLabelValue(executorID),
		LabelTaskID:     "probe",
		labelProbe:      sanitizeLabelValue(run),
	}
}

// probeSecurityContext is the same confinement a harness Pod gets. The probe
// runs an unknown image on the operator's cluster, so it gets no more privilege
// than the workloads it is clearing the way for.
func probeSecurityContext(opts Options) *podSecurityContext {
	uid, gid := opts.RunAsUser, opts.RunAsGroup
	if uid <= 0 {
		uid = DefaultRunAsUser
	}
	if gid <= 0 {
		gid = DefaultRunAsGroup
	}
	t := true
	return &podSecurityContext{
		RunAsNonRoot:   &t,
		RunAsUser:      &uid,
		RunAsGroup:     &gid,
		FSGroup:        &gid,
		SeccompProfile: &seccompProfile{Type: "RuntimeDefault"},
	}
}

// probeContainerSecurityContext drops everything a busybox httpd does not need.
func probeContainerSecurityContext() *containerSecurityContext {
	f := false
	t := true
	return &containerSecurityContext{
		AllowPrivilegeEscalation: &f,
		ReadOnlyRootFilesystem:   &t,
		Privileged:               &f,
		Capabilities:             &capabilities{Drop: []string{"ALL"}},
	}
}

// buildProbeTargetPod serves one byte over HTTP for the clients to fetch.
//
// The document root is an emptyDir because the root filesystem is read-only,
// and busybox httpd needs somewhere to serve from. restartPolicy Never so a
// crashed server stays crashed and waitForPodIP reports it, rather than the
// kubelet quietly restarting it under a probe that is timing the result.
func buildProbeTargetPod(name, namespace, executorID, image string, opts Options) *pod {
	run := strings.TrimSuffix(name, "-target")
	script := fmt.Sprintf("set -e; mkdir -p /probe/www; echo ok > /probe/www/probe; "+
		"exec httpd -f -p %d -h /probe/www", probePort)
	return &pod{
		APIVersion: "v1",
		Kind:       "Pod",
		Metadata: objectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      probeLabels(executorID, run),
			Annotations: map[string]string{AnnotationEgressMode: "probe-target"},
		},
		Spec: podSpec{
			RestartPolicy:                 "Never",
			AutomountServiceAccountToken:  boolPtr(false),
			TerminationGracePeriodSeconds: int64Ptr(0),
			// Bounded in the cluster as well as in this process: a probe killed
			// with SIGKILL runs no deferred cleanup, and without this the target
			// would serve forever.
			ActiveDeadlineSeconds: int64Ptr(600),
			SecurityContext:       probeSecurityContext(opts),
			NodeSelector:          opts.NodeSelector,
			Tolerations:           probeTolerations(opts),
			Volumes:               []volume{{Name: "probe", EmptyDir: &emptyDirSource{}}},
			Containers: []container{{
				Name:            ContainerName,
				Image:           image,
				ImagePullPolicy: strings.TrimSpace(opts.ImagePullPolicy),
				Command:         []string{"sh", "-c", script},
				SecurityContext: probeContainerSecurityContext(),
				VolumeMounts:    []volumeMount{{Name: "probe", MountPath: "/probe"}},
			}},
			ImagePullSecrets: pullSecretRefs(opts.ImagePullSecrets),
		},
	}
}

// buildProbeClientPod fetches the target once and exits with the result.
//
// wget's exit status is the measurement: 0 when the body came back, non-zero on
// a refusal or a timeout. -T bounds the attempt so a dropped packet becomes a
// non-zero exit in seconds rather than hanging until the probe's own deadline,
// which would make a blocked connection indistinguishable from a stuck one.
func buildProbeClientPod(name, namespace, executorID, image, targetIP string, policed bool, opts Options) *pod {
	run := strings.TrimSuffix(strings.TrimSuffix(name, "-control"), "-policed")
	labels := probeLabels(executorID, run)
	role := "control"
	if policed {
		role = "policed"
		// The label the deny-all policy selects on, and the reason this Pod is
		// governed at all. It belongs here rather than at the call site: a
		// policed client that lost this label would be selected by nothing,
		// connect exactly as the control did, and be recorded as a *refutation*
		// — the probe reporting that the cluster ignores NetworkPolicy when
		// what it actually did was forget to ask.
		labels[labelProbeRole] = probeRoleValue(run)
	}
	url := fmt.Sprintf("http://%s/probe", joinHostPort(targetIP, probePort))
	script := fmt.Sprintf("wget -q -T %d -O - %s", probeConnectTimeoutSeconds, url)
	return &pod{
		APIVersion: "v1",
		Kind:       "Pod",
		Metadata: objectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
			Annotations: map[string]string{
				AnnotationEgressMode: "probe-" + role,
			},
		},
		Spec: podSpec{
			RestartPolicy:                 "Never",
			AutomountServiceAccountToken:  boolPtr(false),
			TerminationGracePeriodSeconds: int64Ptr(0),
			ActiveDeadlineSeconds:         int64Ptr(120),
			SecurityContext:               probeSecurityContext(opts),
			NodeSelector:                  opts.NodeSelector,
			Tolerations:                   probeTolerations(opts),
			Containers: []container{{
				Name:            ContainerName,
				Image:           image,
				ImagePullPolicy: strings.TrimSpace(opts.ImagePullPolicy),
				Command:         []string{"sh", "-c", script},
				SecurityContext: probeContainerSecurityContext(),
			}},
			ImagePullSecrets: pullSecretRefs(opts.ImagePullSecrets),
		},
	}
}

// buildProbeDenyPolicy is a default-deny egress policy selecting only the
// policed client.
//
// It selects on labelProbeRole, whose value carries the run id, so that two
// concurrent probes cannot police each other — and, more importantly, so that
// this policy can never select a *harness* Pod. It is compiled from an empty
// netfilter.Input by the same renderer the real per-run policies use, which is
// what makes the experiment a test of the mechanism actually in use rather than
// of a hand-written object that resembles it.
func buildProbeDenyPolicy(name, namespace, executorID, run string) (*netfilter.NetworkPolicy, error) {
	policy, err := netfilter.Compile(netfilter.Input{})
	if err != nil {
		return nil, fmt.Errorf("compile the probe's deny-all policy: %w", err)
	}
	labels := probeLabels(executorID, run)
	np, err := netfilter.RenderNetworkPolicy(policy, netfilter.NetworkPolicyOptions{
		Name:        name,
		Namespace:   namespace,
		PodSelector: map[string]string{labelProbeRole: probeRoleValue(run)},
		Labels:      labels,
		Annotations: map[string]string{
			AnnotationEgressMode: "probe-deny-all",
		},
		// Deliberately false. Cluster DNS is the one hole a default-deny policy
		// is usually punched for, and the probe must not punch it: the client
		// connects to a bare IP, so it needs no resolver, and leaving DNS open
		// would mean the experiment tested a policy nobody runs.
		AllowClusterDNS: false,
	})
	if err != nil {
		return nil, fmt.Errorf("render the probe's deny-all policy: %w", err)
	}
	return np, nil
}

// joinHostPort brackets an IPv6 literal, which a cluster with an IPv6 pod
// network will hand back and which would otherwise produce a URL wget rejects.
func joinHostPort(ip string, port int) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}
