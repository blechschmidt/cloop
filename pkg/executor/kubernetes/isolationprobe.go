package kubernetes

// isolationprobe.go verifies the RuntimeClass this executor names: a Pod runs
// `cloop isolation-probe` under it, and what the kernel serving that Pod says
// about itself is compared with the node's own kernel (Task 20439).
//
// A RuntimeClass called "kata" whose handler is runc is the case this exists
// for. The name is all the API shows a client, and Capabilities read
// Virtualized off it; the handler is node configuration nothing in the
// executor's reach can inspect.
//
// # The node's kernel, within the executor Role
//
// A hub cannot read a Node object: nodes are cluster-scoped, and the executor
// Role is a namespaced Role that grants pods, pods/log, secrets and
// networkpolicies, verb for verb (rbac.go, checked by rbac_test.go and CI). So
// the node's kernel is read the only way those verbs allow: a second Pod, bound
// to the node the probe Pod ran on with spec.nodeName and run under the
// cluster's default runtime. On a node whose default handler is runc, that Pod
// shares the node's kernel, boot ID and all. If the cluster's default is itself
// a sandbox, the reference reads a kernel booted seconds before it, and
// isolationprobe.Classify refuses to compare against it.
//
// Both Pods use create, get and delete on pods and get on pods/log — nothing
// the Role does not already hold.
//
// # The probe binary
//
// Kubernetes has no way to bind a file from the hub into a Pod — host mounts
// are refused on this driver, a Secret holds a megabyte, and the Role has no
// ConfigMaps. The probe is therefore the cloop the executor's own image ships:
// the image the operator configured, never a project's sandbox.yaml image,
// which no probe Pod ever runs. A container or device executor binds its own
// binary instead (pkg/executor/container), so an image there cannot answer
// for the probe at all.

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/isolationprobe"
)

const (
	// isolationProbeNamePrefix starts every probe Pod's name.
	isolationProbeNamePrefix = "cloop-isolation-probe-"
	// isolationProbeTimeout bounds one probe: two Pods, each with an image
	// pull on a cold node and, for the first, a VM's boot.
	isolationProbeTimeout = 4 * time.Minute
	// isolationProbeDeadline is each Pod's activeDeadlineSeconds, so a probe
	// killed before its janitor ran is still reaped by the cluster.
	isolationProbeDeadline = 300
	// labelIsolationProbe carries the probe's run id.
	labelIsolationProbe = "cloop.dev/isolation-probe"
)

// IsolationRuntime implements executor.IsolationClaimer: the RuntimeClass this
// executor's Pods run under, empty for the cluster's default.
func (e *Executor) IsolationRuntime() (string, bool) { return e.opts.RuntimeClass, true }

// ProbeIsolation implements executor.IsolationProber.
func (e *Executor) ProbeIsolation(ctx context.Context) (executor.IsolationProbe, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, isolationProbeTimeout)
	defer cancel()
	out := executor.IsolationProbe{Runtime: e.opts.RuntimeClass, Image: e.opts.Image}

	creds, cli, err := e.connect(ctx, "")
	if err != nil {
		return out, fmt.Errorf("kubernetes: connect for the isolation probe: %w", err)
	}
	defer func() {
		cli.close()
		e.opts.Credentials.Release(creds.LeaseID)
	}()
	namespace := e.namespaceFor(creds)
	run := isolationProbeNamePrefix + strings.ToLower(newHandleID())
	if err := validateDNSSubdomain(run+"-reference", "isolation probe pod name"); err != nil {
		return out, err
	}
	jan := &probeJanitor{cli: cli, namespace: namespace}
	defer jan.clean()

	// The probe, under the RuntimeClass the executor claims.
	probeName := run + "-probe"
	jan.addPod(probeName)
	if _, err := cli.createPod(ctx, namespace, buildIsolationProbePod(probeName, namespace, e.id, run,
		e.opts.RuntimeClass, "", e.opts)); err != nil {
		return out, fmt.Errorf("kubernetes: create the isolation probe Pod in namespace %q: %w", namespace, err)
	}
	ev, node, err := readIsolationProbe(ctx, cli, namespace, probeName, e.opts.Image)
	if err != nil {
		return out, fmt.Errorf("kubernetes: the isolation probe under %s: %w", runtimeClassName(e.opts.RuntimeClass), err)
	}
	if node == "" {
		return out, fmt.Errorf("kubernetes: the isolation probe Pod finished without naming its node, so " +
			"there is no node to read the reference kernel on")
	}

	// The reference: the node's own kernel, under the cluster's default
	// runtime, on the same node.
	refName := run + "-reference"
	jan.addPod(refName)
	if _, err := cli.createPod(ctx, namespace, buildIsolationProbePod(refName, namespace, e.id, run,
		"", node, e.opts)); err != nil {
		return out, fmt.Errorf("kubernetes: create the isolation probe's reference Pod on node %s: %w", node, err)
	}
	ref, refNode, err := readIsolationProbe(ctx, cli, namespace, refName, e.opts.Image)
	if err != nil {
		return out, fmt.Errorf("kubernetes: the isolation probe's reference Pod on node %s: %w", node, err)
	}
	if refNode != node {
		// Comparing two nodes' kernels would read a second machine as isolation.
		return out, fmt.Errorf("kubernetes: the reference Pod ran on node %q, not %q where the probe ran", refNode, node)
	}
	out.Evidence = ev
	out.Reference = isolationprobe.Reference{Kernel: &ref, Source: isolationprobe.SourceClusterNode}
	return out, nil
}

func runtimeClassName(rc string) string {
	if strings.TrimSpace(rc) == "" {
		return "the cluster's default runtime"
	}
	return fmt.Sprintf("RuntimeClass %q", rc)
}

// isolationProbeLabels mark a probe Pod. LabelTaskID is set, as the
// NetworkPolicy probe's is, so the orphan sweep can reap one a killed hub left
// behind.
func isolationProbeLabels(executorID, run string) map[string]string {
	return map[string]string{
		LabelManaged:        "true",
		LabelExecutorID:     sanitizeLabelValue(executorID),
		LabelTaskID:         "probe",
		labelIsolationProbe: sanitizeLabelValue(run),
	}
}

// buildIsolationProbePod runs the probe once. runtimeClass is the probe's
// RuntimeClass, empty for the reference; node pins the reference to the probe
// Pod's node, empty for the probe itself.
//
// The confinement is a harness Pod's: non-root, no privilege escalation, no
// capabilities, a read-only root filesystem, no service account token. The
// probe reads kernel interfaces and needs none of what those take away.
func buildIsolationProbePod(name, namespace, executorID, run, runtimeClass, node string, opts Options) *pod {
	f := false
	return &pod{
		APIVersion: "v1",
		Kind:       "Pod",
		Metadata: objectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    isolationProbeLabels(executorID, run),
		},
		Spec: podSpec{
			RestartPolicy:                 "Never",
			AutomountServiceAccountToken:  boolPtr(false),
			EnableServiceLinks:            &f,
			TerminationGracePeriodSeconds: int64Ptr(0),
			ActiveDeadlineSeconds:         int64Ptr(isolationProbeDeadline),
			SecurityContext:               probeSecurityContext(opts),
			NodeSelector:                  opts.NodeSelector,
			Tolerations:                   probeTolerations(opts),
			RuntimeClassName:              strings.TrimSpace(runtimeClass),
			NodeName:                      node,
			Containers: []container{{
				Name:            ContainerName,
				Image:           opts.Image,
				ImagePullPolicy: strings.TrimSpace(opts.ImagePullPolicy),
				Command:         []string{"cloop", isolationprobe.Arg},
				SecurityContext: probeContainerSecurityContext(),
			}},
			ImagePullSecrets: pullSecretRefs(opts.ImagePullSecrets),
		},
	}
}

// readIsolationProbe waits for a probe Pod to finish and returns its evidence
// and the node it ran on.
func readIsolationProbe(ctx context.Context, cli *client, namespace, name, image string) (isolationprobe.Evidence, string, error) {
	var (
		node string
		code = -1
	)
wait:
	for {
		p, err := cli.getPod(ctx, namespace, name)
		if err != nil {
			return isolationprobe.Evidence{}, "", err
		}
		if n := strings.TrimSpace(p.Spec.NodeName); n != "" {
			node = n
		}
		if p.Status.Phase == phaseSucceeded || p.Status.Phase == phaseFailed {
			for _, cs := range p.Status.ContainerStatuses {
				if cs.State.Terminated != nil {
					code = cs.State.Terminated.ExitCode
				}
			}
			if code < 0 {
				return isolationprobe.Evidence{}, node, fmt.Errorf("the Pod ended %s without an exit code: %s",
					p.Status.Phase, firstNonEmpty(p.Status.Reason, p.Status.Message))
			}
			break wait
		}
		if !sleepCtx(ctx, probePollInterval) {
			return isolationprobe.Evidence{}, node, fmt.Errorf("%w (last phase %s: %s)", ctx.Err(), p.Status.Phase,
				firstNonEmpty(waitingMessage(p), p.Status.Message, p.Status.Reason))
		}
	}

	rc, err := cli.followLogs(ctx, namespace, name, ContainerName, false)
	if err != nil {
		return isolationprobe.Evidence{}, node, fmt.Errorf("read the probe's output: %w", err)
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, isolationprobe.MaxOutput))
	if err != nil {
		return isolationprobe.Evidence{}, node, fmt.Errorf("read the probe's output: %w", err)
	}
	ev, err := isolationprobe.Decode(b)
	if err != nil {
		if code != 0 {
			// The image's cloop predates the probe, or the image has none.
			return isolationprobe.Evidence{}, node, fmt.Errorf("`cloop %s` exited %d in the executor's image %s, "+
				"which is how an image whose cloop predates the probe answers: %w", isolationprobe.Arg, code, image, err)
		}
		return isolationprobe.Evidence{}, node, err
	}
	return ev, node, nil
}
