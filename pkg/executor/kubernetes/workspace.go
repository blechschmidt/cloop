package kubernetes

// workspace.go is the control-plane half of getting a source tree into a Pod.
// The other half — the git commands themselves — runs inside the cluster, as
// the init container buildPod renders, executing `cloop workspace provision`.
//
// The split exists because the credential must not be where the driver is. A
// control plane that cloned the repository itself would have to hold the tree,
// then ship it into a Pod it cannot write to; a control plane that put the
// token in the Pod spec would publish it to everyone with `get pods`. So the
// driver does the one thing only it can do — lease the credential from the
// broker — parks it in a Secret that exactly one container mounts, and gets out
// of the way.
//
// # The lifetime of the material
//
// A brokered token is short-lived by design, and this file's job is to keep the
// *copy* it makes at least as short-lived:
//
//	lease ──► Secret created ──► lease released ──► init container runs
//	                                                       │
//	                              Secret deleted ◄──────────┘
//
// The lease is released as soon as the Secret exists, not when the fetch
// finishes. By that point the cluster holds the material and the broker's lease
// no longer controls anything: releasing later would not make the copy in etcd
// any less available, it would only keep the broker believing a credential is
// out on loan for the length of a run. Releasing here also means the whole
// credential-handling path is one function with a `defer release()` in it,
// which is a stronger guarantee than remembering to release on nine branches.
//
// The Secret is deleted when the init container terminates — success or
// failure, seen through initContainerStatuses in the watch the driver already
// runs — and again, unconditionally, when the workload reaches a terminal state
// or when Start fails at any point after the Secret was created.
//
// One honest gap: a control plane killed between creating the Secret and seeing
// the init container finish leaves the Secret behind. Nothing sweeps it,
// because sweeping needs `list secrets` and this driver deliberately has no
// read access to Secrets at all (see the Role in the Helm chart). The window is
// seconds, and the material inside expires on the broker's own TTL regardless,
// which is a better trade than holding read authority over every Secret in the
// namespace for the rest of time.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// workspaceSecretPrefix names the Secrets this driver creates. It is a
// recognisable prefix so an operator who finds one left behind by a crashed
// control plane knows what it is and that deleting it is safe.
const workspaceSecretPrefix = "cloop-ws-"

// workspaceState is one run's provisioning bookkeeping.
//
// It holds no credential. Everything here is an identifier, a name or a
// timestamp — the token exists only inside provisionWorkspace's stack frame and
// in the Secret it writes, which is what makes "where could this leak" a
// question with a short answer.
type workspaceState struct {
	// secretName is "" when no credential was leased, which is the ordinary
	// case for a public repository. The Pod then has an init container with no
	// token env var at all and the fetch is unauthenticated.
	secretName string
	namespace  string
	handleID   string

	workspace   executor.Workspace
	projectPath string
	grantID     string
	leaseID     string
	startedAt   time.Time

	mu sync.Mutex
	// deleted and ended make the two terminal actions idempotent. Both can be
	// reached from the watcher goroutine and from the pump at the same moment,
	// and a second delete is a spurious API call while a second audit row is a
	// compliance trail that double-counts.
	deleted bool
	ended   bool
}

// secret returns the Secret name the Pod must reference, or "" when there is
// none. Nil-safe, because the ordinary case — a Spec with no workspace at all —
// produces no state and every caller would otherwise need the same guard.
func (s *workspaceState) secret() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secretName
}

// workspaceSecretName derives the Secret's name from the handle ID.
//
// Deterministic rather than generateName, because the Pod that references it is
// built before either object exists and a name the API server chose would have
// to be threaded back. The handle ID is already a short random token, so
// collision is not a concern; sanitising it keeps a future ID format from
// producing a name the API server rejects.
func workspaceSecretName(handleID string) string {
	slug := sanitizeDNSLabel(handleID)
	if slug == "" {
		slug = "none"
	}
	return workspaceSecretPrefix + slug
}

// provisionWorkspace leases the workspace credential and parks it in a Secret
// the Pod's init container can mount.
//
// It returns a non-nil state whenever the Spec asks for provisioning, even on
// the paths where no Secret was created, so the caller has something to clean
// up with and something to audit against. A nil state means the Spec asked for
// nothing and there is nothing to undo.
//
// A *executor.WorkspaceGrantError from the credential source is returned
// unchanged. It is the one error in this package a caller is expected to type-
// assert: the UI renders its Remediation() as the exact `cloop secret grant`
// command, and wrapping it in a fmt.Errorf that hid the type would turn that
// into an unactionable string.
func (e *Executor) provisionWorkspace(ctx context.Context, spec executor.Spec, cli *client,
	handleID, namespace, projectPath string) (*workspaceState, error) {

	if !spec.Workspace.NeedsProvisioning() {
		return nil, nil
	}

	st := &workspaceState{
		namespace:   namespace,
		handleID:    handleID,
		workspace:   spec.Workspace,
		projectPath: projectPath,
		startedAt:   e.opts.now(),
	}
	e.auditWorkspace(st, executor.WorkspaceProvisionStart, "")

	// The credential source is optional. A nil one is not an error: an
	// unauthenticated fetch of a public repository is a legitimate thing to
	// want, and refusing it would make a public-repo run depend on a secret
	// broker it has no use for. A *private* repository fails at the fetch, in
	// the init container, with git's own message — which names the repository
	// and says authentication failed, and is the correct place for that to
	// surface once no grant was ever asked for.
	var (
		cred    executor.GitCredential
		release = func() {}
	)
	if e.opts.Workspace != nil {
		var err error
		cred, release, err = e.opts.Workspace.ForWorkspace(ctx, projectPath, spec.Workspace)
		if release == nil {
			// The interface promises a non-nil release on every path. This is
			// the guard against an implementation that forgets on one of them,
			// because the failure would be a nil-func panic in a deferred call
			// on the Start path — a crash reported as a workspace bug.
			release = func() {}
		}
		if err != nil {
			release()
			// Returned verbatim: a *executor.WorkspaceGrantError must survive
			// errors.As all the way to the UI, which prints its remediation.
			return st, e.failWorkspace(st, cred, err)
		}
	} else if spec.Workspace.RequiresCredential() {
		// The Spec named a grant and there is nothing here to honour it with.
		// That is a configuration failure on the hub, not a missing grant, so
		// it must not masquerade as one — the operator's fix is to wire the
		// broker, not to create a grant that already exists.
		release()
		return st, e.failWorkspace(st, cred, fmt.Errorf(
			"%w: this executor has no workspace credential source, so grant %q cannot be honoured; "+
				"the hub was built or configured without a secret broker",
			executor.ErrWorkspaceUnavailable, strings.TrimSpace(spec.Workspace.CredentialGrant)))
	}
	// Released here and not at the end of the run: see the file comment.
	defer release()

	st.grantID, st.leaseID = cred.GrantID, cred.LeaseID
	if cred.Empty() {
		// Nothing to deliver. The init container still runs — the tree still
		// has to be fetched — it just has no token env var.
		return st, nil
	}
	if !cred.ExpiresAt.IsZero() && !cred.ExpiresAt.After(e.opts.now()) {
		// A credential that has already lapsed would produce a 401 from the
		// remote and a failed run whose cause is three layers away.
		return st, e.failWorkspace(st, cred, fmt.Errorf(
			"%w: the leased workspace credential expired at %s, before the Pod could be created",
			executor.ErrWorkspaceUnavailable, cred.ExpiresAt.UTC().Format(time.RFC3339)))
	}

	name := workspaceSecretName(handleID)
	obj := &secret{
		APIVersion: "v1",
		Kind:       "Secret",
		Metadata: objectMeta{
			Name:      name,
			Namespace: namespace,
			// Labelled exactly like the Pod, including the task-id the sweep
			// requires to exist, so an operator can find the Secret belonging
			// to a run with the same selector they use for its Pod.
			Labels: map[string]string{
				LabelManaged:    "true",
				LabelExecutorID: sanitizeLabelValue(e.id),
				LabelHandleID:   sanitizeLabelValue(handleID),
				LabelTaskID:     sanitizeLabelValue(taskIDFrom(spec.Labels)),
				LabelProject:    sanitizeLabelValue(projectSlug(spec.Labels["project"])),
			},
			Annotations: map[string]string{
				AnnotationProjectPath: strings.TrimSpace(spec.Labels["project"]),
			},
		},
		Type: "Opaque",
		// The bare token under the env var's own name, so the init container's
		// secretKeyRef needs no mapping table. See EnvWorkspaceToken for why
		// this is the token and not a rendered Authorization header.
		StringData: map[string]string{EnvWorkspaceToken: cred.Password},
	}

	createCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), requestTimeout)
	defer cancel()
	if _, err := cli.createSecret(createCtx, namespace, obj); err != nil {
		// A create that failed may still have landed. A 4xx is the API server
		// stating it did not — a rejection, a conflict, an authorization
		// failure — so there is nothing to clean up and arming the delete would
		// only produce a second confusing 403 in the log. Anything else (a
		// timeout, a 5xx, a connection dropped after the request was written)
		// leaves the question open, and an orphaned Secret holding a live
		// credential is much worse than a delete for an object that was never
		// created, which the API server answers 404 and this driver treats as
		// success.
		if ae, ok := asAPIError(err); !ok || ae.Code >= 500 {
			st.mu.Lock()
			st.secretName = name
			st.mu.Unlock()
		}
		return st, e.failWorkspace(st, cred, explainSecretFailure(namespace, name, err))
	}

	st.mu.Lock()
	st.secretName = name
	st.mu.Unlock()
	return st, nil
}

// failWorkspace closes out a failed provisioning: one end event, with the
// error redacted against the credential in hand.
//
// Redaction matters here and nowhere later. This is the only point at which the
// driver holds the token and is also formatting a message — an API server
// rejecting a Secret quotes back parts of the object, and a 422 that echoed
// stringData would otherwise put the credential into an audit row and a UI
// panel. Once the material is in the cluster there is nothing left in this
// process to redact against, which is why the other end-event paths do not try.
func (e *Executor) failWorkspace(st *workspaceState, cred executor.GitCredential, err error) error {
	if err == nil {
		return nil
	}
	msg := executor.RedactSecrets(err.Error(), cred.Secrets())
	e.auditWorkspace(st, executor.WorkspaceProvisionEnd, msg)
	return err
}

// auditWorkspace emits one provisioning row. The end phase is emitted at most
// once per run, whichever path reaches it first.
func (e *Executor) auditWorkspace(st *workspaceState, phase executor.WorkspaceEventPhase, errMsg string) {
	if st == nil {
		return
	}
	if phase == executor.WorkspaceProvisionEnd {
		st.mu.Lock()
		if st.ended {
			st.mu.Unlock()
			return
		}
		st.ended = true
		st.mu.Unlock()
	}
	ev := executor.WorkspaceEvent{
		Phase:        phase,
		ExecutorID:   e.id,
		ExecutorKind: executor.KindKubernetes,
		HandleID:     st.handleID,
		ProjectPath:  st.projectPath,
		Workspace:    st.workspace,
		GrantID:      st.grantID,
		LeaseID:      st.leaseID,
		Err:          errMsg,
	}
	if phase == executor.WorkspaceProvisionEnd {
		ev.DurationMS = e.opts.now().Sub(st.startedAt).Milliseconds()
	}
	executor.AuditWorkspace(ev)
}

// discardWorkspaceSecret deletes the credential Secret and closes the audit
// span. It is safe to call with a nil state, with a state that never created a
// Secret, and repeatedly — every cleanup path calls it without first checking
// which of those it is looking at.
//
// Failure is reported to stderr and not propagated. By the time this runs the
// caller is either returning an error it already has or finishing a workload
// whose result is collected; replacing either with "could not delete a Secret"
// would lose the thing the operator actually needs to know.
func (e *Executor) discardWorkspaceSecret(st *workspaceState, cli *client, errMsg string) {
	if st == nil {
		return
	}
	st.mu.Lock()
	name := st.secretName
	already := st.deleted
	if name != "" {
		st.deleted = true
	}
	namespace := st.namespace
	st.mu.Unlock()

	e.auditWorkspace(st, executor.WorkspaceProvisionEnd, errMsg)
	if name == "" || already || cli == nil {
		return
	}

	// Detached from any caller's context: this is cleanup that must happen
	// even when the request that triggered it has been cancelled.
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := cli.deleteSecret(ctx, namespace, name); err != nil {
		fmt.Fprintf(os.Stderr, "kubernetes: could not delete workspace secret %s/%s: %v — "+
			"delete it by hand; it holds a brokered credential\n", namespace, name, err)
	}
}

// observeWorkspace reacts to a Pod status update by dropping the credential as
// soon as it is no longer needed.
//
// "As soon as" is the whole point. The init container is the only consumer, and
// it has consumed the Secret by the time the kubelet reports it terminated — so
// the material's exposure is the length of a git fetch rather than the length
// of a run that may last hours. Waiting for the Pod to finish would be simpler
// and would leave a token sitting in etcd for exactly as long as the workload
// is interesting to attack.
func (e *Executor) observeWorkspace(rec *record, p *pod) {
	st := rec.workspace()
	if st == nil || p == nil {
		return
	}
	cs := p.workspaceInitStatus()
	if cs == nil || cs.State.Terminated == nil {
		return
	}
	t := cs.State.Terminated
	var errMsg string
	if t.ExitCode != 0 || t.Signal != 0 {
		errMsg = workspaceFailureMessage(t)
		rec.bus.Emit(fmt.Sprintf("[cloop] workspace provisioning failed: %s\n", errMsg))
	}
	e.discardWorkspaceSecret(st, rec.client(), errMsg)
}

// workspaceFailureMessage renders a failed provisioning step.
//
// It is deliberately not a redaction site: the kubelet composes this from the
// container's exit status and its termination-log, neither of which the token
// ever reaches — the token is an environment variable read by one process and
// handed to git as a config value, never printed, never in argv.
func workspaceFailureMessage(t *stateTerminated) string {
	switch {
	case t.Message != "":
		return firstLine(t.Message)
	case t.Reason != "":
		return fmt.Sprintf("%s (exit %d)", t.Reason, t.ExitCode)
	case t.Signal != 0:
		return fmt.Sprintf("killed by signal %d", t.Signal)
	default:
		return fmt.Sprintf("exit %d", t.ExitCode)
	}
}

// explainSecretFailure turns a rejected Secret create into an actionable error.
//
// It is a sibling of explainCreateFailure rather than a branch inside it,
// because the remedies do not overlap: the interesting failure here is a 403,
// and what an operator needs is the two verbs to add — plus the reassurance
// that they are not being asked for read access, which is the objection anyone
// reviewing an RBAC change to Secrets will raise first.
func explainSecretFailure(namespace, name string, err error) error {
	ae, ok := asAPIError(err)
	if !ok {
		return fmt.Errorf("%w: create workspace secret %s/%s: %w",
			executor.ErrWorkspaceUnavailable, namespace, name, err)
	}
	switch {
	case ae.Code == http.StatusForbidden:
		return fmt.Errorf("%w: not allowed to create Secrets in %q, which a git workspace needs: %w — "+
			"add this rule to the executor's Role:\n"+
			"  - apiGroups: [\"\"]\n"+
			"    resources: [\"secrets\"]\n"+
			"    verbs: [\"create\", \"delete\"]\n"+
			"create and delete only: the driver writes the credential and removes it again, and never "+
			"reads a Secret back",
			executor.ErrWorkspaceUnavailable, namespace, err)
	case ae.Code == http.StatusNotFound:
		return fmt.Errorf("%w: namespace %q does not exist (or the kubeconfig cannot see it): %w",
			executor.ErrWorkspaceUnavailable, namespace, err)
	case ae.Code == http.StatusConflict:
		// The name is derived from the handle ID, so a conflict means a Secret
		// from a previous run of this exact handle survived — which only
		// happens if a control plane died between creating it and deleting it.
		return fmt.Errorf("%w: a workspace secret named %s already exists in %q, left behind by an "+
			"interrupted run: %w — delete it with `kubectl -n %s delete secret %s`",
			executor.ErrWorkspaceUnavailable, name, namespace, err, namespace, name)
	default:
		return fmt.Errorf("%w: create workspace secret %s/%s: %w",
			executor.ErrWorkspaceUnavailable, namespace, name, err)
	}
}
