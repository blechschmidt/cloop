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
// # Who deletes it when this process does not
//
// That used to be an honest gap: a control plane killed between creating the
// Secret and seeing the init container finish left the Secret behind, and
// nothing swept it, because sweeping needs `list secrets` and this driver
// deliberately has no read access to Secrets at all (see the Role in the Helm
// chart).
//
// It is now closed, and without taking that read access. The Secret carries an
// ownerReference naming the Pod that consumes it, so the cluster's own garbage
// collector deletes it when the Pod goes — whether the Pod was deleted by this
// driver, by the orphan sweep, by a node eviction, or by an operator. The
// explicit delete above is still the fast path, because it takes the material
// back at the end of one init container rather than at the end of the run; GC
// is the path that does not require this process to still exist.
//
// That is what moved the create to *after* the Pod. An ownerReference needs the
// owner's UID, the API server assigns it, and a client cannot choose it — so
// there is no ordering in which a Secret created first can name the Pod that
// comes second. The Pod is created first and parks harmlessly for the few
// milliseconds until its Secret lands: it is unschedulable-then-scheduled in
// that window, and the kubelet cannot reach a secretKeyRef before the scheduler
// has bound the Pod at all. What the reordering buys is that from the instant
// the material exists in etcd, something other than this process is responsible
// for destroying it.

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
	// plannedName is the Secret the Pod's init container references. It is ""
	// when no credential was leased, which is the ordinary case for a public
	// repository: the init container then has no token env var at all and the
	// fetch is unauthenticated.
	//
	// It is set before the Secret exists, because the Pod is built — and now
	// created — first, so that the Secret can name it as its owner.
	plannedName string
	// secretName is what cleanup deletes. It is set only once a create has
	// happened that may have landed, which is what keeps a failure path from
	// arming a delete for an object that was never there. It therefore lags
	// plannedName, and the two are never used for each other's purpose.
	secretName string
	namespace  string
	handleID   string

	workspace executor.Workspace
	// routed is workspace with any git-proxy redirection applied. It is what
	// the Pod fetches and pushes through; workspace above stays the true
	// upstream so the audit rows name the repository an operator recognises.
	routed      executor.Workspace
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
//
// This is the planned name, not the created one. The Pod is built and created
// before the Secret exists — see the file comment on ownerReferences — so a
// reader that waited for the create would wire no reference at all.
func (s *workspaceState) secret() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.plannedName
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

// pendingSecret is a per-run Secret that has been decided but not yet created,
// because the Pod that will own it does not exist yet.
//
// The split it represents is forced by ownerReferences: the Secret's content is
// decided before the Pod — the Pod spec references it by name, and for the
// workspace Secret the same broker call also decides where the fetch is routed
// — while the Secret's *creation* has to come after, because an ownerReference
// needs a UID only the API server can assign. So provisioning returns what it
// decided, and Start materialises it once it has an owner.
//
// A nil *pendingSecret means there is nothing to create: a public-repository
// workspace that leased no credential, or a Spec carrying no credential files.
//
// # Exactly one of materialise and abandon runs
//
// That invariant is the whole reason this is a struct and not a bare closure.
// The workspace credential is held on a broker lease that must come back
// whether or not the Secret is ever written, and Start has failure paths
// between deciding and creating — a refused Pod create being the obvious one.
// A closure that released only on the create path would leak the lease on
// every one of them, with the broker believing a credential is out on loan for
// the rest of the hub's life. Both methods are idempotent and nil-safe so the
// cleanup path can call abandon without knowing whether Start got far enough
// to materialise.
type pendingSecret struct {
	// create writes the object. The owner may be the zero reference with
	// owned=false, which creates the Secret unowned rather than failing the
	// run. Everything else it needs — the built object, the credential to
	// redact an API error against, and the lease to release — it captured
	// lexically, so the material never has to be parked on a struct field to
	// survive the gap between deciding and creating.
	create func(ctx context.Context, owner ownerReference, owned bool) error
	// release returns what the decision borrowed, on the paths where create is
	// never called. Nil when nothing was borrowed.
	release func()
	done    bool
}

// materialise creates the Secret, owned by the Pod when one is available.
func (p *pendingSecret) materialise(ctx context.Context, owner ownerReference, owned bool) error {
	if p == nil || p.done {
		return nil
	}
	p.done = true
	return p.create(ctx, owner, owned)
}

// abandon gives back whatever the decision borrowed, for a Start that failed
// before there was a Pod to own the Secret.
func (p *pendingSecret) abandon() {
	if p == nil || p.done {
		return
	}
	p.done = true
	if p.release != nil {
		p.release()
	}
}

// provisionWorkspace leases the workspace credential and prepares the Secret
// the Pod's init container will mount.
//
// It returns a non-nil state whenever the Spec asks for provisioning, even on
// the paths where no Secret will be created, so the caller has something to
// clean up with and something to audit against. A nil state means the Spec
// asked for nothing and there is nothing to undo.
//
// The Secret is *not* created here — see pendingSecret. The returned closure
// creates it, and is also what releases the broker lease, so the documented
// lease lifetime is unchanged: released as soon as the cluster holds the
// material, not when the fetch finishes.
//
// A *executor.WorkspaceGrantError from the credential source is returned
// unchanged. It is the one error in this package a caller is expected to type-
// assert: the UI renders its Remediation() as the exact `cloop secret grant`
// command, and wrapping it in a fmt.Errorf that hid the type would turn that
// into an unactionable string.
func (e *Executor) provisionWorkspace(ctx context.Context, spec executor.Spec, cli *client,
	handleID, namespace, projectPath string) (*workspaceState, *pendingSecret, error) {

	if !spec.Workspace.NeedsProvisioning() {
		return nil, nil, nil
	}

	st := &workspaceState{
		namespace:   namespace,
		handleID:    handleID,
		workspace:   spec.Workspace,
		routed:      spec.Workspace,
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
		var access executor.WorkspaceAccess
		access, release, err = e.opts.Workspace.ForWorkspace(ctx, projectPath, spec.Workspace)
		cred = access.Credential
		st.routed = access.Apply(spec.Workspace)
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
			return st, nil, e.failWorkspace(st, cred, err)
		}
	} else if spec.Workspace.RequiresCredential() {
		// The Spec named a grant and there is nothing here to honour it with.
		// That is a configuration failure on the hub, not a missing grant, so
		// it must not masquerade as one — the operator's fix is to wire the
		// broker, not to create a grant that already exists.
		release()
		return st, nil, e.failWorkspace(st, cred, fmt.Errorf(
			"%w: this executor has no workspace credential source, so grant %q cannot be honoured; "+
				"the hub was built or configured without a secret broker",
			executor.ErrWorkspaceUnavailable, strings.TrimSpace(spec.Workspace.CredentialGrant)))
	}

	st.grantID, st.leaseID = cred.GrantID, cred.LeaseID
	if cred.Empty() {
		// Nothing to deliver. The init container still runs — the tree still
		// has to be fetched — it just has no token env var. Nothing was leased
		// that the create path would have released, so release here: there is
		// no pendingSecret to carry it.
		release()
		return st, nil, nil
	}
	if !cred.ExpiresAt.IsZero() && !cred.ExpiresAt.After(e.opts.now()) {
		// A credential that has already lapsed would produce a 401 from the
		// remote and a failed run whose cause is three layers away.
		release()
		return st, nil, e.failWorkspace(st, cred, fmt.Errorf(
			"%w: the leased workspace credential expired at %s, before the Pod could be created",
			executor.ErrWorkspaceUnavailable, cred.ExpiresAt.UTC().Format(time.RFC3339)))
	}

	name := workspaceSecretName(handleID)
	// Recorded before the create, because the Pod is built before the create
	// and its init container references the Secret by this name. secretName —
	// the name cleanup deletes — stays unset until a create that may have
	// landed, so a failure path does not arm a delete for an object that was
	// never there.
	st.mu.Lock()
	st.plannedName = name
	st.mu.Unlock()
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

	// Everything below runs after the Pod exists. cred, obj and release are
	// captured rather than stored on the state: the token is already inside obj,
	// so closing over it adds no exposure, and keeping it out of a struct field
	// means there is no lifetime to reason about beyond this closure's own.
	create := func(ctx context.Context, owner ownerReference, owned bool) error {
		// Released as soon as the cluster holds the material — unchanged by the
		// move, because the release travelled here with the create it was
		// always paired with. See the file comment.
		defer release()

		if owned {
			obj.Metadata.OwnerReferences = []ownerReference{owner}
		}

		createCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), requestTimeout)
		defer cancel()
		if _, err := cli.createSecret(createCtx, namespace, obj); err != nil {
			// A create that failed may still have landed. A 4xx is the API
			// server stating it did not — a rejection, a conflict, an
			// authorization failure — so there is nothing to clean up and arming
			// the delete would only produce a second confusing 403 in the log.
			// Anything else (a timeout, a 5xx, a connection dropped after the
			// request was written) leaves the question open, and an orphaned
			// Secret holding a live credential is much worse than a delete for
			// an object that was never created, which the API server answers 404
			// and this driver treats as success.
			//
			// The ownerReference makes this less load-bearing than it was: a
			// Secret that landed unseen is now reaped with the Pod regardless.
			// The explicit delete is kept because it takes the material back in
			// seconds rather than whenever the Pod ends.
			if ae, ok := asAPIError(err); !ok || ae.Code >= 500 {
				st.mu.Lock()
				st.secretName = name
				st.mu.Unlock()
			}
			return e.failWorkspace(st, cred, explainSecretFailure(namespace, name, err))
		}

		st.mu.Lock()
		st.secretName = name
		st.mu.Unlock()
		return nil
	}
	return st, &pendingSecret{create: create, release: release}, nil
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
