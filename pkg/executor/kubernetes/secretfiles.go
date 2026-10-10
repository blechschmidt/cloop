package kubernetes

// secretfiles.go delivers a secret lease's credential *files* into a Pod, and
// owns the per-run Secret they travel in — the lease Secret, cloop-lease-<handle>,
// which since Task 20401 also carries every value of the workload's environment
// (see leaseenv.go).
//
// # Why a Secret and not something simpler
//
// A lease produces files, not just environment variables: a repository-scoped
// GitHub PAT delivers its whole enforcement as a gitconfig, a credential helper
// and a token file, and exports no bare token at all. The hub used to write
// those into its own /dev/shm and put the paths into the workload's
// environment, which is a delivery only for a workload running on the hub's
// filesystem. A Pod is on a node the control plane cannot write to, so the
// bytes travel in Spec.SecretFiles and this file puts them somewhere the
// kubelet can project.
//
// The three alternatives were all worse:
//
//   - a hostPath volume would mean writing plaintext onto a node's disk, and
//     the node is not the control plane, so there would be nothing there to
//     write. Hence Capabilities.SecretFilesFromHostPath is false.
//   - a ConfigMap is the same object with none of the handling: no encryption
//     at rest, no restricted RBAC convention, and the kubelet does not back it
//     with tmpfs.
//   - baking the content into the Pod as an env var or a command that writes
//     files would publish the credential to everyone with `get pods`, which is
//     the exact property buildPod exists to preserve.
//
// So: one Secret per run, created right after the Pod that owns it, projected
// read-only at the directory the environment already names, and deleted on
// every path the Pod is cleaned up on — but never before the harness container
// has started, because its environment is read from the same object when the
// kubelet creates it.
//
//	spec.SecretFiles ─┐
//	spec.Env ─────────┴─► Pod created ──► Secret created ──► kubelet projects the files
//	                                            │            (tmpfs, 0440), and resolves the
//	                                            │            env when it creates the harness
//	                                            └──► Secret deleted ◄── workload terminal
//
// # What is not relocated
//
// Dir is honoured verbatim. GIT_CONFIG_GLOBAL, KUBECONFIG and CLOOP_LEASE_DIR
// are already in Spec.Env pointing at it, and a mountPath is one of the few
// things a Pod can place at an absolute path of someone else's choosing — so
// there is no reason to move the files and then have to rewrite the
// environment, which is the step a driver gets wrong once and debugs for a day.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// secretFilesPrefix names the Secrets this file creates, in the same shape as
// workspaceSecretPrefix: recognisable enough that an operator who finds one
// left behind by a crashed control plane knows what it is. It matches the
// prefix pkg/secretbroker gives the lease directory itself, so "cloop-lease-"
// means the same thing in a cluster as it does on a host.
const secretFilesPrefix = "cloop-lease-"

// secretFileMode is the mode the kubelet creates the projected files with.
//
// 0400 rather than the 0600 executor.SecretFile asks for, and the difference is
// not a relaxation. The Pod sets fsGroup (see buildPod), and for a volume it
// owns the kubelet applies that group and ORs group-read into the file mode —
// so 0400 lands as an effective 0440: readable by the workload's user and its
// group, and by nobody else. Asking for 0600 would name a mode the kubelet does
// not preserve, and the object would then disagree with what is on disk, which
// is worse than stating the mode that actually results.
//
// Nothing wider is reachable: the volume is per-Pod, the group is the Pod's
// own, and no other workload shares either.
const secretFileMode int32 = 0o400

// secretExecFileMode is the per-file mode for a lease file that has to be
// executed — the credential helper a GitHub lease's gitconfig runs by path.
//
// defaultMode alone left `git-credential-cloop` without an execute bit, so git
// could not run it and obtained no credential from a GitHub lease in a Pod,
// guarded or not (Task 20349). The execute bit has to be the *group's*: the
// harness runs as a non-root UID that owns nothing in the volume and reaches
// its files through fsGroup, so an owner-only 0500 would still be refused.
// 0550 lands as 0550 after the kubelet ORs in fsGroup's read bits — read and
// execute for the workload's group, nothing for anyone else, and still no
// write for anybody, which is what keeps the helper from being rewritten into
// one that answers for repositories the grant excluded.
const secretExecFileMode int32 = 0o550

// maxLeaseSecretBytes is the API server's cap on a Secret's data, summed over
// its values.
const maxLeaseSecretBytes = 1 << 20

// leaseSecretState is one run's lease-Secret bookkeeping.
//
// Like workspaceState it holds no credential — only the name of the Secret that
// does — which is what keeps "where could this leak" a question with a short
// answer.
type leaseSecretState struct {
	namespace string

	mu sync.Mutex
	// secretName is "" when nothing was created. deleted makes the drop
	// idempotent: Start's release closure and finish both call it without
	// first checking which of them got there, and a second delete is a
	// spurious 404 in the log rather than a second cleanup.
	secretName string
	deleted    bool
	// keys maps each delivered file — its directory as the workload sees it,
	// joined with its name — to the Secret key it is stored under, so a
	// refresh (Task 20375) patches exactly the key the volume projects to that
	// path. Names only, like everything else here.
	keys map[string]string
}

// keyFor returns the Secret key a delivered file is stored under.
func (st *leaseSecretState) keyFor(path string) (string, bool) {
	if st == nil {
		return "", false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	k, ok := st.keys[path]
	return k, ok
}

// leaseSecretName derives the lease Secret's name from the handle ID.
//
// Deterministic rather than generateName, for the reason workspaceSecretName is:
// the Pod that references it is built from a request that does not carry a name
// the API server chose. Being a pure function of the handle ID also means
// buildPod can wire the reference without the create path threading anything
// back to it, and a revocation after a hub restart can find it with nothing but
// the handle.
func leaseSecretName(handleID string) string {
	slug := sanitizeDNSLabel(handleID)
	if slug == "" {
		slug = "none"
	}
	return secretFilesPrefix + slug
}

// secretFileVolumeName names the volume carrying one lease directory. A lease
// produces one; two leases on one workload would produce two, and they must be
// distinct objects or the second would silently replace the first.
func secretFileVolumeName(dirIndex int) string {
	return fmt.Sprintf("%s%d", secretFilesPrefix, dirIndex)
}

// secretFileKey renders the Secret key one file is stored under.
//
// The directory index is a prefix because a Secret is a flat map and a lease may
// name more than one directory: two directories each holding a `gitconfig` would
// otherwise collide on one key, and the workload would read whichever the driver
// happened to write last — for a credential helper, that is answering with a
// grant it was not given. The volume's items map the prefix back off, so the
// workload still sees the bare name its environment points at.
//
// '.' and digits are both legal in a Secret key ([-._a-zA-Z0-9]+), so the prefix
// never makes a legal name illegal.
func secretFileKey(dirIndex int, name string) string {
	return fmt.Sprintf("d%d.%s", dirIndex, name)
}

// validSecretKeyName reports whether name may appear in a Secret's data map.
// The API server's rule is [-._a-zA-Z0-9]+ and it rejects the whole object on a
// violation, with a message about a field path rather than about a credential.
func validSecretKeyName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '.' || r == '_':
		default:
			return false
		}
	}
	return true
}

// secretFilePlan is the single derivation of "which key holds which file, and
// which volume carries which directory".
//
// It exists so the Secret's keys and the volumes' items cannot drift apart.
// Those are built by two different functions, called from two different places
// — the create path and the pure buildPod — and a disagreement between them
// would not fail anything: the Secret would be created, the Pod would be
// created, the kubelet would project a directory missing the file the volume
// asked for, and git would fail to authenticate for a reason nothing named.
// That is precisely the class of failure this whole feature exists to remove.
type secretFilePlan struct {
	// dirs are the distinct directories, in first-appearance order. The index
	// into this slice is the one in secretFileKey and secretFileVolumeName.
	dirs []string
	// keys holds one Secret key per input file, aligned with the input slice.
	keys []string
	// dirIndex holds the directory index per input file, likewise aligned.
	dirIndex []int
}

// planSecretFiles validates a set of credential files and works out where each
// one goes.
//
// The validation is deliberately repeated from executor.ValidateSecretFiles,
// which Spec.Validate already ran. This is the function that turns a name into
// an object the API server acts on, and a check at that point is the one a
// future call path cannot skip.
func planSecretFiles(files []executor.SecretFile) (*secretFilePlan, error) {
	if len(files) == 0 {
		return nil, nil
	}
	if err := executor.ValidateSecretFiles(files); err != nil {
		return nil, fmt.Errorf("kubernetes: %w", err)
	}

	dirs := executor.SecretFileDirs(files)
	index := make(map[string]int, len(dirs))
	for i, d := range dirs {
		index[d] = i
	}

	plan := &secretFilePlan{
		dirs:     dirs,
		keys:     make([]string, len(files)),
		dirIndex: make([]int, len(files)),
	}
	for i, f := range files {
		name := strings.TrimSpace(f.Name)
		// Every credential file a grant produces today — gitconfig,
		// github-token, git-credential-cloop, kubeconfig — is already a legal
		// key. Refusing the ones that are not is still the right answer rather
		// than mangling them: the workload's environment names the file, so a
		// driver that renamed it would deliver a file nothing opens.
		if !validSecretKeyName(name) {
			return nil, fmt.Errorf("%w: secret file %q cannot be a Kubernetes Secret key — "+
				"a key may only contain letters, digits, '-', '_' and '.'",
				executor.ErrInvalidSpec, f.Name)
		}
		plan.dirIndex[i] = index[f.Dir]
		plan.keys[i] = secretFileKey(plan.dirIndex[i], name)
	}
	return plan, nil
}

// leaseSecretData renders the whole lease Secret: one entry per credential
// file, keyed d<N>.<name> by planSecretFiles, and one per environment variable,
// keyed env.<NAME> by planLeaseEnv. Nil when there is nothing to carry, which is
// also exactly when buildPod references no Secret.
//
// The total is checked against the API server's 1 MiB here, because the
// server's refusal names a field rather than the run, and arrives after the Pod
// has been created.
func leaseSecretData(files []executor.SecretFile, env []string) (map[string][]byte, error) {
	fileData, err := secretFileData(files)
	if err != nil {
		return nil, err
	}
	envData, err := leaseEnvData(env)
	if err != nil {
		return nil, err
	}
	if len(fileData)+len(envData) == 0 {
		return nil, nil
	}
	data := make(map[string][]byte, len(fileData)+len(envData))
	total := 0
	for _, part := range []map[string][]byte{fileData, envData} {
		for k, v := range part {
			if _, clash := data[k]; clash {
				// Unreachable while file keys start with "d<digit>" and env
				// keys with "env." — checked so a future key scheme that broke
				// that cannot make one value silently replace another.
				return nil, fmt.Errorf("%w: lease Secret key %q would carry two values", executor.ErrInvalidSpec, k)
			}
			if v == nil {
				// encoding/json renders a nil []byte as null; an empty
				// file or variable is a present, empty key.
				v = []byte{}
			}
			data[k] = v
			total += len(v)
		}
	}
	if total > maxLeaseSecretBytes {
		return nil, fmt.Errorf("%w: this run's credential files and environment total %d bytes, more "+
			"than the %d a Kubernetes Secret can hold", executor.ErrInvalidSpec, total, maxLeaseSecretBytes)
	}
	return data, nil
}

// secretFileData renders the file half of the Secret's data map: one entry per
// file, keyed by the plan.
//
// []byte and not a string, so content that is not valid UTF-8 survives the trip
// intact; encoding/json base64-encodes it, which is exactly the `data` field's
// wire format.
func secretFileData(files []executor.SecretFile) (map[string][]byte, error) {
	plan, err := planSecretFiles(files)
	if err != nil || plan == nil {
		return nil, err
	}
	data := make(map[string][]byte, len(files))
	for i, f := range files {
		data[plan.keys[i]] = f.Content
	}
	return data, nil
}

// secretFileVolumes renders the volume and volumeMount pair per lease
// directory, mapping the prefixed keys back to the bare file names.
//
// Read-only is not decoration. A credential helper the workload could rewrite is
// a credential helper that answers for every repository, which would undo the
// one enforcement point a repository-scoped GitHub PAT has: the workload asks
// git for a token and gets one scoped to the repositories the grant named, and
// a writable helper script would let it answer for the ones the grant excluded.
func secretFileVolumes(secretName string, files []executor.SecretFile) ([]volume, []volumeMount, error) {
	plan, err := planSecretFiles(files)
	if err != nil || plan == nil {
		return nil, nil, err
	}
	name := strings.TrimSpace(secretName)
	if name == "" {
		// The bytes exist and there is nowhere to read them from. Starting the
		// Pod anyway would produce the original bug — an environment pointing
		// at an empty directory — so this is fatal, and it is a spec error
		// because the caller built a request that cannot be honoured.
		return nil, nil, fmt.Errorf("%w: %d secret lease file(s) to deliver but no Secret to project them from",
			executor.ErrInvalidSpec, len(files))
	}
	if err := validateDNSSubdomain(name, "secret lease secret"); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", executor.ErrInvalidSpec, err)
	}

	mode := secretFileMode
	vols := make([]volume, len(plan.dirs))
	mounts := make([]volumeMount, len(plan.dirs))
	for i, dir := range plan.dirs {
		vols[i] = volume{
			Name: secretFileVolumeName(i),
			Secret: &secretSource{
				SecretName:  name,
				DefaultMode: &mode,
				Optional:    boolPtr(false),
			},
		}
		mounts[i] = volumeMount{
			Name:      secretFileVolumeName(i),
			MountPath: dir,
			ReadOnly:  true,
		}
	}
	// Items are added per file rather than per directory above, because a file
	// belongs to exactly one volume and the plan is what says which.
	for i, f := range files {
		d := plan.dirIndex[i]
		item := keyToPath{
			Key: plan.keys[i],
			// The bare name, which is what the workload's environment points
			// at. Everything the prefix bought is unwound here.
			Path: strings.TrimSpace(f.Name),
		}
		if f.FileMode()&0o111 != 0 {
			// A file the lease asked to be executable is one something runs by
			// path, and the volume's 0400 would leave it unrunnable.
			exec := secretExecFileMode
			item.Mode = &exec
		}
		vols[d].Secret.Items = append(vols[d].Secret.Items, item)
	}
	return vols, mounts, nil
}

// provisionLeaseSecret prepares the per-run Secret that carries a lease's
// credential files and the workload's environment into the Pod.
//
// It returns nil state and nil error when the Spec carries neither, which is a
// run that leases nothing and sets no environment. A non-nil state means there
// is something to clean up, whether or not the create succeeded.
//
// As with the workspace Secret the object is built here and created by the
// returned pendingSecret, once the Pod that will own it exists. See the
// ownerReference note in pod.go for why the create cannot come first.
func (e *Executor) provisionLeaseSecret(ctx context.Context, spec executor.Spec, cli *client,
	handleID, namespace string) (*leaseSecretState, *pendingSecret, error) {

	data, err := leaseSecretData(spec.SecretFiles, spec.Env)
	if err != nil || len(data) == 0 {
		return nil, nil, err
	}
	plan, err := planSecretFiles(spec.SecretFiles)
	if err != nil {
		return nil, nil, err
	}
	keys := make(map[string]string, len(spec.SecretFiles))
	for i, f := range spec.SecretFiles {
		keys[f.Path()] = plan.keys[i]
	}

	name := leaseSecretName(handleID)
	obj := &secret{
		APIVersion: "v1",
		Kind:       "Secret",
		Metadata: objectMeta{
			Name:      name,
			Namespace: namespace,
			// The same labels the Pod and the workspace Secret carry, so one
			// selector finds everything a run left in the namespace — including
			// the task-id the sweep requires to exist.
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
		Data: data,
	}

	st := &leaseSecretState{namespace: namespace, keys: keys}

	create := func(ctx context.Context, owner ownerReference, owned bool) error {
		if owned {
			obj.Metadata.OwnerReferences = []ownerReference{owner}
		}

		createCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), requestTimeout)
		defer cancel()
		if _, err := cli.createSecret(createCtx, namespace, obj); err != nil {
			// A create that failed may still have landed, and the same reasoning
			// provisionWorkspace uses applies: a 4xx is the API server stating it
			// did not, so arming the delete would only produce a second confusing
			// 403 in the log; anything else leaves the question open, and an
			// orphaned Secret holding live credential files is much worse than a
			// delete for an object that was never created, which the API server
			// answers 404 and this driver treats as success.
			//
			// As with the workspace Secret, the ownerReference is the backstop
			// that makes a Secret which landed unseen reap with its Pod anyway.
			if ae, ok := asAPIError(err); !ok || ae.Code >= 500 {
				st.mu.Lock()
				st.secretName = name
				st.mu.Unlock()
			}
			return explainLeaseSecretFailure(namespace, name, err)
		}

		st.mu.Lock()
		st.secretName = name
		st.mu.Unlock()
		return nil
	}
	return st, &pendingSecret{create: create}, nil
}

// discardLeaseSecret deletes the lease Secret. It is safe to call with a nil
// state, with a state whose create failed, and repeatedly — every cleanup path
// calls it without first checking which of those it is looking at.
//
// Callers decide *whether* it may go; see finish for why that is not always
// the moment the hub stops following the run.
//
// Failure goes to stderr and is not propagated, for the reason
// discardWorkspaceSecret's does: by the time this runs the caller is either
// returning an error it already has or finishing a workload whose result is
// collected, and replacing either with "could not delete a Secret" would lose
// what the operator actually needs to know.
func (e *Executor) discardLeaseSecret(st *leaseSecretState, cli *client) {
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

	if name == "" || already || cli == nil {
		return
	}

	// Detached from any caller's context: this is cleanup that must happen even
	// when the request that triggered it has been cancelled.
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := cli.deleteSecret(ctx, namespace, name); err != nil {
		fmt.Fprintf(os.Stderr, "kubernetes: could not delete lease secret %s/%s: %v — "+
			"delete it by hand; it holds brokered credentials\n", namespace, name, err)
	}
}

// leaveLeaseSecret is what finish does instead of discardLeaseSecret when the
// hub stops following a run whose harness container has not started: the
// kubelet resolves the harness's environment from this Secret when it creates
// the container, so deleting it now would hold the harness in
// CreateContainerConfigError for good. The ownerReference reaps it with its
// Pod, and a hub that adopts the run finds it still startable.
func leaveLeaseSecret(st *leaseSecretState, podName string) {
	if st == nil {
		return
	}
	st.mu.Lock()
	name, namespace, deleted := st.secretName, st.namespace, st.deleted
	st.mu.Unlock()
	if name == "" || deleted {
		return
	}
	fmt.Fprintf(os.Stderr, "kubernetes: leaving lease secret %s/%s in place: the harness container "+
		"of pod %s has not started, and its environment is read from it; it is deleted with the Pod\n",
		namespace, name, podName)
}

// explainLeaseSecretFailure turns a rejected Secret create into an actionable
// error.
//
// A sibling of explainSecretFailure rather than a branch inside it: that one
// speaks in terms of a git workspace and wraps ErrWorkspaceUnavailable, and an
// operator whose lease delivery failed would be sent to look at a workspace they
// did not configure. The RBAC remedy is the same rule, which is worth saying
// explicitly — an operator who already added it for workspaces needs to add
// nothing.
func explainLeaseSecretFailure(namespace, name string, err error) error {
	ae, ok := asAPIError(err)
	if !ok {
		return fmt.Errorf("kubernetes: deliver the run's credentials and environment as %s/%s: %w", namespace, name, err)
	}
	switch ae.Code {
	case http.StatusForbidden:
		return fmt.Errorf("kubernetes: not allowed to create Secrets in %q, which delivering a "+
			"workload's environment and a lease's credential files needs: %w — add this rule to the "+
			"executor's Role:\n%s\n%s",
			namespace, err, secretsRuleYAML(), secretsRuleRationale)
	case http.StatusConflict:
		// The name is derived from the handle ID, so a conflict means a Secret
		// from a previous run of this exact handle survived — which only happens
		// if a control plane died between creating it and deleting it.
		return fmt.Errorf("kubernetes: a lease Secret named %s already exists in %q, left "+
			"behind by an interrupted run: %w — delete it with `kubectl -n %s delete secret %s`",
			name, namespace, err, namespace, name)
	default:
		return fmt.Errorf("kubernetes: deliver the run's credentials and environment as %s/%s: %w", namespace, name, err)
	}
}
