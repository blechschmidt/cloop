package kubernetes

// projectresult.go carries a seeded run's project into its Pod and the run's
// outcome back out (Task 20402) — this driver's half of what
// pkg/executor/projectseed does for every executor that does not share the
// hub's filesystem.
//
// Until it existed a Kubernetes executor reported neither capability. A Pod
// fetched the project's repository and started `cloop run` in a tree with no
// `.cloop/`, so the run exited on its first line unless the project's state
// database had been committed to the repository; and even then the tasks the
// run finished were recorded only in the Pod's copy, which died with it, so the
// hub's plan never changed and the next Start ran them again.
//
// # In: the seed rides the lease Secret
//
// The seed is the project's control state — goal, instructions, provider and
// plan, typically tens of kilobytes compressed — and it reaches the Pod the way
// a lease's credential files do: as one more key of the per-run lease Secret
// (projectSeedKey), created after the Pod that owns it and reaped with it. A
// Secret volume projects that one key, read-only, into the workspace init
// container and nothing else, and `cloop workspace provision --seed` places it
// into the checkout once the fetch is done, exactly as the remote agent places
// it after its own (agent/session.go).
//
// The three channels that look simpler are each worse:
//
//   - argv and environment are readable by every identity with `get pods` in
//     the namespace, printed by every `kubectl describe` and written to the
//     API server's audit log; a project's instructions and plan are the
//     operator's, not the namespace's;
//   - a ConfigMap is the same object with none of the handling: not kept on
//     tmpfs by the kubelet, not encrypted at rest by the usual configuration,
//     and the executor's Role has no rule for configmaps at all, by design.
//
// A Secret holds at most 1 MiB, so a seed on this executor is capped tighter
// than projectseed's own 4 MiB: the Secret's whole data — credential files,
// environment and seed — must fit, and leaseSecretData refuses a run whose
// does not, naming the seed. A plan big enough to reach it has hundreds of
// finished tasks in it; archiving them shrinks the seed.
//
// The init container also leaves a copy of the seed in a small emptyDir it
// alone may write (dispatchVolume), mounted read-only in the harness container.
// It is what the wrapper measures the run's changes against afterwards; the
// Secret volume itself never reaches the harness.
//
// A placed `.cloop/` is excluded from the tree's commits (HideControlDir), so a
// push write-back's `git add --all` cannot carry the project's state database
// onto the cloop/ branch. A seed supersedes a `.cloop/` the repository commits:
// the database there is removed from the working tree before the seed is
// written, so the run sees the hub's project rather than the repository's copy.
//
// # Out: a frame at the end of the log
//
// A Pod's only channel home is its log stream (writeback.go). The harness is
// wrapped in `cloop workspace writeback --seed … --project-result-frame <handle>`,
// which, once the harness has exited, reads back what the run changed in its
// copy (projectseed.Harvest) and prints it as a pkg/executor/resultframe block,
// after everything else including the write-back's report. The log pump hands
// every chunk to the record's frame scanner before the bus: the frame's lines
// are lifted out — they never reach the live log or the run's artifact — and
// the rest is forwarded untouched. ProjectResult hands the frame to the hub
// once, when the run has ended.
//
// The workload shares that stream. What it can do with that is bounded the way
// a device's project_result frame is: a payload over
// executor.MaxProjectResultBytes (or a reason over
// executor.MaxProjectResultErrBytes) is refused on its declaration, a frame
// that is truncated, interleaved with another, duplicated or not framed at all
// yields executor.ErrProjectResultUnavailable and no bytes, and a forged frame
// is always followed by the wrapper's real one, which makes the pair a
// duplicate. The content of a result is the workload's to shape on every
// transport — a device reads it out of the database the workload wrote — and
// the hub's merge treats it accordingly (projectseed.Merge).
//
// # Memory
//
// A result is held from the moment the Pod's log ends until the hub collects
// it, which for a run is the same instant: runEnded settles it straight after
// the stream closes. What may wait is a result nobody collects — a helper
// subcommand's, whose outcome the hub never merges — and those are bounded:
// past maxHeldProjectResultBytes per executor the oldest uncollected result is
// dropped, saying so to a collector that turns up after all.

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/resultframe"
)

const (
	// projectSeedKey is the lease Secret key that carries the compressed seed.
	// It cannot collide with a credential file's key (d<N>.<name>) or a
	// variable's (env.<NAME>).
	projectSeedKey = "project-seed"

	// seedVolume projects projectSeedKey into the workspace init container,
	// read-only, at seedMountDir/seedFileName.
	seedVolume   = "cloop-seed"
	seedMountDir = "/run/cloop/seed"
	seedFileName = "seed.gz"

	// dispatchVolume is where the init container leaves its copy of the seed
	// for the harness's wrapper: an emptyDir the init container writes and the
	// harness container mounts read-only.
	dispatchVolume   = "cloop-dispatch"
	dispatchMountDir = "/run/cloop/dispatch"
	// dispatchSizeLimit bounds it. The seed it holds fits in a Secret, so it is
	// under 1 MiB; the kubelet evicts a Pod whose emptyDir outgrows its limit,
	// which is the right answer to something writing there that should not.
	dispatchSizeLimit = "2Mi"

	// maxHeldProjectResultBytes bounds the project results one executor holds
	// for collection: fifty-one of the largest a frame may carry.
	maxHeldProjectResultBytes = 32 << 20
)

// checkSeedDelivery refuses a request whose seed has no way into the Pod.
func checkSeedDelivery(req podRequest) error {
	switch {
	case !req.Workspace.NeedsProvisioning():
		// A tree that is not fetched has no init container, and the init
		// container is what places the seed. "none" means an intentionally
		// empty tree, and a project seed for one is a caller's mistake.
		return fmt.Errorf("%w: a project seed is placed by the workspace init container after it "+
			"fetches the tree, and workspace kind %q fetches nothing", executor.ErrInvalidSpec, req.Workspace.Kind)
	case strings.TrimSpace(req.LeaseSecretName) == "":
		return fmt.Errorf("%w: a project seed to deliver but no lease Secret to carry it", executor.ErrInvalidSpec)
	case !resultframe.ValidTag(req.HandleID):
		return fmt.Errorf("%w: handle ID %q cannot tag the run's project result frame",
			executor.ErrInvalidSpec, req.HandleID)
	}
	if err := validateDNSSubdomain(strings.TrimSpace(req.LeaseSecretName), "secret lease secret"); err != nil {
		return fmt.Errorf("%w: %v", executor.ErrInvalidSpec, err)
	}
	return nil
}

// seedVolumes renders the seed's Secret volume and the dispatch emptyDir.
func seedVolumes(secretName string) []volume {
	mode := secretFileMode
	return []volume{
		{
			Name: seedVolume,
			Secret: &secretSource{
				SecretName: strings.TrimSpace(secretName),
				// Only the seed: the volume must not project the lease's
				// credential files or its environment into the init
				// container, which has no use for either.
				Items:       []keyToPath{{Key: projectSeedKey, Path: seedFileName}},
				DefaultMode: &mode,
				// A missing seed holds the Pod rather than starting a fetch
				// that ends in a workspace with no project.
				Optional: boolPtr(false),
			},
		},
		{Name: dispatchVolume, EmptyDir: &emptyDirSource{SizeLimit: dispatchSizeLimit}},
	}
}

// projectResultFlags are the wrapper flags that read a seeded run back and
// print it as the log's last block, tagged with the handle so a frame bearing
// any other tag is transcript.
func projectResultFlags(req podRequest) []string {
	return []string{
		"--seed", dispatchMountDir + "/" + seedFileName,
		"--project-result-frame", req.HandleID,
	}
}

// heldResults accounts the project results an executor holds for collection,
// oldest first. Guarded by Executor.mu.
type heldResults struct {
	order []string
	size  map[string]int
	total int
}

// holdLocked records that the handle id holds n bytes, then drops the oldest
// uncollected results until the executor is back under its bound. The newest
// result — the one just arrived, about to be collected — is never the one
// dropped. e.mu is held.
func (h *heldResults) holdLocked(e *Executor, id string, n int) {
	if h.size == nil {
		h.size = make(map[string]int)
	}
	if _, ok := h.size[id]; ok {
		return
	}
	h.size[id] = n
	h.order = append(h.order, id)
	h.total += n
	for h.total > maxHeldProjectResultBytes && len(h.order) > 1 {
		victim := h.order[0]
		if rec, ok := e.handles[victim]; ok && rec.result != nil {
			rec.result.Drop(fmt.Sprintf("executor %s let it go uncollected to make room for newer "+
				"results (it holds at most %d bytes of them)", e.id, maxHeldProjectResultBytes))
		}
		h.releaseLocked(victim)
	}
}

// releaseLocked forgets the handle id's held result. e.mu is held.
func (h *heldResults) releaseLocked(id string) {
	n, ok := h.size[id]
	if !ok {
		return
	}
	delete(h.size, id)
	h.total -= n
	for i, v := range h.order {
		if v == id {
			h.order = append(h.order[:i], h.order[i+1:]...)
			break
		}
	}
}

// newResultScanner returns the frame scanner for a seeded run, nil for any
// other: an unseeded run was given no project to read back, and a frame in its
// log is somebody's text.
func newResultScanner(seeded bool, handleID string) (*resultframe.Scanner, error) {
	if !seeded {
		return nil, nil
	}
	s, err := resultframe.NewScanner(handleID)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: %w", err)
	}
	return s, nil
}

// settleProjectResult closes a seeded run's frame scanner once the Pod's log
// has ended, says in the log what came back, and starts holding the result for
// collection. It runs before finish, so the result is final by the time the
// stream closes and the hub asks for it.
func (e *Executor) settleProjectResult(rec *record) {
	if rec.result == nil {
		return
	}
	if rest := rec.result.Close(); rest != "" {
		rec.bus.Emit(rest)
	}
	frame, err := rec.result.Result()
	switch {
	case err != nil:
		rec.bus.Emit(fmt.Sprintf("[cloop] no project result came back from pod %s/%s: %v\n",
			rec.namespace, rec.podName, err))
		return
	case frame.Kind == resultframe.KindError:
		rec.bus.Emit(fmt.Sprintf("[cloop] pod %s/%s could not read the run's project state back: %s\n",
			rec.namespace, rec.podName, firstLine(string(frame.Payload))))
	default:
		rec.bus.Emit(fmt.Sprintf("[cloop] read the run's project state back from pod %s/%s (%d bytes)\n",
			rec.namespace, rec.podName, len(frame.Payload)))
	}
	e.mu.Lock()
	e.held.holdLocked(e, rec.id, len(frame.Payload))
	e.mu.Unlock()
}

// ProjectResult implements executor.ProjectResultFetcher.
//
// Released once: the bytes go to the caller and are dropped here, because a
// second merge of the same run would book its spend twice. Every way a Pod can
// fail to report — it was not seeded, it has not finished, its frame was cut
// off or forged or never printed — is executor.ErrProjectResultUnavailable,
// with the reason, and never part of a result.
func (e *Executor) ProjectResult(handleID string) (executor.ProjectResult, error) {
	rec, err := e.lookup(handleID)
	if err != nil {
		return executor.ProjectResult{}, err
	}
	if rec.result == nil {
		return executor.ProjectResult{}, fmt.Errorf("%w: handle %s on executor %s was dispatched with no "+
			"project seed, so it has no project state to return", executor.ErrProjectResultUnavailable, handleID, e.id)
	}
	if !rec.finished() {
		return executor.ProjectResult{}, fmt.Errorf("%w: pod %s/%s has not finished, so its log does not yet "+
			"hold the run's project state", executor.ErrProjectResultUnavailable, rec.namespace, rec.podName)
	}
	frame, err := rec.result.Take()
	e.mu.Lock()
	e.held.releaseLocked(rec.id)
	e.mu.Unlock()
	if err != nil {
		// Redacted: a refusal can quote a line of the Pod's log, which the
		// workload wrote, and this text ends up in the project's journal
		// rather than in the scrubbed live log.
		return executor.ProjectResult{}, fmt.Errorf("%w: pod %s/%s: %s", executor.ErrProjectResultUnavailable,
			rec.namespace, rec.podName, rec.bus.Redactor().String(err.Error()))
	}
	res := executor.ProjectResult{
		// The set in force on the handle's log bus when the hub reads the
		// result, which includes a credential refreshed while the run went on
		// (AddRedactions) — the same set that scrubbed the live log. An
		// adopted record's bus has none, which is no worse than its log.
		Redact: func(s string) string { return rec.bus.Redactor().String(s) },
	}
	switch frame.Kind {
	case resultframe.KindError:
		res.Err = strings.ToValidUTF8(string(frame.Payload), "�")
	default:
		res.Data = frame.Payload
	}
	return res, nil
}

var _ executor.ProjectResultFetcher = (*Executor)(nil)
