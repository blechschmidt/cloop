package kubecontroller

// storage.go: runner volumes (Task 20484).
//
// A pool with spec.persistence keeps up to maxClaims PersistentVolumeClaims,
// <pool>-storage-<n>, created as runners need them and kept between runners —
// a project's workspace, a git object cache, tool caches — so the next run of
// the same project fetches instead of cloning and builds warm. Four rules hold
// whatever else happens:
//
//  1. A claim is mounted by one runner Pod at a time. The controller claims a
//     volume before it creates the Pod that mounts it, by writing the Pod's
//     name into the claim's cloop.dev/claimed-by annotation with a merge patch
//     guarded by the resourceVersion it read — so of two reconcilers that both
//     saw the volume free, the API server lets one write and answers the other
//     409 — and releases it only once that Pod has terminated or is gone. A
//     claim whose Pod is not there is released only after claimGrace, past
//     the longest a claim can precede the Pod's creation.
//  2. A volume records whose data it holds: cloop.dev/holds, the tenant the
//     hub named (executorpool.ProjectTenant — the hub pool, the project and its
//     owner), "unknown" from the moment a runner that may write anybody's data
//     holds it until the hub says whose run that runner took. A volume is
//     handed back unwiped only to a runner the controller minted as holding
//     that tenant, which the hub hands only that tenant's runs — when its
//     starter may read the project — and which itself refuses a start naming
//     another tenant, or none (--holds). Every other runner gets a volume its
//     init container wipes before the runner starts, or a fresh one.
//  3. Nothing that is a credential is written to a volume: payload homes,
//     leased files and the runner's own HOME are on a memory-backed emptyDir
//     (runner.go), and the agent refuses a layout that would put them there.
//  4. Storage trouble is reported, not retried in a loop: a runner whose
//     volume cannot be bound or whose Pod cannot be scheduled with it, a volume
//     still full after its init container cleared it, an init container that
//     failed — each marks the volume, deletes the runner, says so in a Degraded
//     condition, an Event and the hub's queue, and leaves the volume alone for
//     storageRetryAfter.
//
// Volumes past maxClaims, or all of them with persistence turned off, follow
// reclaimPolicy once free: Delete deletes them; Retain keeps them, with their
// record, and the pool takes them up again if it grows back. Under Delete a
// volume is owned by its ExecutorPool, so the garbage collector deletes it with
// the pool; under Retain it is not, and outlives the pool.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// What the controller writes on a runner volume and on the Pod that holds it.
const (
	// RunnerStorageName is the name label of a runner volume.
	RunnerStorageName = "cloop-runner-storage"
	// AnnotationStoragePool names the volume's ExecutorPool, in full.
	AnnotationStoragePool = "cloop.dev/executor-pool"
	// AnnotationClaimedBy is the runner Pod holding the volume, "" or absent
	// when it is free; AnnotationClaimedAt is when it was claimed.
	AnnotationClaimedBy = "cloop.dev/claimed-by"
	AnnotationClaimedAt = "cloop.dev/claimed-at"
	// AnnotationHolds is the tenant whose data the volume holds, or
	// holdsUnknown; AnnotationHubPool is the hub pool that tenant is of.
	// LabelProject repeats a tenant as a label, so an operator can select a
	// project's volumes; absent while the volume holds nobody's known data.
	AnnotationHolds   = "cloop.dev/holds"
	LabelProject      = "cloop.dev/project"
	AnnotationHubPool = "cloop.dev/hub-pool"
	// AnnotationProjectName and AnnotationProjectOwner name the project, for
	// people; they decide nothing.
	AnnotationProjectName  = "cloop.dev/project-name"
	AnnotationProjectOwner = "cloop.dev/project-owner"
	// The volume's last measurement, by the runner that last used it or by
	// its init container.
	AnnotationUsedBytes     = "cloop.dev/used-bytes"
	AnnotationCapacityBytes = "cloop.dev/capacity-bytes"
	AnnotationMeasuredAt    = "cloop.dev/measured-at"
	// AnnotationReleasedAt is when the volume was last released.
	AnnotationReleasedAt = "cloop.dev/released-at"
	// AnnotationProblem is when a runner could not start on the volume, and
	// AnnotationProblemReason why; AnnotationFull is when the volume was found
	// under minFree after clearing.
	AnnotationProblem       = "cloop.dev/storage-problem"
	AnnotationProblemReason = "cloop.dev/storage-problem-reason"
	AnnotationFull          = "cloop.dev/storage-full"
	// AnnotationFailures counts the runners that could not start on the
	// volume: one that failed maxVolumeFailures times is deleted under
	// reclaimPolicy Delete, and left unused under Retain.
	AnnotationFailures = "cloop.dev/storage-failures"
	// On the runner Pod: the claim it mounts, the tenant it was minted as
	// holding, and whether its init container wipes the volume.
	AnnotationPodClaim = "cloop.dev/storage-claim"
	AnnotationPodHolds = "cloop.dev/storage-holds"
	AnnotationPodWipe  = "cloop.dev/storage-wipe"

	// holdsUnknown is a volume a runner that may have written anybody's data
	// held, before the hub said whose: it is wiped before it is used again.
	holdsUnknown = "unknown"
)

// Storage timing.
var (
	// claimGrace is how long a claim whose Pod does not exist is held,
	// counted from when this replica first saw the claim — never from a time
	// another replica wrote, whose clock is not this one's. The controller
	// claims a volume, then creates the Pod within claimCreateTimeout; a
	// create the client gave up on may still land until the API server's own
	// request timeout (a minute by default) runs out. A claim younger than
	// both may be one whose Pod is still on its way.
	claimGrace = 3 * time.Minute
	// claimCreateTimeout bounds the Pod create that follows a claim.
	claimCreateTimeout = 20 * time.Second
	// storagePendingTimeout is how long a runner Pod may wait to be scheduled
	// with its volume before the volume is taken for stuck.
	storagePendingTimeout = 3 * time.Minute
	// storageRetryAfter is how long a volume that failed is left alone.
	storageRetryAfter = 10 * time.Minute
	// storageReportRefresh repeats a report of trouble to the hub, within the
	// ten minutes the hub lets one speak for the pool.
	storageReportRefresh = 4 * time.Minute
)

// More condition and Event reasons.
const (
	ReasonStoragePending       = "StoragePending"
	ReasonStorageFull          = "StorageFull"
	ReasonStoragePrepareFailed = "StoragePrepareFailed"
	ReasonStorageUnavailable   = "StorageUnavailable"
	ReasonStorageUnsupported   = "StorageUnsupported"
	ReasonVolumeCreated        = "VolumeCreated"
	ReasonVolumeDeleted        = "VolumeDeleted"
	ReasonVolumeRetained       = "VolumeRetained"
	// ReasonStorageConflict is a runner the hub said it handed another
	// project's run than the one its volume holds.
	ReasonStorageConflict = "StorageConflict"
	// ReasonVolumeUnusable is a volume Lost, or given up on, that the pool
	// keeps under reclaimPolicy Retain: runners start on the others.
	ReasonVolumeUnusable = "VolumeUnusable"
)

// maxVolumeFailures is how many runners may fail to start on a volume before
// it is given up on.
const maxVolumeFailures = 3

// claimName is the name of pool's volume ordinal: <pool>-storage-<n>, the
// pool's name cut and suffixed with its digest when it is too long to fit.
func claimName(pool *ExecutorPool, ordinal int) string {
	base := pool.Metadata.Name
	if len(base) > 220 {
		sum := sha256.Sum256([]byte(base))
		base = strings.TrimRight(base[:210], "-.") + "-" + hex.EncodeToString(sum[:4])
	}
	return base + "-storage-" + strconv.Itoa(ordinal)
}

// ordinalOf returns the ordinal of pool's volume name, or false.
func ordinalOf(pool *ExecutorPool, name string) (int, bool) {
	prefix := strings.TrimSuffix(claimName(pool, 0), "0")
	rest, ok := strings.CutPrefix(name, prefix)
	if !ok || rest == "" || (len(rest) > 1 && rest[0] == '0') {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 0 || n >= maxClaimsCeiling {
		return 0, false
	}
	return n, true
}

// volumeView is one runner volume as a pass sees it.
type volumeView struct {
	claim                    *PersistentVolumeClaim
	ordinal                  int
	claimedBy                string
	claimedAt                time.Time
	holds                    string
	hubPool                  string
	usedBytes, capacityBytes int64
	releasedAt               time.Time
	problemAt                time.Time
	problemReason            string
	fullAt                   time.Time
	failures                 int
}

// givenUp reports whether too many runners failed on the volume to try it
// again.
func (v *volumeView) givenUp() bool { return v.failures >= maxVolumeFailures }

func (v *volumeView) name() string { return v.claim.Metadata.Name }

// free reports whether no Pod holds the volume and it is not being deleted.
func (v *volumeView) free() bool {
	return v.claimedBy == "" && v.claim.Metadata.DeletionTimestamp == ""
}

// troubled reports whether the volume failed within storageRetryAfter.
func (v *volumeView) troubled(now time.Time) bool {
	return (!v.problemAt.IsZero() && now.Sub(v.problemAt) < storageRetryAfter) ||
		(!v.fullAt.IsZero() && now.Sub(v.fullAt) < storageRetryAfter)
}

// holdsFor reports whether the volume holds tenant's data for hub pool poolID.
func (v *volumeView) holdsFor(tenant, poolID string) bool {
	return tenant != "" && executorpool.ValidTenant(tenant) && v.holds == tenant && v.hubPool == poolID
}

func viewOfClaim(c *PersistentVolumeClaim, ordinal int) *volumeView {
	a := c.Metadata.Annotations
	v := &volumeView{claim: c, ordinal: ordinal, claimedBy: a[AnnotationClaimedBy], holds: a[AnnotationHolds],
		hubPool: a[AnnotationHubPool], problemReason: a[AnnotationProblemReason]}
	v.claimedAt = parseTime(a[AnnotationClaimedAt], time.Time{})
	v.releasedAt = parseTime(a[AnnotationReleasedAt], time.Time{})
	v.problemAt = parseTime(a[AnnotationProblem], time.Time{})
	v.fullAt = parseTime(a[AnnotationFull], time.Time{})
	v.usedBytes, _ = strconv.ParseInt(a[AnnotationUsedBytes], 10, 64)
	v.capacityBytes, _ = strconv.ParseInt(a[AnnotationCapacityBytes], 10, 64)
	v.failures, _ = strconv.Atoi(a[AnnotationFailures])
	return v
}

// volumesOf lists pool's volumes: claims in its namespace named for one of its
// ordinals and recording it as their pool.
func (c *Controller) volumesOf(pool *ExecutorPool) []*volumeView {
	var out []*volumeView
	for _, cl := range c.claims.list() {
		if cl.Metadata.Namespace != pool.Metadata.Namespace || cl.Metadata.Annotations[AnnotationStoragePool] != pool.Metadata.Name {
			continue
		}
		n, ok := ordinalOf(pool, cl.Metadata.Name)
		if !ok {
			continue
		}
		out = append(out, viewOfClaim(cl, n))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ordinal < out[j].ordinal })
	return out
}

// ── settling: releases, measurements, stuck runners ─────────────────────────

// storageReport is what a runner Pod said about its volume as it ended.
type storageReport struct {
	used, capacity int64
	full           bool
	prepareFailed  string
	// startFailed is a runner whose one run never started — refused by its
	// workspace, say.
	startFailed bool
}

// podStorageReport reads a terminated runner Pod's reports: its init
// container's PrepareReport and its runner's RetirementReport.
func podStorageReport(p *Pod) storageReport {
	var r storageReport
	for _, cs := range p.Status.InitContainerStatuses {
		if cs.Name != storageInitContainer || cs.State.Terminated == nil {
			continue
		}
		t := cs.State.Terminated
		var rep PrepareReport
		if json.Unmarshal([]byte(strings.TrimSpace(t.Message)), &rep) == nil && rep.CapacityBytes > 0 {
			r.used, r.capacity = rep.UsedBytes, rep.CapacityBytes
			r.full = rep.Full
		}
		if t.ExitCode != 0 && !r.full {
			msg := strings.TrimSpace(rep.Error)
			if msg == "" {
				msg = firstLine(t.Message)
			}
			if msg == "" {
				msg = fmt.Sprintf("exit %d (%s)", t.ExitCode, t.Reason)
			}
			r.prepareFailed = msg
		}
	}
	for _, cs := range p.Status.ContainerStatuses {
		if cs.Name != runnerContainer || cs.State.Terminated == nil {
			continue
		}
		// The agent's RetirementReport, as much of it as says how full its
		// workspace volume was as it left.
		var rep struct {
			Storage *struct {
				CapacityBytes int64 `json:"capacity_bytes"`
				UsedBytes     int64 `json:"used_bytes"`
			} `json:"storage"`
			StartFailed string `json:"start_failed"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(cs.State.Terminated.Message)), &rep) != nil {
			continue
		}
		if rep.Storage != nil && rep.Storage.CapacityBytes > 0 {
			r.used, r.capacity = rep.Storage.UsedBytes, rep.Storage.CapacityBytes
		}
		// Trusted in one direction only: a run that forged it costs a wipe.
		r.startFailed = rep.StartFailed != ""
	}
	return r
}

// settleVolumes releases the claims of runner Pods that are done — reading
// what each said about its volume — and returns the runner Pods stuck waiting
// on their volume, which the caller deletes. It runs before finished Pods are
// collected, while their status is still in the cache.
func (c *Controller) settleVolumes(ctx context.Context, pool *ExecutorPool, vols []*volumeView, views []*runnerView,
	created map[string]bool, st *passState, now time.Time, res *result) []*runnerView {
	byName := map[string]*runnerView{}
	for _, v := range views {
		byName[v.pod.Metadata.Name] = v
	}
	var stuck []*runnerView
	for _, vol := range vols {
		if vol.claimedBy == "" {
			continue
		}
		rv := byName[vol.claimedBy]
		switch {
		case rv != nil && (rv.pod.Status.Phase == PodSucceeded || rv.pod.Status.Phase == PodFailed):
			rep := podStorageReport(rv.pod)
			c.releaseVolume(ctx, pool, vol, &rep, now)
		case rv != nil:
			if why, ok := stuckOnVolume(rv.pod, vol, now); ok {
				c.markVolume(ctx, pool, vol, why, now)
				c.logf("runner Pod %s/%s waited %s for its volume %s: %s", pool.Metadata.Namespace,
					rv.pod.Metadata.Name, storagePendingTimeout, vol.name(), why)
				stuck = append(stuck, rv)
				vol.problemAt, vol.problemReason = now, why
			} else if neverStarted(rv.pod) {
				res.sooner(storagePendingTimeout)
			}
		case created[vol.claimedBy]:
			// This leader created it a moment ago; the cache has not caught up.
		case now.Sub(c.claimSeen(vol, now)) < claimGrace:
			res.sooner(claimGrace - now.Sub(c.claimSeen(vol, now)))
		default:
			// No Pod of this pool by that name in the cache, and the claim is
			// older than any create could be: the API server has the last word.
			if _, err := c.api.getPod(ctx, pool.Metadata.Namespace, vol.claimedBy); kubernetes.IsNotFound(err) {
				c.releaseVolume(ctx, pool, vol, nil, now)
			}
		}
	}
	return stuck
}

// stuckOnVolume reports whether a runner Pod that never started has waited
// past storagePendingTimeout for a node with its volume — the claim unbound,
// or the scheduler unable to place it with it — and why.
func stuckOnVolume(p *Pod, vol *volumeView, now time.Time) (string, bool) {
	if !neverStarted(p) || p.Metadata.DeletionTimestamp != "" {
		return "", false
	}
	if now.Sub(parseTime(p.Metadata.CreationTimestamp, now)) < storagePendingTimeout {
		return "", false
	}
	sched := ""
	for _, cond := range p.Status.Conditions {
		if cond.Type == "PodScheduled" && cond.Status == ConditionFalse {
			sched = strings.TrimSpace(cond.Reason + ": " + cond.Message)
		}
	}
	// Only when the scheduler says it is the volume: a claim of a class
	// that binds on first use is Pending as long as its Pod has no node, and
	// a Pod with no node for want of CPU, or waiting for an autoscaler, is
	// the cluster's matter, not the volume's — that runner waits like any.
	if sched == "" || !volumeScheduling(sched) {
		return "", false
	}
	if vol.claim.Status.Phase == ClaimPending {
		return fmt.Sprintf("volume %s has been Pending for %s (%s)", vol.name(), storagePendingTimeout, sched), true
	}
	return fmt.Sprintf("runner Pod %s could not be scheduled with volume %s for %s: %s", p.Metadata.Name,
		vol.name(), storagePendingTimeout, sched), true
}

// volumeScheduling reports whether a scheduler's message is about a Pod's
// volumes: an unbound claim, a volume node affinity conflict, no persistent
// volume to bind.
func volumeScheduling(msg string) bool {
	m := strings.ToLower(msg)
	for _, s := range []string{"persistentvolumeclaim", "volume node affinity", "persistent volume", "volume binding",
		"volumebinding", "unbound", "pvc", "storageclass"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

// releaseVolume frees a claim, recording what its runner said.
func (c *Controller) releaseVolume(ctx context.Context, pool *ExecutorPool, vol *volumeView, rep *storageReport,
	now time.Time) {
	ann := map[string]*string{
		AnnotationClaimedBy:  nil,
		AnnotationClaimedAt:  nil,
		AnnotationReleasedAt: ptr(now.UTC().Format(time.RFC3339)),
	}
	if rep != nil {
		if rep.capacity > 0 {
			ann[AnnotationUsedBytes] = ptr(strconv.FormatInt(rep.used, 10))
			ann[AnnotationCapacityBytes] = ptr(strconv.FormatInt(rep.capacity, 10))
			ann[AnnotationMeasuredAt] = ptr(now.UTC().Format(time.RFC3339))
		}
		switch {
		case rep.full:
			ann[AnnotationFull] = ptr(now.UTC().Format(time.RFC3339))
			c.events.record(ctx, pool, EventWarning, ReasonStorageFull, fmt.Sprintf(
				"volume %s has %s free of %s after clearing it, under minFree; expand spec.persistence.size or "+
					"lower minFree", vol.name(), humanBytes(rep.capacity-rep.used), humanBytes(rep.capacity)))
		case rep.prepareFailed != "":
			ann[AnnotationProblem] = ptr(now.UTC().Format(time.RFC3339))
			ann[AnnotationProblemReason] = ptr(trimMessage("its init container failed: " + rep.prepareFailed))
			ann[AnnotationFailures] = ptr(strconv.Itoa(vol.failures + 1))
			c.events.record(ctx, pool, EventWarning, ReasonStoragePrepareFailed, fmt.Sprintf(
				"volume %s could not be prepared for a runner: %s", vol.name(), rep.prepareFailed))
		default:
			ann[AnnotationFull] = nil
			if rep.capacity > 0 && !rep.startFailed {
				// Its init container prepared it and its runner ran on it:
				// earlier failures are behind it.
				ann[AnnotationFailures] = nil
			}
		}
		if rep.startFailed && vol.holds != holdsUnknown && executorpool.ValidTenant(vol.holds) {
			// The runner's run did not start on what the volume kept — a run
			// can leave its own tree unusable — so the volume is wiped before
			// it is used again rather than handed back as it is.
			ann[AnnotationHolds] = ptr(holdsUnknown)
			ann[AnnotationProjectName], ann[AnnotationProjectOwner] = nil, nil
		}
	}
	var labels map[string]*string
	if h, ok := ann[AnnotationHolds]; ok && h != nil {
		labels = projectLabel(*h)
	}
	updated, err := c.api.patchClaimMeta(ctx, pool.Metadata.Namespace, vol.name(), vol.claim.Metadata.ResourceVersion,
		ann, labels, nil)
	if err != nil {
		if !kubernetes.IsConflict(err) && !kubernetes.IsNotFound(err) {
			c.logf("release volume %s/%s: %v", pool.Metadata.Namespace, vol.name(), err)
		}
		return
	}
	// The pass goes on with the version just written, so a volume released
	// here may be claimed in the same pass rather than meeting a 409.
	c.forgetClaimSeen(vol)
	*vol = *viewOfClaim(updated, vol.ordinal)
}

// markVolume records that a runner could not start on a volume, keeping its
// claim, and counts it.
func (c *Controller) markVolume(ctx context.Context, pool *ExecutorPool, vol *volumeView, why string, now time.Time) {
	ann := map[string]*string{
		AnnotationProblem:       ptr(now.UTC().Format(time.RFC3339)),
		AnnotationProblemReason: ptr(trimMessage(why)),
		AnnotationFailures:      ptr(strconv.Itoa(vol.failures + 1)),
	}
	updated, err := c.api.patchClaimMeta(ctx, vol.claim.Metadata.Namespace, vol.name(), vol.claim.Metadata.ResourceVersion,
		ann, nil, nil)
	switch {
	case err == nil:
		*vol = *viewOfClaim(updated, vol.ordinal)
	case !kubernetes.IsConflict(err) && !kubernetes.IsNotFound(err):
		c.logf("mark volume %s/%s: %v", vol.claim.Metadata.Namespace, vol.name(), err)
	}
	if vol.failures+1 >= maxVolumeFailures {
		c.events.record(ctx, pool, EventWarning, ReasonStorageUnavailable, fmt.Sprintf(
			"volume %s failed %d runners and is no longer used: %s", vol.name(), vol.failures+1, why))
	}
}

// recordProjects writes on each busy runner's volume the project the hub says
// it was handed — the hub telling the controller each runner's project at
// assignment. A volume that already records another tenant for the same
// claim is not upgraded to the new one: it becomes "unknown", and is wiped
// before it is used again.
func (c *Controller) recordProjects(ctx context.Context, pool *ExecutorPool, vols []*volumeView, live []*runnerView,
	snap *executorpool.Snapshot) {
	byName := map[string]*volumeView{}
	for _, v := range vols {
		byName[v.name()] = v
	}
	for _, rv := range live {
		if rv.hub == nil || rv.hub.State != statedb.PoolRunnerBusy {
			continue
		}
		vol := byName[rv.pod.Metadata.Annotations[AnnotationPodClaim]]
		if vol == nil || vol.claimedBy != rv.pod.Metadata.Name {
			continue
		}
		tenant := strings.TrimSpace(rv.hub.Project)
		ann := map[string]*string{}
		switch {
		case tenant == "" || !executorpool.ValidTenant(tenant):
			// The hub named no project for a run it handed this runner — a
			// member older than runner storage did, which checks nothing:
			// whose data the volume now holds is unknown.
			if vol.holds != holdsUnknown {
				ann[AnnotationHolds] = ptr(holdsUnknown)
				ann[AnnotationProjectName], ann[AnnotationProjectOwner] = nil, nil
			}
		case vol.holds == tenant && vol.hubPool == snap.PoolID:
			if vol.claim.Metadata.Annotations[AnnotationProjectName] == "" && rv.hub.ProjectName != "" {
				ann[AnnotationProjectName] = ptr(rv.hub.ProjectName)
				ann[AnnotationProjectOwner] = ptr(rv.hub.ProjectOwner)
			}
		case vol.holds == holdsUnknown && rv.pod.Metadata.Annotations[AnnotationPodHolds] == "":
			// Only a runner minted on a wiped or fresh volume makes "unknown"
			// its project's: one minted holding a tenant whose volume says
			// "unknown" was downgraded below, and stays so.
			ann[AnnotationHolds] = ptr(tenant)
			ann[AnnotationHubPool] = ptr(snap.PoolID)
			ann[AnnotationProjectName] = ptr(rv.hub.ProjectName)
			ann[AnnotationProjectOwner] = ptr(rv.hub.ProjectOwner)
		case vol.holds == holdsUnknown:
		default:
			msg := fmt.Sprintf("volume %s holds %s, and its runner %s was handed a run of %s; the volume will be "+
				"wiped before it is used again", vol.name(), vol.holds, rv.enrollmentID, tenant)
			c.logf("%s/%s: %s", pool.Metadata.Namespace, vol.name(), msg)
			c.events.record(ctx, pool, EventWarning, ReasonStorageConflict, msg)
			ann[AnnotationHolds] = ptr(holdsUnknown)
			ann[AnnotationProjectName] = nil
			ann[AnnotationProjectOwner] = nil
		}
		if len(ann) == 0 {
			continue
		}
		var labels map[string]*string
		if h, ok := ann[AnnotationHolds]; ok && h != nil {
			labels = projectLabel(*h)
		}
		updated, err := c.api.patchClaimMeta(ctx, pool.Metadata.Namespace, vol.name(), vol.claim.Metadata.ResourceVersion,
			ann, labels, nil)
		switch {
		case err == nil:
			fresh := viewOfClaim(updated, vol.ordinal)
			*vol = *fresh
		case !kubernetes.IsConflict(err) && !kubernetes.IsNotFound(err):
			c.logf("record the project on volume %s/%s: %v", pool.Metadata.Namespace, vol.name(), err)
		}
	}
}

// claimObservations remember when this replica first saw each claim held by
// its current holder: what claimGrace is measured from.
type claimObservations struct {
	mu   sync.Mutex
	seen map[string]claimObservation
}

type claimObservation struct {
	holder string
	at     time.Time
}

func newClaimObservations() *claimObservations {
	return &claimObservations{seen: map[string]claimObservation{}}
}

func claimKey(c *PersistentVolumeClaim) string { return c.Metadata.Namespace + "/" + c.Metadata.Name }

// claimSeen is when this replica first saw vol held by its current holder.
func (c *Controller) claimSeen(vol *volumeView, now time.Time) time.Time {
	c.claimObs.mu.Lock()
	defer c.claimObs.mu.Unlock()
	k := claimKey(vol.claim)
	if o, ok := c.claimObs.seen[k]; ok && o.holder == vol.claimedBy {
		return o.at
	}
	c.claimObs.seen[k] = claimObservation{holder: vol.claimedBy, at: now}
	return now
}

// noteClaimed records a claim this replica made, as of when it made it.
func (c *Controller) noteClaimed(namespace, name, holder string, at time.Time) {
	c.claimObs.mu.Lock()
	defer c.claimObs.mu.Unlock()
	c.claimObs.seen[namespace+"/"+name] = claimObservation{holder: holder, at: at}
}

// forgetClaimSeen drops what was seen of a claim now released.
func (c *Controller) forgetClaimSeen(vol *volumeView) {
	c.claimObs.mu.Lock()
	defer c.claimObs.mu.Unlock()
	delete(c.claimObs.seen, claimKey(vol.claim))
}

// ── planning ───────────────────────────────────────────────────────────────

// demandInput is what a pass knows of a pool's demand and runners.
type demandInput struct {
	minRunners, maxRunners int
	busy                   int
	// waiting are the tenants held by each live runner that holds no run —
	// idle, pending or starting — "" for one holding nothing.
	waiting []string
	// queued is the hub's demand by project, oldest first; demand all of it,
	// runs the hub could not name included.
	queued []executorpool.ProjectDemand
	demand int
}

// demandPlan is how many runners a pool needs, and for which tenants.
type demandPlan struct {
	desired int
	// start are the tenants the new runners should hold, one per runner to
	// start: a project whose runs no runner can take yet, or "" for a runner
	// holding nothing — demand a clean runner meets, and the idle target.
	start []string
	// excess is how many waiting runners are more than the demand and the
	// idle target need; stranded the waiting runners per tenant that hold
	// data nobody's run waits for, which go first.
	excess   int
	stranded map[string]int
	// cleanExcess is the part of excess that is runners holding nothing,
	// past the idle target.
	cleanExcess int
	// unmet is demand no runner, waiting or started this pass, can take.
	unmet int
}

// planDemand decides a pass's runners. Without held tenants it is the
// controller's formula, desired = clamp(minRunners, minRunners + busy +
// queued, maxRunners); with them, a runner holding one project's data counts
// only towards that project's runs, and one holding a project nobody waits for
// is stranded — retired first, never counted towards the idle target, which is
// runners holding nothing.
func planDemand(in demandInput) demandPlan {
	holders := map[string]int{}
	clean := 0
	for _, t := range in.waiting {
		if t == "" {
			clean++
		} else {
			holders[t]++
		}
	}
	matched, named := 0, 0
	var residual []string
	stranded := map[string]int{}
	for _, d := range in.queued {
		if d.Queued <= 0 {
			continue
		}
		named += d.Queued
		m := min(d.Queued, holders[d.Tenant])
		matched += m
		for i := m; i < d.Queued; i++ {
			residual = append(residual, d.Tenant)
		}
	}
	for t, n := range holders {
		served := 0
		for _, d := range in.queued {
			if d.Tenant == t {
				served = min(d.Queued, n)
			}
		}
		if n > served {
			stranded[t] = n - served
		}
	}
	for i := named; i < in.demand; i++ {
		residual = append(residual, "")
	}
	// Runners holding nothing take the oldest residual runs, as the hub hands
	// them: what is left is the newest.
	absorbed := min(len(residual), clean)
	unmetRuns := residual[absorbed:]
	spareClean := clean - absorbed
	topUp := max(0, in.minRunners-spareClean)
	total := in.busy + len(in.waiting)
	room := max(0, in.maxRunners-total)
	var start []string
	start = append(start, unmetRuns...)
	for i := 0; i < topUp; i++ {
		start = append(start, "")
	}
	if len(start) > room {
		start = start[:room]
	}
	cleanExcess := max(0, spareClean-in.minRunners)
	excess := cleanExcess
	for _, n := range stranded {
		excess += n
	}
	desired := clamp(in.minRunners, in.busy+matched+absorbed+len(unmetRuns)+in.minRunners, in.maxRunners)
	unmet := max(0, len(unmetRuns)-min(len(start), len(unmetRuns)))
	return demandPlan{desired: desired, start: start, excess: excess, stranded: stranded, cleanExcess: cleanExcess,
		unmet: unmet}
}

// volumePlan is the volume one new runner gets.
type volumePlan struct {
	vol     *volumeView // nil: a new claim at ordinal
	ordinal int
	holds   string // the tenant the runner holds, "" for a wiped or fresh volume
	wipe    bool
}

// pickVolumes chooses a volume for each tenant in want ("" for a runner
// holding nothing), in order, from vols. A tenant's own free volume is handed
// back unwiped; anything else is wiped first — a volume holding nothing worth
// keeping before a fresh one, a fresh one before a volume holding a project's
// data, and of those the least recently used of a project nobody waits for.
// A runner no volume can be found for is left out; blocked says why.
func pickVolumes(want []string, vols []*volumeView, slots int, hubPool string, queued map[string]bool,
	now time.Time) (plans []volumePlan, blocked string) {
	taken := map[*volumeView]bool{}
	used := map[int]bool{}
	// A claim that never bound may be its storage class's fault, and a new
	// one would fail the same way: none is created while one is left alone.
	// A bound volume that failed — a zone, a full disk, a broken filesystem —
	// is its own, and a new one is not.
	troubled, broken := 0, 0
	for _, v := range vols {
		used[v.ordinal] = true
		if v.troubled(now) {
			troubled++
			if !v.problemAt.IsZero() && now.Sub(v.problemAt) < storageRetryAfter &&
				v.claim.Status.Phase != ClaimBound {
				broken++
			}
		}
	}
	usable := func(v *volumeView) bool {
		return !taken[v] && v.free() && v.ordinal < slots && !v.troubled(now) && !v.givenUp() &&
			v.claim.Status.Phase != ClaimLost
	}
	nextOrdinal := func() (int, bool) {
		for n := 0; n < slots; n++ {
			if !used[n] {
				return n, true
			}
		}
		return 0, false
	}
	for _, tenant := range want {
		var pick *volumeView
		if tenant != "" {
			for _, v := range vols {
				if usable(v) && v.holdsFor(tenant, hubPool) && v.claim.Status.Phase == ClaimBound {
					pick = v
					break
				}
			}
			if pick != nil {
				taken[pick] = true
				plans = append(plans, volumePlan{vol: pick, ordinal: pick.ordinal, holds: tenant})
				continue
			}
		}
		// A wiped or fresh volume: one holding nothing worth keeping first.
		var worthless, keepers []*volumeView
		for _, v := range vols {
			if !usable(v) {
				continue
			}
			if v.holds == "" || v.holds == holdsUnknown || v.hubPool != hubPool || !executorpool.ValidTenant(v.holds) {
				worthless = append(worthless, v)
			} else {
				keepers = append(keepers, v)
			}
		}
		lru := func(xs []*volumeView) {
			sort.SliceStable(xs, func(i, j int) bool {
				// A volume runners failed on before goes last: out of its
				// quarantine it is the one most likely to fail again.
				if fi, fj := xs[i].failures > 0, xs[j].failures > 0; fi != fj {
					return !fi
				}
				qi, qj := queued[xs[i].holds], queued[xs[j].holds]
				if qi != qj {
					return !qi
				}
				return xs[i].releasedAt.Before(xs[j].releasedAt)
			})
		}
		lru(worthless)
		lru(keepers)
		switch {
		case len(worthless) > 0:
			pick = worthless[0]
		default:
			if n, ok := nextOrdinal(); ok && broken == 0 {
				used[n] = true
				plans = append(plans, volumePlan{ordinal: n, wipe: true})
				continue
			}
			if len(keepers) > 0 {
				pick = keepers[0]
			}
		}
		if pick == nil {
			if troubled > 0 {
				blocked = fmt.Sprintf("%d of the pool's volumes failed and are left alone for %s, and no other is "+
					"free", troubled, storageRetryAfter)
			}
			continue
		}
		taken[pick] = true
		plans = append(plans, volumePlan{vol: pick, ordinal: pick.ordinal, wipe: true})
	}
	return plans, blocked
}

// ── claiming ───────────────────────────────────────────────────────────────

// claimFor claims the volume plan describes for the runner Pod podName — a
// merge patch of the volume's annotations guarded by the resourceVersion the
// cache holds, or the creation of a new claim already claimed — and returns
// the claim's name. A conflict is another reconciler's claim, or a change the
// cache has not shown: the runner is not started this pass.
func (c *Controller) claimFor(ctx context.Context, pool *ExecutorPool, p *Persistence, plan volumePlan, podName,
	hubPool string) (*PersistentVolumeClaim, error) {
	holds := plan.holds
	if holds == "" {
		holds = holdsUnknown
	}
	// The time of the claim itself, not of the pass: for people reading the
	// claim. claimGrace is measured from each replica's own first sight of it.
	now := c.now()
	stamp := now.UTC().Format(time.RFC3339Nano)
	if plan.vol != nil {
		ann := map[string]*string{
			AnnotationClaimedBy: ptr(podName), AnnotationClaimedAt: ptr(stamp),
			AnnotationHolds: ptr(holds), AnnotationHubPool: ptr(hubPool),
			AnnotationProblem: nil, AnnotationProblemReason: nil,
		}
		if plan.wipe {
			ann[AnnotationProjectName], ann[AnnotationProjectOwner], ann[AnnotationFull] = nil, nil, nil
		}
		updated, err := c.api.patchClaimMeta(ctx, pool.Metadata.Namespace, plan.vol.name(),
			plan.vol.claim.Metadata.ResourceVersion, ann, projectLabel(holds), nil)
		if err != nil {
			return nil, fmt.Errorf("claim volume %s: %w", plan.vol.name(), err)
		}
		c.noteClaimed(pool.Metadata.Namespace, plan.vol.name(), podName, now)
		return updated, nil
	}
	name := claimName(pool, plan.ordinal)
	cl := buildClaim(pool, p, name, plan.ordinal)
	cl.Metadata.Annotations[AnnotationClaimedBy] = podName
	cl.Metadata.Annotations[AnnotationClaimedAt] = stamp
	cl.Metadata.Annotations[AnnotationHolds] = holds
	cl.Metadata.Annotations[AnnotationHubPool] = hubPool
	created, err := c.api.createClaim(ctx, cl)
	if err != nil {
		return nil, fmt.Errorf("create volume %s: %w", name, err)
	}
	c.noteClaimed(pool.Metadata.Namespace, name, podName, now)
	c.events.record(ctx, pool, EventNormal, ReasonVolumeCreated, fmt.Sprintf("created volume %s (%s)", name, p.Size))
	return created, nil
}

// projectLabel is the label patch that keeps LabelProject in step with what a
// volume holds: the tenant, or no label for holdsUnknown.
func projectLabel(holds string) map[string]*string {
	if executorpool.ValidTenant(holds) {
		return map[string]*string{LabelProject: ptr(holds)}
	}
	return map[string]*string{LabelProject: nil}
}

// unclaim gives a claim back at once, for a runner Pod the API server refused
// to create: nothing mounted it. claimed is the claim as the claim left it,
// whose version the release is guarded by.
func (c *Controller) unclaim(ctx context.Context, claimed *PersistentVolumeClaim, podName string, claimedAt time.Time) {
	if claimed.Metadata.Annotations[AnnotationClaimedBy] != podName {
		return
	}
	ns, name := claimed.Metadata.Namespace, claimed.Metadata.Name
	release := map[string]*string{AnnotationClaimedBy: nil, AnnotationClaimedAt: nil}
	_, err := c.api.patchClaimMeta(ctx, ns, name, claimed.Metadata.ResourceVersion, release, nil, nil)
	if kubernetes.IsConflict(err) && c.now().Sub(claimedAt) < claimGrace/2 {
		// Something else wrote the claim since — the binder, typically, a
		// moment after it was created. The claim is still this one: a rival
		// releases a claim only after watching it for claimGrace, and this
		// is well inside that.
		_, err = c.api.patchClaimMetaUnguarded(ctx, ns, name, release)
	}
	if err != nil {
		if !kubernetes.IsConflict(err) && !kubernetes.IsNotFound(err) {
			c.logf("give back volume %s/%s: %v", ns, name, err)
		}
		return
	}
	c.claimObs.mu.Lock()
	delete(c.claimObs.seen, ns+"/"+name)
	c.claimObs.mu.Unlock()
}

// buildClaim is a new runner volume, before the API server has seen it.
func buildClaim(pool *ExecutorPool, p *Persistence, name string, ordinal int) *PersistentVolumeClaim {
	labels := map[string]string{LabelManagedBy: ManagedBy, LabelName: RunnerStorageName}
	if n := pool.Metadata.Name; len(n) <= 63 && labelValue.MatchString(n) {
		labels[LabelPool] = n
	}
	var class *string
	if p.StorageClassName != "" {
		class = ptr(p.StorageClassName)
	}
	cl := &PersistentVolumeClaim{
		Metadata: ObjectMeta{
			Name:        name,
			Namespace:   pool.Metadata.Namespace,
			Labels:      labels,
			Annotations: map[string]string{AnnotationStoragePool: pool.Metadata.Name},
		},
		Spec: ClaimSpec{
			AccessModes:      append([]string(nil), p.AccessModes...),
			StorageClassName: class,
			VolumeMode:       "Filesystem",
			Resources:        ClaimResources{Requests: map[string]string{"storage": string(p.Size)}},
		},
	}
	if p.ReclaimPolicy != ReclaimRetain {
		cl.Metadata.OwnerReferences = poolOwner(pool)
	}
	_ = ordinal
	return cl
}

// poolOwner is the ownerReference that has the garbage collector delete a
// volume with its pool.
func poolOwner(pool *ExecutorPool) []OwnerReference {
	ctrl := true
	return []OwnerReference{{APIVersion: APIVersion, Kind: Kind, Name: pool.Metadata.Name, UID: pool.Metadata.UID,
		Controller: &ctrl}}
}

// ── reclaim ────────────────────────────────────────────────────────────────

// reclaimVolumes applies reclaimPolicy to the volumes the pool no longer
// needs — past maxClaims, or all of them with persistence off — once they are
// free, and keeps the others' ownership matching the policy. It returns how
// many are retained.
func (c *Controller) reclaimVolumes(ctx context.Context, pool *ExecutorPool, p *Persistence, vols []*volumeView) int {
	slots := 0
	if p.On() {
		slots = p.MaxClaims
	}
	retained := 0
	for _, vol := range vols {
		owned := controllerOf(vol.claim.Metadata) == pool.Metadata.UID
		policy := ReclaimRetain
		switch {
		case p != nil:
			policy = p.ReclaimPolicy
		case owned:
			policy = ReclaimDelete
		}
		// Past the pool's slots, given up on after too many failed runners, or
		// whose volume is gone (Lost): no runner uses it, and the policy says
		// what becomes of it once free. A given-up or Lost volume under Delete
		// frees its ordinal for a fresh one.
		unusable := vol.givenUp() || vol.claim.Status.Phase == ClaimLost
		if vol.ordinal >= slots || (unusable && policy == ReclaimDelete) {
			if !vol.free() {
				continue
			}
			if policy == ReclaimDelete {
				if err := c.api.deleteClaim(ctx, pool.Metadata.Namespace, vol.name(), vol.claim.Metadata.UID); err != nil {
					c.logf("delete volume %s/%s: %v", pool.Metadata.Namespace, vol.name(), err)
					continue
				}
				why := fmt.Sprintf("past the pool's %d", slots)
				switch {
				case vol.claim.Status.Phase == ClaimLost:
					why = "whose volume is Lost"
				case vol.givenUp():
					why = fmt.Sprintf("on which %d runners failed", vol.failures)
				}
				c.events.record(ctx, pool, EventNormal, ReasonVolumeDeleted, fmt.Sprintf(
					"deleted volume %s, %s (reclaimPolicy Delete)", vol.name(), why))
				continue
			}
			retained++
			if owned {
				empty := []OwnerReference{}
				if _, err := c.api.patchClaimMeta(ctx, pool.Metadata.Namespace, vol.name(),
					vol.claim.Metadata.ResourceVersion, nil, nil, &empty); err != nil && !kubernetes.IsConflict(err) {
					c.logf("retain volume %s/%s: %v", pool.Metadata.Namespace, vol.name(), err)
				}
				c.events.record(ctx, pool, EventNormal, ReasonVolumeRetained, fmt.Sprintf(
					"kept volume %s past the pool's %d, with the record of whose data it holds (reclaimPolicy Retain)",
					vol.name(), slots))
			}
			continue
		}
		// In use: owned by the pool exactly when the policy is Delete.
		switch {
		case policy == ReclaimDelete && !owned:
			refs := poolOwner(pool)
			if _, err := c.api.patchClaimMeta(ctx, pool.Metadata.Namespace, vol.name(),
				vol.claim.Metadata.ResourceVersion, nil, nil, &refs); err != nil && !kubernetes.IsConflict(err) {
				c.logf("own volume %s/%s: %v", pool.Metadata.Namespace, vol.name(), err)
			}
		case policy == ReclaimRetain && owned:
			empty := []OwnerReference{}
			if _, err := c.api.patchClaimMeta(ctx, pool.Metadata.Namespace, vol.name(),
				vol.claim.Metadata.ResourceVersion, nil, nil, &empty); err != nil && !kubernetes.IsConflict(err) {
				c.logf("disown volume %s/%s: %v", pool.Metadata.Namespace, vol.name(), err)
			}
		}
	}
	return retained
}

// ── status ─────────────────────────────────────────────────────────────────

// storageStatus counts the pool's volumes, nil when it has none and wants
// none.
func storageStatus(vols []*volumeView, retained int, p *Persistence, now time.Time) *StorageStatus {
	if len(vols) == 0 && !p.On() {
		return nil
	}
	s := &StorageStatus{Claims: len(vols), Retained: retained}
	for _, v := range vols {
		switch v.claim.Status.Phase {
		case ClaimBound:
			s.Bound++
		case ClaimPending, "":
			s.Pending++
		}
		if v.claimedBy != "" {
			s.InUse++
		}
		if !v.fullAt.IsZero() && now.Sub(v.fullAt) < storageRetryAfter {
			s.Full++
		}
		s.BytesUsed += v.usedBytes
		s.BytesCapacity += v.capacityBytes
	}
	return s
}

// storageTrouble is what keeps runners from starting on the pool's volumes,
// as a Degraded reason and message; "" when nothing does.
func storageTrouble(vols []*volumeView, now time.Time) (reason, msg string) {
	var pending, full, failed, gone []string
	for _, v := range vols {
		switch {
		case v.claim.Status.Phase == ClaimLost:
			gone = append(gone, v.name()+" is Lost: the volume behind it is gone")
		case v.givenUp():
			gone = append(gone, fmt.Sprintf("%s failed %d runners and is no longer used; delete it to free its slot",
				v.name(), v.failures))
		case !v.fullAt.IsZero() && now.Sub(v.fullAt) < storageRetryAfter:
			full = append(full, v.name())
		case !v.problemAt.IsZero() && now.Sub(v.problemAt) < storageRetryAfter:
			if strings.Contains(v.problemReason, "init container") {
				failed = append(failed, v.name()+": "+v.problemReason)
			} else {
				pending = append(pending, v.problemReason)
			}
		}
	}
	switch {
	case len(pending) > 0:
		return ReasonStoragePending, "a runner could not start on its volume: " + strings.Join(pending, "; ")
	case len(full) > 0:
		return ReasonStorageFull, fmt.Sprintf("volume %s is full: under spec.persistence.minFree even after it was "+
			"cleared; expand spec.persistence.size or lower minFree", strings.Join(full, ", "))
	case len(failed) > 0:
		return ReasonStoragePrepareFailed, "a runner's volume could not be prepared: " + strings.Join(failed, "; ")
	case len(gone) > 0:
		return ReasonVolumeUnusable, strings.Join(gone, "; ")
	}
	return "", ""
}

// humanBytes renders n bytes for a message.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ── telling the hub ────────────────────────────────────────────────────────

// storageReports remembers what each pool last told the hub about its storage.
type storageReports struct {
	mu   sync.Mutex
	last map[string]storageReportState
}

type storageReportState struct {
	healthy     bool
	reason, msg string
	at          time.Time
	// unsupported is a hub that answered 404 — older than the report, or an
	// ingress mid-rollout — asked again after storageReportRefresh.
	unsupported bool
}

// reset forgets every pool's last report: a new leader term reports afresh.
func (r *storageReports) reset() {
	r.mu.Lock()
	r.last = map[string]storageReportState{}
	r.mu.Unlock()
}

func newStorageReports() *storageReports {
	return &storageReports{last: map[string]storageReportState{}}
}

// reportStorage tells the hub, for the pool key, what keeps runners from
// starting on its volumes — "" for nothing — when that changed since it last
// did, or trouble was last reported longer ago than storageReportRefresh. It
// returns when to try again after a report that did not get through, 0 when
// nothing needs trying.
func (c *Controller) reportStorage(ctx context.Context, key string, f *feed, reason, msg string, now time.Time) time.Duration {
	healthy := reason == ""
	c.reports.mu.Lock()
	last, seen := c.reports.last[key]
	due := false
	switch {
	case last.unsupported:
		due = now.Sub(last.at) >= storageReportRefresh
	case !seen:
		// Once at the start, healthy or not: a report of trouble a replica
		// made before it stopped, or another made, would otherwise speak
		// for the pool until it lapsed.
		due = true
	case last.healthy != healthy || last.reason != reason || last.msg != msg:
		due = true
	case !healthy && now.Sub(last.at) >= storageReportRefresh:
		due = true
	}
	c.reports.mu.Unlock()
	if !due {
		return 0
	}
	err := f.client.ReportStatus(ctx, healthy, reason, trimMessage(msg))
	var he *HubError
	c.reports.mu.Lock()
	defer c.reports.mu.Unlock()
	switch {
	case errors.As(err, &he) && he.Status == http.StatusNotFound:
		c.reports.last[key] = storageReportState{unsupported: true, at: now}
		return 0
	case errors.As(err, &he) && he.Status == http.StatusTooManyRequests:
		return 2 * time.Second
	case err != nil:
		c.logf("tell the hub about %s's storage: %v", key, err)
		return feedBackoffBase * 5
	}
	c.reports.last[key] = storageReportState{healthy: healthy, reason: reason, msg: msg, at: now}
	return 0
}

// forget drops what was reported for a pool that is gone.
func (r *storageReports) forget(key string) {
	r.mu.Lock()
	delete(r.last, key)
	r.mu.Unlock()
}
