package orchestrator

// diskfloor.go keeps a run from starting work on a disk too full to record
// what the work did (Task 20381).
//
// Nothing used to look at free space before work started. A run learned the
// disk was full when a write failed, and the write that fails first is often
// the one recording a task's outcome. Since Task 20362 the run then stops with
// state_not_persisted, which is honest but late: the task's work is done and
// its record is not. The verdict sidecar written just before it (Task 20365)
// can fail in the same moment, and with both gone stale-task recovery falls
// back to the agent's own TASK_* claim.
//
// Two mechanisms close that:
//
//   - A floor. Before every task attempt and every evolve round the run
//     measures the volume holding the project's .cloop and the working tree's
//     volume — normally one, told apart by device. If either is below
//     orchestrator.min_free_disk_mb, nothing starts: the run pauses with
//     reason disk_low, journals why, and measures again every minute. It
//     carries on by itself once every volume is back above the floor plus a
//     tenth, a margin that keeps a disk hovering at the floor from flapping
//     the run, or ends when the operator stops it. The process stays up
//     throughout, which is why pausereason.RunWaits counts this pause as a
//     live run.
//
//   - A reserve. .cloop/reserve holds 16 MiB of preallocated blocks
//     (pkg/diskreserve), put in place whenever the floor check passes. When a
//     critical write — persistOutcome's verdict, or its state write — fails for
//     want of space anyway, because the task's own build filled the disk
//     between the check and the write, the reserve is deleted and the write
//     tried once more on the space that frees. The run then pauses disk_low at
//     its next check, whatever the volume reads by then. If the retry fails
//     too, the error stands and the run stops state_not_persisted, as before.
//
// A floor of 0 turns both off.
//
// What counts as a task attempt is the dispatch of a task from the plan,
// including a retry of one that went back to pending. A heal re-run happens
// inside an attempt, with the task already in progress, and is part of it. In
// the parallel loop the check runs where a round would launch: the round
// before it has finished and recorded its outcomes by then, so workers start
// nothing new and the work in flight is never cut short.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/pkg/diskreserve"
	"github.com/blechschmidt/cloop/pkg/diskusage"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// diskPollInterval is how often a run paused for disk space measures again.
// A minute, like the backoff a usage cap with no known reset waits (Task
// 20285): space comes back when someone frees it, and nobody needs the run to
// notice within seconds.
const diskPollInterval = time.Minute

// diskFloorBytes is the configured floor in bytes, or 0 when the check is off.
func (o *Orchestrator) diskFloorBytes() int64 {
	if o == nil || o.config.MinFreeDiskMB <= 0 {
		return 0
	}
	return int64(o.config.MinFreeDiskMB) << 20
}

// diskResumeBytes is the free space a paused run waits for: the floor plus a
// tenth. Resuming at the floor itself would let a volume hovering there pause
// and resume the run once a minute.
func diskResumeBytes(floor int64) int64 {
	return floor + floor/10
}

// diskPoll is diskPollInterval unless a test has shortened it.
func (o *Orchestrator) diskPoll() time.Duration {
	if o.testDiskPoll > 0 {
		return o.testDiskPoll
	}
	return diskPollInterval
}

// probeDisk measures the volumes this run writes to: the one holding the
// project's .cloop — state.db, the verdicts, the reserve — and the working
// tree's, deduplicated by device.
func (o *Orchestrator) probeDisk() ([]diskusage.Volume, error) {
	work := o.config.WorkDir
	paths := []string{filepath.Join(work, ".cloop"), work}
	if o.diskProbe != nil {
		return o.diskProbe(paths...)
	}
	return diskusage.Volumes(paths...)
}

// volumesBelow returns the volumes with less than threshold bytes free.
func volumesBelow(vols []diskusage.Volume, threshold int64) []diskusage.Volume {
	var low []diskusage.Volume
	for _, v := range vols {
		if v.FreeBytes < threshold {
			low = append(low, v)
		}
	}
	return low
}

// describeVolumes renders volumes for the operator: "volume / has 812.3 MB
// free". threshold, when positive, adds what it falls short of.
func describeVolumes(vols []diskusage.Volume, threshold int64, noun string) string {
	parts := make([]string, 0, len(vols))
	for _, v := range vols {
		p := fmt.Sprintf("volume %s has %s free", v.Mount, diskusage.HumanBytes(v.FreeBytes))
		if threshold > 0 {
			p += fmt.Sprintf(", below the %s %s", diskusage.HumanBytes(threshold), noun)
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; ")
}

// volumeDetails is the journal's account of the volumes measured.
func volumeDetails(vols []diskusage.Volume) []map[string]any {
	out := make([]map[string]any, 0, len(vols))
	for _, v := range vols {
		out = append(out, map[string]any{"mount": v.Mount, "path": v.Path, "free_bytes": v.FreeBytes})
	}
	return out
}

// awaitDiskSpace is the free-space check in front of every task attempt and
// evolve round. before names what was about to start, for the record.
//
// With room on every volume it returns (false, nil) and the caller starts its
// work; it also puts the reserve in place, since there is room for it. Without,
// it pauses the run with reason disk_low — stored before it is announced, like
// every pause — and waits, measuring every diskPoll, until every volume is back
// above diskResumeBytes. Then it sets the run running again and returns (true,
// nil): time has passed and the plan may have changed under the run, so the
// caller goes back to the top of its loop rather than starting what it had
// picked.
//
// A stop while it waits is recorded as a cancelled pause and returned as the
// context's error. A pause or resume the database will not store comes back as
// the persist error, which ends the run.
//
// mu, when the parallel loop passes it, guards the state while it is written.
// Both loops call this with no task in flight, so neither does.
func (o *Orchestrator) awaitDiskSpace(ctx context.Context, s *state.ProjectState, mu sync.Locker, before string) (waited bool, err error) {
	floor := o.diskFloorBytes()
	if floor == 0 {
		return false, nil
	}
	spent := o.takeReserveSpent()
	vols, probeErr := o.probeDisk()
	if probeErr != nil && spent == "" {
		// A volume that cannot be measured is not known to be full. Holding
		// the run on a statfs that fails would turn a diagnostic into an
		// outage; the reserve and state_not_persisted still stand behind it.
		o.noteDiskProbeFailure(probeErr)
		return false, nil
	}
	low := volumesBelow(vols, floor)
	if len(low) == 0 && spent == "" {
		o.keepReserve()
		return false, nil
	}

	detail := describeVolumes(low, floor, "floor")
	if spent != "" {
		detail = spent
		if len(low) > 0 {
			detail += "; " + describeVolumes(low, floor, "floor")
		} else if len(vols) > 0 {
			detail += "; " + describeVolumes(vols, 0, "")
		}
	}
	if err := o.pauseLocked(s, pausereason.New(pausereason.CodeDiskLow, detail), "the pause (disk space low: "+detail+")", mu); err != nil {
		return true, err
	}
	resume := diskResumeBytes(floor)
	pausedAt := o.now()
	details := map[string]any{
		"pause_code":   string(pausereason.CodeDiskLow),
		"before":       before,
		"floor_bytes":  floor,
		"resume_bytes": resume,
		"volumes":      volumeDetails(vols),
	}
	if spent != "" {
		details["reserve_spent"] = spent
	}
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type:    state.EventSessionPaused,
		Step:    state.NoStep,
		Message: "Run paused before " + before + ": disk space low — " + detail,
	}, details)
	o.log.Warn(logger.EventDiskSpace, 0, "run paused: disk space low", details)
	color.New(color.FgYellow).Printf("⏸ Pausing before %s: %s. Nothing starts until every volume is back above %s; "+
		"checking every %s. Free some space, or stop the run.\n",
		before, detail, diskusage.HumanBytes(resume), o.diskPoll())

	for {
		timer := time.NewTimer(o.diskPoll())
		select {
		case <-ctx.Done():
			timer.Stop()
			stopErr := o.pauseLocked(s, pausereason.New(pausereason.CodeCancelled,
				"run stopped while waiting for disk space: "+detail), "the pause (run stopped while waiting for disk space)", mu)
			if stopErr != nil {
				return true, errors.Join(ctx.Err(), stopErr)
			}
			return true, ctx.Err()
		case <-timer.C:
		}
		vols, probeErr = o.probeDisk()
		if probeErr != nil {
			// Same reasoning as above: an unmeasurable volume is not a full
			// one, and waiting on a measurement that never comes is a hang.
			o.noteDiskProbeFailure(probeErr)
			break
		}
		if len(volumesBelow(vols, resume)) == 0 {
			break
		}
	}

	o.keepReserve()
	if err := o.resumeLocked(s, mu); err != nil {
		return true, err
	}
	waitedFor := o.now().Sub(pausedAt).Round(time.Second)
	recovered := describeVolumes(vols, 0, "")
	if recovered == "" {
		recovered = "free space could not be measured"
	}
	resumeDetails := map[string]any{
		"resumed_from":   string(pausereason.CodeDiskLow),
		"paused_seconds": int64(waitedFor / time.Second),
		"floor_bytes":    floor,
		"volumes":        volumeDetails(vols),
	}
	state.LogEventDetails(o.config.WorkDir, state.EventRow{
		Type:    state.EventSessionStarted,
		Step:    state.NoStep,
		Message: "Run resumed: disk space recovered — " + recovered,
	}, resumeDetails)
	o.log.Info(logger.EventDiskSpace, 0, "run resumed: disk space recovered", resumeDetails)
	color.New(color.FgGreen).Printf("▶ Disk space recovered (%s) — resuming after %s.\n", recovered, waitedFor)
	return true, nil
}

// resumeLocked sets a run that waited out its pause running again and stores
// it, holding mu (when given) across both.
func (o *Orchestrator) resumeLocked(s *state.ProjectState, mu sync.Locker) error {
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	s.Status = "running"
	s.PauseReason = nil
	return o.persist(s, "the run's status (running: disk space recovered)")
}

// keepReserve puts the reserve in place, or back after it was spent. It is
// called where the floor check passed, so there is room for it; a failure only
// means it cannot be kept yet, and is reported without stopping anything.
func (o *Orchestrator) keepReserve() {
	created, err := diskreserve.Ensure(o.config.WorkDir)
	switch {
	case err == nil && created:
		o.log.Info(logger.EventDiskSpace, 0, "free-space reserve in place",
			map[string]interface{}{"path": diskreserve.Path(o.config.WorkDir), "bytes": diskreserve.Size})
	case err == nil, errors.Is(err, diskreserve.ErrNoRoom):
	default:
		// Once per run: the cause will not change between attempts.
		o.diskMu.Lock()
		first := !o.reserveWarned
		o.reserveWarned = true
		o.diskMu.Unlock()
		if !first {
			return
		}
		o.log.Warn(logger.EventDiskSpace, 0, "free-space reserve not kept", map[string]interface{}{"error": err.Error()})
		color.New(color.FgYellow).Fprintf(os.Stderr,
			"⚠ Could not keep the free-space reserve (%v) — carrying on; a task's outcome written onto a full disk has nothing to fall back on.\n", err)
	}
}

// settleReserve runs once, when a run starts: with the floor off there is no
// reserve to keep, and one a run with the floor on left behind is given back.
func (o *Orchestrator) settleReserve() {
	if o.diskFloorBytes() > 0 || o.config.WorkDir == "" {
		return
	}
	if freed, err := diskreserve.Release(o.config.WorkDir); err == nil && freed > 0 {
		o.log.Info(logger.EventDiskSpace, 0, "free-space reserve released: orchestrator.min_free_disk_mb is 0",
			map[string]interface{}{"bytes": freed})
	}
}

// writeOnReserve runs a critical write and, when it fails for want of space,
// gives up the reserve and runs it once more on the space that frees. what
// names the write — "task #3's verdict" — for the record.
//
// Whatever the retry does, the next disk check pauses the run: the reserve is
// gone, and the disk was full enough to refuse a write. If the retry fails as
// well, its error is the write's, and the caller's handling of a failed write
// stands — state_not_persisted for an outcome.
//
// Safe from parallel workers, which write verdicts: releasing a reserve that
// another write already released frees nothing and is not an error.
func (o *Orchestrator) writeOnReserve(what string, write func() error) error {
	err := write()
	if err == nil || o.diskFloorBytes() == 0 || !diskreserve.IsDiskFull(err) {
		return err
	}
	freed, relErr := diskreserve.Release(o.config.WorkDir)
	retryErr := write()

	fields := map[string]interface{}{"write": what, "error": err.Error(), "freed_bytes": freed, "landed": retryErr == nil}
	if relErr != nil {
		fields["release_error"] = relErr.Error()
	}
	var note string
	switch {
	case retryErr == nil && freed > 0:
		note = fmt.Sprintf("%s only reached the disk by releasing the %s free-space reserve", what, diskusage.HumanBytes(freed))
		color.New(color.FgYellow).Fprintf(os.Stderr,
			"⚠ Out of disk space writing %s: released the %s reserve and tried again — it landed. "+
				"The run pauses before it starts anything else.\n", what, diskusage.HumanBytes(freed))
	case retryErr == nil:
		note = what + " only reached the disk on a second try, with no free-space reserve left to release"
		color.New(color.FgYellow).Fprintf(os.Stderr,
			"⚠ Out of disk space writing %s: the reserve was already spent, and a second try landed. "+
				"The run pauses before it starts anything else.\n", what)
	default:
		note = what + " could not be written: the disk is full even with the free-space reserve released"
		fields["retry_error"] = retryErr.Error()
	}
	o.log.Warn(logger.EventDiskSpace, 0, "out of disk space on a critical write", fields)
	o.noteReserveSpent(note)
	return retryErr
}

// noteReserveSpent records that a write needed the reserve, so the next disk
// check pauses whatever it measures. The first account is kept: it names the
// write that found the disk full.
func (o *Orchestrator) noteReserveSpent(note string) {
	o.diskMu.Lock()
	defer o.diskMu.Unlock()
	if o.reserveSpent == "" {
		o.reserveSpent = note
	}
}

// takeReserveSpent returns and clears the note noteReserveSpent left.
func (o *Orchestrator) takeReserveSpent() string {
	o.diskMu.Lock()
	defer o.diskMu.Unlock()
	note := o.reserveSpent
	o.reserveSpent = ""
	return note
}

// noteDiskProbeFailure reports, once per run, that free space could not be
// measured. It is not repeated before every task: the cause will not change
// between them, and the run carries on either way.
func (o *Orchestrator) noteDiskProbeFailure(err error) {
	o.diskMu.Lock()
	first := !o.diskProbeWarned
	o.diskProbeWarned = true
	o.diskMu.Unlock()
	if !first {
		return
	}
	o.log.Warn(logger.EventDiskSpace, 0, "free space could not be measured", map[string]interface{}{"error": err.Error()})
	color.New(color.FgYellow).Fprintf(os.Stderr,
		"⚠ Could not measure free disk space (%v) — carrying on without the orchestrator.min_free_disk_mb check.\n", err)
}

// roundNoun names a parallel round for the record: "task #4", or "tasks #4,
// #7 and #9".
func roundNoun(ready []*pm.Task) string {
	ids := make([]string, 0, len(ready))
	for _, t := range ready {
		if t != nil {
			ids = append(ids, fmt.Sprintf("#%d", t.ID))
		}
	}
	switch len(ids) {
	case 0:
		return "the next round"
	case 1:
		return "task " + ids[0]
	default:
		return "tasks " + strings.Join(ids[:len(ids)-1], ", ") + " and " + ids[len(ids)-1]
	}
}
