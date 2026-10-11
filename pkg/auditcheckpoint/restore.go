package auditcheckpoint

// Restore records: telling a restore from a truncation (Task 20410).
//
// Restoring a backup legitimately does to a chain exactly what an attacker
// does when they delete its tail while the hub keeps writing: the rows the
// newest checkpoints saw are gone, and new rows have since taken their ids.
// Before restore records, the verifier had to call both "restored" and fail
// them alike — forever, since the checkpoint file keeps the superseded records
// — so after every real restore `cloop hub audit verify --checkpoints` exited 2
// for good, and the doctor failed until fifty new checkpoints had pushed the old
// ones out of the window it reads. An operator who has to ignore a permanent
// alarm has no alarm.
//
// A restore record is the difference. `cloop db restore` writes one, sealed
// under the checkpoint key, once the backup is in place and its audit.restored
// row is appended: the backup's digest and time, the head the chain was
// restored to, the newest checkpoint it superseded, who and why. Here, a record
// sealed under the key this verifier holds — and only such a record, because
// database or file write access must never be enough to explain a truncation
// away — accounts for the records sealed before it that saw past the restored
// head. It accounts for nothing sealed after it: the restore's own row reuses
// ids the superseded checkpoints saw, with other hashes, and a checkpoint that
// saw the restored chain and now disagrees is a new divergence. And it has to
// hold itself: a record whose head, or whose restored head, the chain no longer
// holds was itself cut away, and fails.

import (
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// refuseRestore says why a restore record cannot be used at all, or "".
func (v *verifier) refuseRestore(c Checked) string {
	switch {
	case c.Restore == nil || c.Reason != ReasonRestore:
		return fmt.Sprintf("the record on line %d is half a restore record (reason %q, restore section %s): "+
			"`cloop db restore` writes neither without the other", c.Line, c.Reason, presence(c.Restore != nil))
	case c.Seal == SealUnsigned && v.key != nil:
		return fmt.Sprintf("the restore record on line %d carries no seal: `cloop db restore` seals every record when %s "+
			"is set, so this one was written by hand, or by a restore with no key — either way nothing vouches for it",
			c.Line, EnvKey)
	case c.At().IsZero() || c.At().After(time.Now().Add(maxFutureSkew)):
		// Its time decides which records it accounts for — those sealed
		// before it — so a record dated ahead of this clock, by a skewed host
		// or anyone holding the key, would account for records not yet
		// written.
		return fmt.Sprintf("the restore record on line %d is dated %s, ahead of this verifier's clock: a restore "+
			"record accounts for the records sealed before it, so one from the future accounts for none", c.Line, c.Time)
	}
	return ""
}

func presence(ok bool) string {
	if ok {
		return "present"
	}
	return "absent"
}

// acknowledgeRestores applies the restore records the chain agrees with to the
// records sealed before them, fails sealed restore records the chain no longer
// agrees with, and returns what each valid restore gave up.
//
// checked is in time order; vouched is the anchors a trusted record vouched
// for, for a restored head that has since been pruned.
func (v *verifier) acknowledgeRestores(checked []Checked, vouched map[int64]bool) ([]RestoreFinding, error) {
	// A restore record may vouch only when it is sealed under the key held
	// here, and only when the chain still holds both heads it pins.
	valid := map[int]bool{}
	pinDetail := map[int]string{}
	for i := range checked {
		c := &checked[i]
		if !c.IsRestore() || c.Result == ResultRefused || c.Seal != SealValid {
			continue
		}
		pin, err := v.judgeRestoredHead(*c, vouched)
		if err != nil {
			return nil, err
		}
		switch {
		case c.Result.Failing():
			pinDetail[i] = fmt.Sprintf("the restore record at %s (line %d) pins the chain's head after the restore "+
				"at id %d; %s", c.Time, c.Line, c.LastID, c.Detail)
		case pin.Result.Failing():
			pinDetail[i] = fmt.Sprintf("the restore record at %s (line %d) says the chain was restored to id %d; %s",
				c.Time, c.Line, c.Restore.RestoredID, pin.Detail)
		default:
			valid[i] = true
		}
	}

	findings := map[int]*RestoreFinding{}
	for i := range checked {
		c := &checked[i]
		_, mismatched := pinDetail[i]
		if !c.Result.supersedable() && !mismatched {
			continue
		}
		j, ok := supersedingRestore(checked, valid, i)
		if !ok {
			if mismatched {
				c.Result, c.Detail = ResultRestoreMismatch, pinDetail[i]
			}
			continue
		}
		r := checked[j]
		c.Result = ResultAcknowledged
		c.Detail = fmt.Sprintf("superseded by the restore at %s (line %d): it saw id %d, past the id %d "+
			"the chain was restored to", r.Time, r.Line, c.LastID, r.Restore.RestoredID)
		f := findings[j]
		if f == nil {
			f = newRestoreFinding(r)
			findings[j] = f
		}
		f.Superseded++
		if c.LastID > f.LostThroughID {
			f.LostThroughID = c.LastID
		}
		if at := c.At(); at.After(parseTime(f.To)) {
			f.To = FormatTime(at)
		}
	}

	var out []RestoreFinding
	for i := range checked {
		if !valid[i] {
			continue
		}
		f := findings[i]
		if f == nil {
			f = newRestoreFinding(checked[i])
		}
		f.LostEvents = 0
		if f.LostThroughID > f.Record.Restore.RestoredID {
			f.LostEvents = f.LostThroughID - f.Record.Restore.RestoredID
		} else {
			f.LostFromID, f.LostThroughID = 0, 0
		}
		out = append(out, *f)
	}
	return out, nil
}

// supersedingRestore finds the earliest valid restore record sealed after
// record i whose restored head lies before the id i saw: the restore that gave
// up the history i recorded.
func supersedingRestore(checked []Checked, valid map[int]bool, i int) (int, bool) {
	c := checked[i]
	at := c.At()
	for j := range checked {
		if !valid[j] || j == i {
			continue
		}
		r := checked[j]
		if r.At().After(at) && c.LastID > r.Restore.RestoredID {
			return j, true
		}
	}
	return 0, false
}

// newRestoreFinding starts a finding from what the record itself says.
func newRestoreFinding(r Checked) *RestoreFinding {
	x := r.Restore
	f := &RestoreFinding{Record: r, From: x.RestoredTime}
	if f.From == "" {
		f.From = x.BackupTime
	}
	f.LostFromID = x.RestoredID + 1
	if x.SupersededID > x.RestoredID {
		f.LostThroughID, f.To = x.SupersededID, x.SupersededTime
	}
	return f
}

// judgeRestoredHead asks the chain whether it still holds the head the restore
// record says it was restored to, as if a checkpoint had seen it at the
// record's time.
func (v *verifier) judgeRestoredHead(c Checked, vouched map[int64]bool) (Checked, error) {
	x := c.Restore
	pin := Checked{Located: Located{Line: c.Line, Record: Record{
		Kind: c.Kind, Version: c.Version, Chain: c.Chain, Path: c.Path,
		LastID: x.RestoredID, LastRowHash: x.RestoredRowHash, Time: c.Time,
	}}}
	if x.RestoredID <= 0 {
		pin.Result, pin.Detail = ResultConsistent, "the backup's chain was empty"
		return pin, nil
	}
	anchor, err := v.judge(&pin)
	if err != nil {
		return pin, err
	}
	if pin.Result == ResultPruned {
		pins := []Checked{pin}
		checkArchive(anchor, v.boundaryBefore(anchor), vouched[anchor.ID], pins, []int{0})
		pin = pins[0]
	}
	return pin, nil
}

// Superseded returns the record a restore of a chain to restoredID supersedes:
// the newest of recs that may vouch (see Usable), when it saw an id past
// restoredID. A newest record within the restored head supersedes nothing, and
// an older one past it was superseded by an earlier restore, not this one.
func Superseded(recs []Located, key *Key, restoredID int64, now time.Time) (Located, bool) {
	usable := Usable(recs, key, now)
	if len(usable) == 0 {
		return Located{}, false
	}
	newest := usable[len(usable)-1]
	if newest.LastID <= restoredID {
		return Located{}, false
	}
	return newest, true
}

// RestoreFrom fills in what a restore record says about the backup's chain
// from its head.
func RestoreFrom(head statedb.AuditHead) Restore {
	x := Restore{RestoredID: head.LastID, RestoredRowHash: head.LastRowHash}
	if !head.LastTimestamp.IsZero() {
		x.RestoredTime = FormatTime(head.LastTimestamp)
	}
	return x
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
