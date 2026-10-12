package dbbackup

// Recording a restore, once the backup is in place (Task 20410).
//
// A restore rewinds a hash chain, and to anything checking the chain against
// its off-database checkpoints that is indistinguishable from a tail deleted
// while the hub kept writing — which is exactly what an attacker would call a
// restore. So a restore leaves two records, each where the other cannot reach:
//
//   - an audit.restored row, appended to the restored chain as its next row:
//     the backup's digest and time, the head the chain was restored to, the
//     newest checkpoint superseded and the history lost, who and why;
//   - a restore record, sealed under the audit checkpoint key and written to
//     the checkpoint sinks (the file and stderr), saying the same and pinning
//     that row's hash.
//
// The second is what `cloop hub audit verify --checkpoints` accepts as the
// explanation for the checkpoints the restore superseded. It is sealed under a
// key derived from CLOOP_SECRET_KEY, which is never stored, so write access to
// the database — or to the checkpoint file — is not enough to forge one.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/auditcheckpoint"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Recording is how a restore was recorded.
type Recording struct {
	// RestoredHead is where the restored chain ended before the restore
	// appended to it: the newest row the backup holds.
	RestoredHead statedb.AuditHead
	// Superseded is the newest checkpoint the restore superseded; nil when
	// none saw history past the restored head, or none could be read.
	Superseded *auditcheckpoint.Located
	// Row is the audit.restored row; zero when it could not be appended.
	Row statedb.AuditEvent
	// Record is the restore record; Sealed whether it carries a seal, and
	// Sinks where it was written ("file", "stderr").
	Record auditcheckpoint.Record
	Sealed bool
	Sinks  []string
	// RetiredKeys are the sealing keys retired under --accept-secret-loss.
	RetiredKeys []string
	// Notes say what could not be done, and why.
	Notes []string
}

// UnrecordedError is a restore that completed and could not be fully
// recorded: the database is the backup, and something is missing from the
// record of it. The message says what, and how to finish it by hand.
type UnrecordedError struct {
	Problems []string
}

func (e *UnrecordedError) Error() string {
	return "dbbackup: restored, but not fully recorded: " + strings.Join(e.Problems, "; ")
}

// record writes the restore's audit row and restore record, and retires the
// sealing keys an accepted secret loss gave up.
func record(dst string, pre *Preflight, opts RestoreOptions) (Recording, error) {
	var (
		rec      Recording
		problems []string
	)
	db, err := statedb.Open(dst)
	if err != nil {
		return rec, &UnrecordedError{Problems: []string{fmt.Sprintf("open the restored database: %v", err)}}
	}
	defer db.Close()
	now := opts.now()

	if opts.AcceptSecretLoss {
		var ids []string
		for _, k := range pre.LostKeys() {
			if k.State != KeyStateLegacy {
				ids = append(ids, k.ID)
			}
		}
		if len(ids) > 0 {
			if rec.RetiredKeys, err = db.AbandonKEKs(ids, now); err != nil {
				problems = append(problems, fmt.Sprintf("retire the sealing keys the restore gave up (%s), "+
					"without which the hub will not start: %v", strings.Join(ids, ", "), err))
			}
		}
	}

	head, err := db.AuditHead()
	if err != nil {
		// Without the head there is nothing to pin: a record claiming the
		// chain was restored to id 0 would be a false statement under seal.
		problems = append(problems, fmt.Sprintf("read the restored chain's head, so neither the audit.restored "+
			"row nor the restore record was written: %v", err))
		return rec, &UnrecordedError{Problems: problems}
	}
	rec.RestoredHead = head
	// The file just swapped in hashed to what the preflight checked, so its
	// chain ends where the backup's did. One that ends anywhere else was
	// written between the swap and this read, and sealing it as "restored to"
	// would vouch for whatever that write did — a truncation included.
	if head.LastID != pre.Chain.LastID || head.LastRowHash != pre.Chain.LastRowHash {
		problems = append(problems, fmt.Sprintf("the restored chain ends at id %d, not at the backup's id %d: the "+
			"database was written between the swap and the record, so neither the audit.restored row nor the restore "+
			"record was written — find out what wrote it", head.LastID, pre.Chain.LastID))
		return rec, &UnrecordedError{Problems: problems}
	}

	// Sealed under the current root; checkpoints sealed under the previous one
	// during a change of root are the hub's own all the same.
	cpKey, _ := auditcheckpoint.KeyForRoots(opts.Key, opts.Previous)
	recs, chain, recordPath, note := checkpointsFor(opts.CheckpointFile, dst)
	if note != "" {
		rec.Notes = append(rec.Notes, note)
	}
	if opts.Chain != "" {
		chain = opts.Chain
	}
	if sup, ok := auditcheckpoint.Superseded(recs, cpKey, head.LastID, now); ok {
		rec.Superseded = &sup
	}

	x := auditcheckpoint.RestoreFrom(head)
	x.BackupSHA256, x.Actor, x.Reason = pre.SHA256, opts.Actor, strings.TrimSpace(opts.Reason)
	x.Sidecar = string(pre.Sidecar)
	if pre.Meta != nil && !pre.Meta.CreatedAt.IsZero() {
		x.BackupTime = auditcheckpoint.FormatTime(pre.Meta.CreatedAt)
	}
	if s := rec.Superseded; s != nil {
		x.SupersededID, x.SupersededRowHash, x.SupersededTime = s.LastID, s.LastRowHash, s.Time
	}
	if opts.AcceptSecretLoss {
		for _, k := range pre.LostKeys() {
			x.SecretLoss = append(x.SecretLoss, k.ID)
		}
	}

	if cpKey != nil {
		rec.Sealed = true
	} else {
		rec.Notes = append(rec.Notes, "there is no "+EnvKey+": the restore record is unsigned, and accounts for "+
			"nothing — `cloop hub audit verify --checkpoints` will report the checkpoints it supersedes as a restore")
	}
	if opts.CheckpointFile != "" {
		rec.Sinks = append(rec.Sinks, "file")
	}
	if opts.CheckpointStderr != nil {
		rec.Sinks = append(rec.Sinks, "stderr")
	}

	rec.Row = restoredRow(pre, opts, x, rec, now)
	if err := db.AppendAuditEvent(&rec.Row); err != nil {
		problems = append(problems, fmt.Sprintf("append the audit.restored row: %v", err))
		rec.Row = statedb.AuditEvent{}
	}

	// The record's head is the restore's own row, so a chain cut back to the
	// restored head later disagrees with it. Without the row it pins the
	// restored head itself.
	after := head
	if rec.Row.ID > 0 {
		after.LastID, after.LastRowHash, after.LastTimestamp = rec.Row.ID, rec.Row.RowHash, rec.Row.Timestamp
		after.Rows = head.Rows + 1
	}
	member := opts.Actor
	if host, err := os.Hostname(); err == nil {
		member = fmt.Sprintf("%s-%d", host, os.Getpid())
	}
	rec.Record = auditcheckpoint.RestoreRecord(after, chain, recordPath, member, now, x)
	cpKey.Seal(&rec.Record)

	if len(rec.Sinks) == 0 {
		// Nothing to write to is nothing to contradict the chain either: with
		// checkpoints off, no record outside the database saw the history
		// this restore gave up. The audit.restored row is the record.
		rec.Notes = append(rec.Notes, "audit checkpoints are off, so the restore record went nowhere; "+
			"the audit.restored row in the restored chain is the record of this restore")
	} else {
		sink := auditcheckpoint.Sink{File: opts.CheckpointFile, Stderr: opts.CheckpointStderr}
		if err := sink.Write([]auditcheckpoint.Record{rec.Record}); err != nil {
			// The file is written first and is what failed; the stderr copy,
			// when there is one, went out.
			hint := "the record went nowhere else, so nothing outside the database accounts for this restore"
			rec.Sinks = nil
			if opts.CheckpointStderr != nil {
				hint = "append the restore record printed on stderr to it; it is sealed, so it counts wherever it is appended from"
				rec.Sinks = []string{"stderr"}
			}
			problems = append(problems, fmt.Sprintf("write the restore record to %s: %v — %s",
				opts.CheckpointFile, err, hint))
		}
	}

	if len(problems) > 0 {
		return rec, &UnrecordedError{Problems: problems}
	}
	return rec, nil
}

// restoredRow is the audit.restored row.
func restoredRow(pre *Preflight, opts RestoreOptions, x auditcheckpoint.Restore, rec Recording, now time.Time) statedb.AuditEvent {
	type lostKey struct {
		KeyID string `json:"key_id"`
		Rows  int    `json:"rows"`
	}
	lost := []lostKey{}
	if opts.AcceptSecretLoss {
		for _, k := range pre.LostKeys() {
			lost = append(lost, lostKey{KeyID: k.ID, Rows: k.Total()})
		}
	}
	sinks := strings.Join(rec.Sinks, "+")
	if sinks == "" {
		sinks = "none"
	}
	payload := map[string]any{
		"backup":              pre.Backup,
		"backup_sha256":       x.BackupSHA256,
		"backup_time":         x.BackupTime,
		"sidecar":             string(pre.Sidecar),
		"restored_id":         x.RestoredID,
		"restored_row_hash":   x.RestoredRowHash,
		"restored_time":       x.RestoredTime,
		"superseded_id":       x.SupersededID,
		"superseded_row_hash": x.SupersededRowHash,
		"superseded_time":     x.SupersededTime,
		"lost_events":         x.LostEvents(),
		"reason":              x.Reason,
		"accepted_loss":       opts.AcceptSecretLoss,
		"lost_keys":           lost,
		"key_fingerprint":     pre.KeyFingerprint,
		"checkpoint_record":   sinks,
	}
	return statedb.AuditEvent{
		Timestamp:  now.UTC(),
		Actor:      opts.Actor,
		EventType:  string(auditaction.ActionAuditRestored),
		EntityType: "audit",
		EntityID:   x.BackupSHA256,
		Payload:    statedb.MarshalAuditPayload(payload),
	}
}

// checkpointsFor reads the records in file that name the database at dst —
// by its path, and by the path its symlinks resolve to — the chain role the
// newest of them names, and the path it spells the database with: the
// restore record spells it the same way, or a verifier grouping records by
// path would never set the two side by side. note says why none could be
// read, when that is worth telling.
func checkpointsFor(file, dst string) (recs []auditcheckpoint.Located, chain, path, note string) {
	chain, path = auditcheckpoint.ChainProject, dst
	if file == "" {
		return nil, chain, path, ""
	}
	parsed, err := auditcheckpoint.ReadFile(file)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, chain, path, ""
	case err != nil:
		return nil, chain, path, fmt.Sprintf("could not read %s for the checkpoints this restore supersedes: %v", file, err)
	}
	groups := auditcheckpoint.ByPath(parsed.Records)
	recs = groups[auditcheckpoint.ValidPath(dst)]
	if real, err := filepath.EvalSymlinks(filepath.Dir(dst)); err == nil {
		if alt := auditcheckpoint.ValidPath(filepath.Join(real, filepath.Base(dst))); alt != auditcheckpoint.ValidPath(dst) {
			recs = append(recs, groups[alt]...)
		}
	}
	if newest, ok := auditcheckpoint.Newest(recs); ok {
		if newest.Chain != "" {
			chain = newest.Chain
		}
		path = newest.Path
	}
	return recs, chain, path, ""
}
