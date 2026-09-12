// Task-audit change detection (Task 20218).
//
// SaveState rewrites plan_tasks wholesale — DELETE all, INSERT all — because
// the caller hands it a whole plan and the cheapest correct write is a
// replacement. The audit emitter mirrored that shape and emitted one
// `task.upsert` per task per save, which is how a 417-task plan turned a
// per-step save into 417 audit rows and 417 transactions. On the hub that
// reached 1.09M rows, 99.7% of the table.
//
// Wholesale replacement is fine for plan_tasks and wrong for an audit trail:
// the trail is supposed to record mutations, and rewriting a row with its own
// contents is not one. So the write path has to know what actually changed,
// and it has to know it *before* the DELETE, since afterwards the previous
// values are gone.
//
// audit_task_fingerprints holds SHA-256 of the exact payload last emitted for
// each task. Not of the task row, and not of a chosen subset of fields: of the
// payload, so "changed" means precisely "would produce a different audit row".
// A projection would drift the first time pm.Task gains a field that
// plan_tasks does not store, and drift here is silent — a field that stops
// being compared stops being audited.
//
// The fingerprints are persisted rather than cached in memory so a hub restart
// does not re-emit the whole plan, and are written inside the same transaction
// as the tasks so the two cannot disagree.
//
// One consequence worth naming: the diff runs even when SetAuditEnabled(false)
// has silenced emission, so mutations made while auditing was off do not
// reappear as a burst of rows when it is switched back on. That is the honest
// behaviour — those changes were not audited, and re-emitting them later under
// today's timestamps would put a false account of when they happened into a
// table whose whole purpose is to say when things happened.

package statedb

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// taskAuditFingerprint hashes the payload that auditTaskUpsert would emit for
// t. Cheap enough to run for every task on every save: one JSON marshal and
// one SHA-256 over a few hundred bytes, against the transaction it saves.
func taskAuditFingerprint(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// taskAuditChange is one task whose audit payload differs from the last one
// emitted for it, carried from inside the write transaction out to the
// post-commit emitter.
type taskAuditChange struct {
	Task    *pm.Task
	Payload string
}

// diffPlanTaskFingerprints compares the incoming plan against the stored
// fingerprints and rewrites the fingerprint table to match, all inside tx.
//
// It returns the tasks whose audit payload changed, in plan order, plus the
// ids of tasks that disappeared. Callers emit after the transaction commits —
// an audit row must never describe a write that rolled back.
//
// A task with no stored fingerprint counts as changed. That is what makes the
// first save after migration 0027 re-establish a baseline (one row per task,
// once) and every save after it cost O(changed).
func diffPlanTaskFingerprints(tx *sql.Tx, tasks []*pm.Task) (changed []taskAuditChange, deleted []int, err error) {
	stored := make(map[int]string)
	rows, err := tx.Query(`SELECT task_id, fingerprint FROM audit_task_fingerprints`)
	if err != nil {
		return nil, nil, fmt.Errorf("read task fingerprints: %w", classifyDriverErr(err))
	}
	for rows.Next() {
		var (
			id int
			fp string
		)
		if err := rows.Scan(&id, &fp); err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("scan task fingerprint: %w", classifyDriverErr(err))
		}
		stored[id] = fp
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, fmt.Errorf("task fingerprint rows: %w", classifyDriverErr(err))
	}
	rows.Close()

	seen := make(map[int]bool, len(tasks))
	for _, t := range tasks {
		if t == nil {
			continue
		}
		seen[t.ID] = true
		payload := MarshalAuditPayload(t)
		fp := taskAuditFingerprint(payload)
		if prev, ok := stored[t.ID]; ok && prev == fp {
			continue
		}
		changed = append(changed, taskAuditChange{Task: t, Payload: payload})
		if _, err := tx.Exec(
			`INSERT INTO audit_task_fingerprints(task_id, fingerprint) VALUES (?,?)
			 ON CONFLICT(task_id) DO UPDATE SET fingerprint = excluded.fingerprint`,
			t.ID, fp,
		); err != nil {
			return nil, nil, fmt.Errorf("write task fingerprint %d: %w", t.ID, classifyDriverErr(err))
		}
	}

	for id := range stored {
		if !seen[id] {
			deleted = append(deleted, id)
			if _, err := tx.Exec(`DELETE FROM audit_task_fingerprints WHERE task_id = ?`, id); err != nil {
				return nil, nil, fmt.Errorf("drop task fingerprint %d: %w", id, classifyDriverErr(err))
			}
		}
	}
	return changed, deleted, nil
}

// recordTaskFingerprintTx stores the fingerprint for a single-task write.
//
// UpsertTask goes through here so its write and SaveState's diff agree on what
// was last emitted. Without it a single-task update would leave a stale
// fingerprint behind, and the next SaveState would either re-emit a change
// already recorded or — the damaging direction — see the stale value match and
// skip a real one.
func recordTaskFingerprintTx(tx *sql.Tx, taskID int, payload string) error {
	if _, err := tx.Exec(
		`INSERT INTO audit_task_fingerprints(task_id, fingerprint) VALUES (?,?)
		 ON CONFLICT(task_id) DO UPDATE SET fingerprint = excluded.fingerprint`,
		taskID, taskAuditFingerprint(payload),
	); err != nil {
		return fmt.Errorf("write task fingerprint %d: %w", taskID, classifyDriverErr(err))
	}
	return nil
}

// forgetTaskFingerprintTx drops a deleted task's fingerprint so that an id
// reused later starts from "never emitted" rather than inheriting the audit
// history of an unrelated task.
func forgetTaskFingerprintTx(tx *sql.Tx, taskID int) error {
	if _, err := tx.Exec(`DELETE FROM audit_task_fingerprints WHERE task_id = ?`, taskID); err != nil {
		return fmt.Errorf("drop task fingerprint %d: %w", taskID, classifyDriverErr(err))
	}
	return nil
}
