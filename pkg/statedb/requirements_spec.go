package statedb

// requirements_spec.go: what the hub knows of a project's requirements spec
// file, and the base its three-way merge runs against (Task 20459; migration
// 0086). The file format is pkg/requirements/specfile.go, the merge
// pkg/requirements/merge.go.
//
// Three writers move the base. An import makes it the file it imported: the
// file is what was merged from, so a requirement the import left as the hub
// had it — a change only the hub made, a conflict settled for the hub — next
// reads as the hub's change, which an export writes. An export makes it what
// it wrote. And a read of the file makes it every requirement the file and the
// hub hold alike: they agree, whatever either held before. Each writes in one
// transaction with what it is based on, so a merge never sees a base that does
// not match the requirements it was taken with.

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
)

// The slots of requirement_spec_files.
const (
	specSlotRead    = "read"
	specSlotSync    = "sync"
	specSlotAttempt = "attempt"
)

// Directions of a sync.
const (
	RequirementSpecImported = "import"
	RequirementSpecExported = "export"
)

// RequirementSpecRead is the project's spec file as the hub last read it from
// the project's checkout, through the project's executor.
type RequirementSpecRead struct {
	ReadAt     time.Time `json:"read_at"`
	ReadBy     string    `json:"read_by,omitempty"`
	ExecutorID string    `json:"executor_id,omitempty"`
	Path       string    `json:"path"`
	// Found reports that the checkout has the file.
	Found bool `json:"found"`
	// Content is the file's bytes, at most requirements.MaxSpecFileBytes.
	Content []byte `json:"-"`
	SHA256  string `json:"sha256,omitempty"`
	// Commit is HEAD of the checkout; Dirty reports that the file differs
	// from it, Ignored that git ignores it — so it reaches no other checkout.
	Commit  string `json:"commit,omitempty"`
	Dirty   bool   `json:"dirty,omitempty"`
	Ignored bool   `json:"ignored,omitempty"`
	// Error says why the file could not be sent whole.
	Error string `json:"error,omitempty"`
}

// RequirementSpecAttempt is the last attempt to read the spec file, whether
// or not it got one: an attempt that failed — the executor unreachable, its
// cloop too old — leaves the last read standing and says why.
type RequirementSpecAttempt struct {
	At         time.Time `json:"at"`
	By         string    `json:"by,omitempty"`
	ExecutorID string    `json:"executor_id,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// RequirementSpecSync is the last import or export of the spec file.
type RequirementSpecSync struct {
	Direction string    `json:"direction"`
	At        time.Time `json:"at"`
	Actor     string    `json:"actor,omitempty"`
	// Source is where it was done: dashboard or cli.
	Source string `json:"source,omitempty"`
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Commit string `json:"commit,omitempty"`
}

// RequirementSpecSnapshot is what a merge runs against, read together: the
// hub's requirements, the base, and the highest id the hub ever gave one.
type RequirementSpecSnapshot struct {
	Hub      []requirements.Requirement
	Base     []requirements.Requirement
	Assigned int
}

// RequirementSpecImport is one import of a spec file.
type RequirementSpecImport struct {
	// File is the spec file's requirements, as ParseSpecFile read them.
	File []requirements.Requirement
	// Sync says where the file came from and who imported it; its Direction
	// and At are set by the import.
	Sync RequirementSpecSync
	// Resolutions settle conflicts: requirements.TakeFile or KeepHub, by id.
	Resolutions map[int]string
	// Digest is the plan the importer reviewed. When it is given and the
	// merge now plans something else, nothing is imported.
	Digest string
	// DryRun plans the import and writes nothing.
	DryRun bool
}

// RequirementSpecImportResult is what an import found, and what it did.
type RequirementSpecImportResult struct {
	Plan  requirements.Plan   `json:"plan"`
	Steps []requirements.Step `json:"steps"`
	// ChecksDeleted counts the recorded checks deleted with each requirement
	// the import deleted.
	ChecksDeleted map[int]int64 `json:"checks_deleted,omitempty"`
	// Unlinked are the tasks each requirement the import deleted was taken
	// out of (Task 20460), as they are after it.
	Unlinked map[int][]*pm.Task `json:"-"`
}

const requirementSpecFileColumns = `at, actor, source, direction, executor_id, path, found, content, sha256, git_commit,
	dirty, ignored, error`

// upsertSpecSlot writes one row of requirement_spec_files.
func upsertSpecSlot(tx *sql.Tx, slot string, at time.Time, actor, source, direction, executorID, path string, found bool,
	content []byte, sha, commit string, dirty, ignored bool, errText string) error {
	_, err := tx.Exec(`INSERT INTO requirement_spec_files
		(slot, `+requirementSpecFileColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(slot) DO UPDATE SET at = excluded.at, actor = excluded.actor, source = excluded.source,
			direction = excluded.direction, executor_id = excluded.executor_id, path = excluded.path,
			found = excluded.found, content = excluded.content, sha256 = excluded.sha256,
			git_commit = excluded.git_commit, dirty = excluded.dirty, ignored = excluded.ignored, error = excluded.error`,
		slot, formatReqTime(at), clipActor(actor), clipText(source, 32), clipText(direction, 16), clipText(executorID, 256),
		clipText(path, 1024), boolInt(found), content, clipText(sha, 64), clipText(requirements.CleanCommit(commit), 64),
		boolInt(dirty), boolInt(ignored), clipText(errText, 2048))
	if err != nil {
		return fmt.Errorf("statedb: record the requirements spec file: %w", classifyDriverErr(err))
	}
	return nil
}

// SaveRequirementSpecRead records rd as the latest read of the project's spec
// file. file, the requirements in it when it parsed (nil otherwise), moves
// the base: a requirement the file and the hub hold alike is agreed on, and
// one neither holds any more is forgotten.
func (d *DB) SaveRequirementSpecRead(rd RequirementSpecRead, file []requirements.Requirement) error {
	if len(rd.Content) > requirements.MaxSpecFileBytes {
		return fmt.Errorf("statedb: a spec file of %d bytes is more than %d", len(rd.Content), requirements.MaxSpecFileBytes)
	}
	if rd.ReadAt.IsZero() {
		rd.ReadAt = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: record the requirements spec file: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after a commit
	if err := upsertSpecSlot(tx, specSlotRead, rd.ReadAt, rd.ReadBy, "", "", rd.ExecutorID, rd.Path, rd.Found,
		rd.Content, rd.SHA256, rd.Commit, rd.Dirty, rd.Ignored, rd.Error); err != nil {
		return err
	}
	if err := upsertSpecSlot(tx, specSlotAttempt, rd.ReadAt, rd.ReadBy, "", "", rd.ExecutorID, rd.Path, false,
		nil, "", "", false, false, ""); err != nil {
		return err
	}
	if file != nil {
		if err := agreeOnSpecBaseTx(tx, file, rd.ReadAt); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: record the requirements spec file: %w", classifyDriverErr(err))
	}
	return nil
}

// agreeOnSpecBaseTx moves the base to every requirement the file and the hub
// hold alike, and forgets the ones neither holds.
func agreeOnSpecBaseTx(tx *sql.Tx, file []requirements.Requirement, at time.Time) error {
	hub, err := queryRequirements(tx, `ORDER BY id`)
	if err != nil {
		return err
	}
	base, err := querySpecBase(tx)
	if err != nil {
		return err
	}
	inFile := make(map[int]requirements.Requirement, len(file))
	for _, r := range file {
		inFile[r.ID] = r
	}
	inHub := make(map[int]bool, len(hub))
	var agreed []requirements.Requirement
	for _, r := range hub {
		inHub[r.ID] = true
		if f, ok := inFile[r.ID]; ok && requirements.SameSpec(r, f) {
			agreed = append(agreed, f)
		}
	}
	if err := upsertSpecBaseTx(tx, agreed, at); err != nil {
		return err
	}
	var gone []int
	for _, b := range base {
		if _, ok := inFile[b.ID]; !ok && !inHub[b.ID] {
			gone = append(gone, b.ID)
		}
	}
	return deleteSpecBaseTx(tx, gone)
}

// upsertSpecBaseTx records reqs as agreed on.
func upsertSpecBaseTx(tx *sql.Tx, reqs []requirements.Requirement, at time.Time) error {
	for _, r := range reqs {
		def := r.SpecCopy()
		def.Status = def.CurrentStatus()
		raw, err := json.Marshal(def)
		if err != nil {
			return fmt.Errorf("statedb: record the requirements spec base: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO requirement_spec_base (requirement_id, definition, fingerprint, synced_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(requirement_id) DO UPDATE SET definition = excluded.definition,
				fingerprint = excluded.fingerprint, synced_at = excluded.synced_at`,
			r.ID, string(raw), def.SyncFingerprint(), formatReqTime(at)); err != nil {
			return fmt.Errorf("statedb: record the requirements spec base: %w", classifyDriverErr(err))
		}
	}
	return nil
}

// deleteSpecBaseTx forgets the base of ids.
func deleteSpecBaseTx(tx *sql.Tx, ids []int) error {
	for _, id := range ids {
		if _, err := tx.Exec(`DELETE FROM requirement_spec_base WHERE requirement_id = ?`, id); err != nil {
			return fmt.Errorf("statedb: forget the requirements spec base: %w", classifyDriverErr(err))
		}
	}
	return nil
}

// replaceSpecBaseTx makes the base exactly reqs: each recorded, then every
// other forgotten.
func replaceSpecBaseTx(tx *sql.Tx, reqs []requirements.Requirement, at time.Time) error {
	if err := upsertSpecBaseTx(tx, reqs, at); err != nil {
		return err
	}
	keep := make(map[int]bool, len(reqs))
	for _, r := range reqs {
		keep[r.ID] = true
	}
	base, err := querySpecBase(tx)
	if err != nil {
		return err
	}
	var gone []int
	for _, b := range base {
		if !keep[b.ID] {
			gone = append(gone, b.ID)
		}
	}
	return deleteSpecBaseTx(tx, gone)
}

// querySpecBase reads the base. A row that does not read as a requirement —
// written by something other than this package — is left out: a requirement
// with no base is merged as one both sides added, which can conflict but
// never silently overwrites.
func querySpecBase(q requirementQuerier) ([]requirements.Requirement, error) {
	rows, err := q.Query(`SELECT requirement_id, definition FROM requirement_spec_base ORDER BY requirement_id LIMIT ?`,
		4*requirements.MaxRequirements)
	if err != nil {
		return nil, fmt.Errorf("statedb: read the requirements spec base: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []requirements.Requirement
	for rows.Next() {
		var (
			id  int
			def string
		)
		if err := rows.Scan(&id, &def); err != nil {
			return nil, fmt.Errorf("statedb: read the requirements spec base: %w", classifyDriverErr(err))
		}
		var r requirements.Requirement
		if len(def) > requirements.MaxEncodedBytes*2 || json.Unmarshal([]byte(def), &r) != nil {
			continue
		}
		r.ID = id
		if r.Normalize() != nil {
			continue
		}
		r.Status = r.CurrentStatus()
		out = append(out, r.SpecCopy())
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read the requirements spec base: %w", classifyDriverErr(err))
	}
	return out, nil
}

// assignedRequirementIDTx is the highest id the hub has given a requirement:
// AUTOINCREMENT's record of it, or the highest id held, whichever is higher.
func assignedRequirementIDTx(q interface {
	QueryRow(query string, args ...any) *sql.Row
}) (int, error) {
	var seq, maxID int
	err := q.QueryRow(`SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'requirements'), 0),
		COALESCE((SELECT MAX(id) FROM requirements), 0)`).Scan(&seq, &maxID)
	if err != nil {
		return 0, fmt.Errorf("statedb: read the requirement ids: %w", classifyDriverErr(err))
	}
	return max(seq, maxID), nil
}

// RecordRequirementSpecAttempt records an attempt to read the spec file that
// got nothing, and why; the last read stands.
func (d *DB) RecordRequirementSpecAttempt(a RequirementSpecAttempt) error {
	if a.At.IsZero() {
		a.At = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: record the requirements spec read: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after a commit
	if err := upsertSpecSlot(tx, specSlotAttempt, a.At, a.By, "", "", a.ExecutorID, "", false, nil, "", "", false,
		false, a.Error); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: record the requirements spec read: %w", classifyDriverErr(err))
	}
	return nil
}

// LastRequirementSpecAttempt returns the last attempt to read the spec file,
// if there was one.
func (d *DB) LastRequirementSpecAttempt() (RequirementSpecAttempt, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var (
		a                               RequirementSpecAttempt
		at, actor, source, dir, ex, pth string
		found, dirty, ignored           int
		content                         []byte
		sha, commit, errText            string
	)
	err := d.conn.QueryRow(`SELECT `+requirementSpecFileColumns+` FROM requirement_spec_files WHERE slot = ?`, specSlotAttempt).
		Scan(&at, &actor, &source, &dir, &ex, &pth, &found, &content, &sha, &commit, &dirty, &ignored, &errText)
	if errors.Is(err, sql.ErrNoRows) {
		return a, false, nil
	}
	if err != nil {
		return a, false, fmt.Errorf("statedb: read the last requirements spec read: %w", classifyDriverErr(err))
	}
	a.At, a.By, a.ExecutorID = parseReqTime(at), clipText(actor, 4*requirements.MaxActorRunes), clipText(ex, 256)
	a.Error = clipText(errText, 2048)
	return a, true, nil
}

// RequirementSpecRead returns the latest read of the spec file, if there is
// one. Its content is bounded on the way out as on the way in.
func (d *DB) RequirementSpecRead() (RequirementSpecRead, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var (
		rd                       RequirementSpecRead
		at, actor, source, dir   string
		found, dirty, ignored    int
		content                  []byte
		sha, commit, errText, ex string
	)
	err := d.conn.QueryRow(`SELECT `+requirementSpecFileColumns+` FROM requirement_spec_files WHERE slot = ?`, specSlotRead).
		Scan(&at, &actor, &source, &dir, &ex, &rd.Path, &found, &content, &sha, &commit, &dirty, &ignored, &errText)
	if errors.Is(err, sql.ErrNoRows) {
		return rd, false, nil
	}
	if err != nil {
		return rd, false, fmt.Errorf("statedb: read the requirements spec file: %w", classifyDriverErr(err))
	}
	rd.ReadAt, rd.ReadBy, rd.ExecutorID = parseReqTime(at), clipText(actor, 4*requirements.MaxActorRunes), clipText(ex, 256)
	rd.Path = clipText(rd.Path, 1024)
	rd.Found, rd.Dirty, rd.Ignored = found != 0, dirty != 0, ignored != 0
	rd.SHA256, rd.Commit, rd.Error = clipText(sha, 64), requirements.CleanCommit(commit), clipText(errText, 2048)
	if len(content) <= requirements.MaxSpecFileBytes {
		rd.Content = content
	} else if rd.Error == "" {
		rd.Error = "the stored file is larger than a spec file may be"
	}
	return rd, true, nil
}

// LastRequirementSpecSync returns the last import or export, if there was one.
func (d *DB) LastRequirementSpecSync() (RequirementSpecSync, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var (
		s                             RequirementSpecSync
		at, ex, sha, commit, errText  string
		found, dirty, ignored         int
		content                       []byte
		actor, source, direction, pth string
	)
	err := d.conn.QueryRow(`SELECT `+requirementSpecFileColumns+` FROM requirement_spec_files WHERE slot = ?`, specSlotSync).
		Scan(&at, &actor, &source, &direction, &ex, &pth, &found, &content, &sha, &commit, &dirty, &ignored, &errText)
	if errors.Is(err, sql.ErrNoRows) {
		return s, false, nil
	}
	if err != nil {
		return s, false, fmt.Errorf("statedb: read the last requirements sync: %w", classifyDriverErr(err))
	}
	s.Direction, s.At = clipText(direction, 16), parseReqTime(at)
	s.Actor, s.Source = clipText(actor, 4*requirements.MaxActorRunes), clipText(source, 32)
	s.Path, s.SHA256, s.Commit = clipText(pth, 1024), clipText(sha, 64), requirements.CleanCommit(commit)
	return s, true, nil
}

// RequirementSpecSnapshot reads what a merge runs against, in one
// transaction.
func (d *DB) RequirementSpecSnapshot() (RequirementSpecSnapshot, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return RequirementSpecSnapshot{}, fmt.Errorf("statedb: read the requirements: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck // read-only
	return specSnapshotTx(tx)
}

func specSnapshotTx(tx *sql.Tx) (RequirementSpecSnapshot, error) {
	var snap RequirementSpecSnapshot
	var err error
	if snap.Hub, err = queryRequirements(tx, `ORDER BY id LIMIT ?`, requirements.MaxRequirements); err != nil {
		return snap, err
	}
	if snap.Base, err = querySpecBase(tx); err != nil {
		return snap, err
	}
	snap.Assigned, err = assignedRequirementIDTx(tx)
	return snap, err
}

// ImportRequirementSpec merges in.File into the project's requirements and,
// unless in.DryRun, applies the merge: in one transaction it plans against the
// requirements and base as they are in it, refuses a plan other than the one
// reviewed (ErrRequirementSpecChanged) or one with a conflict left unsettled
// (a *requirements.ConflictError, an ErrSpecConflict), writes the steps, makes
// the file the base and records the import. Nothing is imported in part. The
// result carries the plan whether or not it was applied.
func (d *DB) ImportRequirementSpec(in RequirementSpecImport) (RequirementSpecImportResult, error) {
	var res RequirementSpecImportResult
	now := time.Now().UTC()
	in.Sync.Direction, in.Sync.At = RequirementSpecImported, now
	actor := clipActor(in.Sync.Actor)

	d.mu.Lock()
	tx, err := d.conn.Begin()
	if err != nil {
		d.mu.Unlock()
		return res, fmt.Errorf("statedb: import requirements: %w", classifyDriverErr(err))
	}
	err = func() error {
		snap, err := specSnapshotTx(tx)
		if err != nil {
			return err
		}
		res.Plan = requirements.Merge(snap.Base, snap.Hub, in.File, snap.Assigned)
		if in.Digest != "" && subtle.ConstantTimeCompare([]byte(in.Digest), []byte(res.Plan.Digest)) != 1 {
			return ErrRequirementSpecChanged
		}
		steps, err := res.Plan.Resolve(in.Resolutions)
		if err != nil {
			return err
		}
		res.Steps = steps
		if in.DryRun {
			return nil
		}
		held := len(snap.Hub)
		for _, s := range steps {
			switch s.Action {
			case requirements.ActionAdd, requirements.ActionRestore:
				held++
			case requirements.ActionDelete:
				held--
			}
		}
		if held > requirements.MaxRequirements {
			return fmt.Errorf("%w: the import would leave %d requirements, more than the %d a project holds",
				requirements.ErrInvalid, held, requirements.MaxRequirements)
		}
		if res.ChecksDeleted, res.Unlinked, err = applySpecStepsTx(tx, steps, actor, now); err != nil {
			return err
		}
		if err := replaceSpecBaseTx(tx, in.File, now); err != nil {
			return err
		}
		if err := upsertSpecSlot(tx, specSlotSync, now, actor, in.Sync.Source, RequirementSpecImported, "",
			in.Sync.Path, true, nil, in.Sync.SHA256, in.Sync.Commit, false, false, ""); err != nil {
			return err
		}
		return tx.Commit()
	}()
	if err != nil || in.DryRun {
		_ = tx.Rollback()
	}
	d.mu.Unlock()
	if err != nil {
		return res, err
	}
	if !in.DryRun {
		auditRequirementImport(d, in, res)
		for _, st := range res.Steps {
			if importApproves(st) {
				r := st.Requirement
				r.ApprovedBy = clipActor(actor)
				was := requirements.StatusDraft
				if st.Previous != nil {
					was = st.Previous.CurrentStatus()
				}
				auditRequirementApprove(d, r, was, actor, "import")
			}
		}
		for _, id := range slices.Sorted(maps.Keys(res.Unlinked)) {
			for _, t := range res.Unlinked[id] {
				auditTaskUpsert(d, t, actorOrSystem(in.Sync.Actor))
			}
		}
	}
	return res, nil
}

// applySpecStepsTx writes an import's steps, which Resolve ordered: the
// requirements added and restored, then those updated, then those deleted —
// each deleted with the history of its checks and taken out of the tasks that
// implemented it, as DeleteRequirement does. It returns the checks deleted and
// the tasks unlinked, by requirement.
func applySpecStepsTx(tx *sql.Tx, steps []requirements.Step, actor string, now time.Time) (map[int]int64, map[int][]*pm.Task, error) {
	for _, s := range steps {
		if s.Action != requirements.ActionAdd && s.Action != requirements.ActionRestore {
			continue
		}
		r := s.Requirement
		// Imported approved, it was approved by whoever imported it.
		approvedBy, approvedAt := "", ""
		if r.CurrentStatus() == requirements.StatusApproved {
			approvedBy, approvedAt = actor, formatReqTime(now)
		}
		if _, err := tx.Exec(`INSERT INTO requirements
			(id, title, description, priority, tags, tests, created_at, updated_at, created_by, updated_by, status,
			 approved_by, approved_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.ID, r.Title, r.Description, r.Priority, marshalJSONColumn(r.Tags, "[]"), marshalJSONColumn(r.Tests, "[]"),
			formatReqTime(now), formatReqTime(now), actor, actor, r.CurrentStatus(), approvedBy, approvedAt); err != nil {
			return nil, nil, fmt.Errorf("statedb: import %s: %w", requirements.Key(r.ID), classifyDriverErr(err))
		}
	}
	for _, s := range steps {
		if s.Action != requirements.ActionUpdate {
			continue
		}
		r := s.Requirement
		res, err := tx.Exec(`UPDATE requirements SET title = ?, description = ?, priority = ?, tags = ?, tests = ?,
			status = ?, updated_at = ?, updated_by = ? WHERE id = ?`,
			r.Title, r.Description, r.Priority, marshalJSONColumn(r.Tags, "[]"), marshalJSONColumn(r.Tests, "[]"),
			r.CurrentStatus(), formatReqTime(now), actor, r.ID)
		if err != nil {
			return nil, nil, fmt.Errorf("statedb: import %s: %w", requirements.Key(r.ID), classifyDriverErr(err))
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return nil, nil, fmt.Errorf("%w: %s", ErrRequirementNotFound, requirements.Key(r.ID))
		}
		// A file that approves a requirement approves it as whoever
		// imported it (Task 20462); one that takes it out of approved takes
		// the approval back.
		switch {
		case importApproves(s):
			_, err = tx.Exec(`UPDATE requirements SET approved_by = ?, approved_at = ? WHERE id = ?`, actor, formatReqTime(now), r.ID)
		case r.CurrentStatus() != requirements.StatusApproved:
			_, err = tx.Exec(`UPDATE requirements SET approved_by = '', approved_at = '' WHERE id = ?`, r.ID)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("statedb: import %s: %w", requirements.Key(r.ID), classifyDriverErr(err))
		}
	}
	deleted := map[int]int64{}
	unlinked := map[int][]*pm.Task{}
	for _, s := range steps {
		if s.Action != requirements.ActionDelete {
			continue
		}
		id := s.Requirement.ID
		if _, err := tx.Exec(`DELETE FROM requirements WHERE id = ?`, id); err != nil {
			return nil, nil, fmt.Errorf("statedb: import: delete %s: %w", requirements.Key(id), classifyDriverErr(err))
		}
		res, err := tx.Exec(`DELETE FROM requirement_checks WHERE requirement_id = ?`, id)
		if err != nil {
			return nil, nil, fmt.Errorf("statedb: import: delete the checks of %s: %w", requirements.Key(id), classifyDriverErr(err))
		}
		deleted[id], _ = res.RowsAffected()
		tasks, err := unlinkRequirementTx(tx, id)
		if err != nil {
			return nil, nil, err
		}
		if len(tasks) > 0 {
			unlinked[id] = tasks
		}
	}
	return deleted, unlinked, nil
}

// importApproves reports whether an import's update step makes a requirement
// approved that was not.
func importApproves(s requirements.Step) bool {
	return s.Action == requirements.ActionUpdate && s.Requirement.CurrentStatus() == requirements.StatusApproved &&
		(s.Previous == nil || s.Previous.CurrentStatus() != requirements.StatusApproved)
}

// auditRequirementImport records an import in the project's trail: what it
// added, changed, restored and deleted, and how each conflict was settled.
func auditRequirementImport(d *DB, in RequirementSpecImport, res RequirementSpecImportResult) {
	var (
		added, restored []int
		updated         []map[string]any
		deleted         []map[string]any
	)
	changes := map[int]requirements.Change{}
	for _, c := range res.Plan.Changes {
		changes[c.ID] = c
	}
	for _, s := range res.Steps {
		r := s.Requirement
		switch s.Action {
		case requirements.ActionAdd:
			added = append(added, r.ID)
		case requirements.ActionRestore:
			restored = append(restored, r.ID)
		case requirements.ActionUpdate:
			row := map[string]any{"id": r.ID, "title": r.Title, "fingerprint": r.Fingerprint()}
			if s.Previous != nil {
				row["changed"] = changedRequirementFields(*s.Previous, r)
				row["previous_fingerprint"] = s.Previous.Fingerprint()
			}
			if c, ok := changes[r.ID]; ok {
				row["kind"] = c.Kind
			}
			updated = append(updated, row)
		case requirements.ActionDelete:
			row := map[string]any{"id": r.ID, "title": r.Title, "checks": res.ChecksDeleted[r.ID]}
			if tasks := res.Unlinked[r.ID]; len(tasks) > 0 {
				ids := make([]int, len(tasks))
				for i, t := range tasks {
					ids[i] = t.ID
				}
				row["unlinked_tasks"] = ids
			}
			deleted = append(deleted, row)
		}
	}
	resolved := map[string]string{}
	ids := make([]int, 0, len(in.Resolutions))
	for id := range in.Resolutions {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		resolved[requirements.Key(id)] = in.Resolutions[id]
	}
	emit(d, &AuditEvent{
		Actor: actorOrSystem(in.Sync.Actor), EventType: string(auditaction.ActionRequirementImport),
		EntityType: "requirement", EntityID: "spec",
		Payload: MarshalAuditPayload(map[string]any{
			"source":          in.Sync.Source,
			"path":            in.Sync.Path,
			"sha256":          in.Sync.SHA256,
			"commit":          requirements.CleanCommit(in.Sync.Commit),
			"added":           added,
			"restored":        restored,
			"updated":         updated,
			"deleted":         deleted,
			"resolved":        resolved,
			"in_sync":         res.Plan.InSync,
			"exports_pending": res.Plan.Exports,
		}),
	})
}

// RecordRequirementSpecExport records that the project's spec file was
// written with exported: they become the base, and the export the last sync.
func (d *DB) RecordRequirementSpecExport(exported []requirements.Requirement, sync RequirementSpecSync) error {
	now := time.Now().UTC()
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: record the requirements export: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after a commit
	if err := replaceSpecBaseTx(tx, exported, now); err != nil {
		return err
	}
	if err := upsertSpecSlot(tx, specSlotSync, now, sync.Actor, sync.Source, RequirementSpecExported, "", sync.Path,
		true, nil, sync.SHA256, sync.Commit, false, false, ""); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: record the requirements export: %w", classifyDriverErr(err))
	}
	return nil
}
