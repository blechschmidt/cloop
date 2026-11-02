package statedb

// requirements_status.go: what the project's database knows of where each
// approved requirement stands (Task 20463) — the facts of the requirement
// status summary its planners are given. See requirements.Standings.
//
// On a device the database is the run's own copy, seeded by the hub: its
// requirements table holds only the requirements the plan links, and its
// checks only the ones the run's own requirements gate made. So the seed also
// carries the hub's facts for every approved requirement, which are kept here
// in the metadata table (SeedRequirementStatus), and RequirementFacts lays the
// local checks over them. On the hub nothing seeds the key, and the facts are
// the database's own.

import (
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/requirements"
)

// requirementStatusKey is the metadata key a seed's requirement status is
// kept under.
const requirementStatusKey = "requirement_status"

// RequirementStandings is what this database records of each approved
// requirement — its latest verdict, and whether that verdict is about its
// current definition — most important first.
func (d *DB) RequirementStandings() ([]requirements.Standing, error) {
	reqs, err := d.Requirements()
	if err != nil {
		return nil, err
	}
	if len(reqs) == 0 {
		return nil, nil
	}
	latest, err := d.LatestRequirementChecks()
	if err != nil {
		return nil, err
	}
	held, err := d.lastHeld()
	if err != nil {
		return nil, err
	}
	last := make(map[int]requirements.LastCheck, len(latest))
	for _, r := range reqs {
		c, ok := latest[r.ID]
		if !ok {
			continue
		}
		last[r.ID] = requirements.LastCheck{Verdict: c.Verdict, Summary: c.Summary, Fingerprint: c.Fingerprint,
			CheckedAt: c.CheckedAt, HeldAt: held[heldKey{r.ID, r.Fingerprint()}]}
	}
	return requirements.Standings(reqs, last), nil
}

// heldKey is a requirement as one definition of it.
type heldKey struct {
	id          int
	fingerprint string
}

// lastHeld is when each requirement, as each definition it has had, was last
// found fulfilled: what tells a failure since from one before (Task 20463).
func (d *DB) lastHeld() (map[heldKey]time.Time, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT requirement_id, fingerprint, MAX(checked_at) FROM requirement_checks
		WHERE verdict = ? GROUP BY requirement_id, fingerprint`, requirements.VerdictFulfilled)
	if err != nil {
		return nil, fmt.Errorf("statedb: read when requirements last held: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	out := map[heldKey]time.Time{}
	for rows.Next() {
		var (
			id     int
			fp, at string
		)
		if err := rows.Scan(&id, &fp, &at); err != nil {
			return nil, fmt.Errorf("statedb: read when requirements last held: %w", classifyDriverErr(err))
		}
		out[heldKey{id, fp}] = parseReqTime(at)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read when requirements last held: %w", classifyDriverErr(err))
	}
	return out, nil
}

// SeedRequirementStatus keeps the facts a project seed carries of the hub's
// requirements (Task 20463), for the run on a device to plan from. An empty
// summary clears them.
func (d *DB) SeedRequirementStatus(sum requirements.StatusSummary) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if sum.Empty() {
		if _, err := d.conn.Exec(`DELETE FROM metadata WHERE key = ?`, requirementStatusKey); err != nil {
			return fmt.Errorf("statedb: clear the seeded requirement status: %w", classifyDriverErr(err))
		}
		return nil
	}
	raw, err := sum.EncodeFacts()
	if err != nil {
		return fmt.Errorf("statedb: encode the seeded requirement status: %w", err)
	}
	if _, err := d.conn.Exec(`INSERT INTO metadata(key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, requirementStatusKey, string(raw)); err != nil {
		return fmt.Errorf("statedb: keep the seeded requirement status: %w", classifyDriverErr(err))
	}
	return nil
}

// seededRequirementStatus reads what SeedRequirementStatus kept. A value
// that does not read is reported, never guessed at.
func (d *DB) seededRequirementStatus() (requirements.StatusSummary, error) {
	d.mu.Lock()
	raw, err := d.getMeta(requirementStatusKey)
	d.mu.Unlock()
	if err != nil {
		return requirements.StatusSummary{}, fmt.Errorf("statedb: read the seeded requirement status: %w", classifyDriverErr(err))
	}
	if raw == "" {
		return requirements.StatusSummary{}, nil
	}
	sum, err := requirements.ParseStatusSummary([]byte(raw))
	if err != nil {
		return requirements.StatusSummary{}, fmt.Errorf("statedb: the seeded requirement status: %w", err)
	}
	return sum, nil
}

// RequirementFacts is what this project knows of where each approved
// requirement stands: this database's own record, laid over what a seed
// carried from the hub when there is one. omitted counts the approved
// requirements the seed left out to fit.
func (d *DB) RequirementFacts() (facts []requirements.Standing, omitted int, err error) {
	local, err := d.RequirementStandings()
	if err != nil {
		return nil, 0, err
	}
	seeded, err := d.seededRequirementStatus()
	if err != nil {
		return nil, 0, err
	}
	if seeded.Empty() {
		return local, 0, nil
	}
	merged, unknown := requirements.MergeStandings(seeded.Facts().Requirements, local)
	// A requirement the seed cut is one of those it says it omitted.
	return merged, max(seeded.Omitted, unknown), nil
}
