package requirements

// merge.go: reconciling the hub's requirements with the spec file (Task 20459).
//
// Once a project keeps a spec file its requirements live in two places: the
// hub's database, which the dashboard and `cloop requirements` change, and
// .cloop/requirements.yaml, which a pull request changes. Either may change
// while the other does not know, so neither may simply overwrite the other: an
// import that wrote the file over the hub would undo a requirement somebody
// tightened in the dashboard, and an export that wrote the hub over the file
// would undo the pull request.
//
// So the two are merged as version control merges, three ways, against the
// base: the definitions both last agreed on, which the hub records at every
// import and export, and whenever it reads a file that agrees with it
// (statedb's requirement_spec_base). For each id:
//
//	hub and file agree                  in sync
//	only the file changed it            import: add, update or delete it in the hub
//	only the hub changed it             export: the file is behind
//	both changed it, in different       import the merge: each side's change to
//	  fields                              the fields it alone changed
//	both changed the same field, or     conflict: reported, and settled only by
//	  one deleted what the other          somebody choosing — never silently
//	  changed, or both added it apart     overwritten
//	the file adds an id the hub gave    refused: an id names one requirement for
//	  a requirement since deleted         good, so a second may not take it
//
// "Changed" is decided by SyncFingerprint — the Fingerprint a verdict is
// recorded against, with the priority, tags and status the file adds — and
// only a requirement whose three fingerprints all differ is merged field by
// field.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Kinds of difference between the hub and the spec file.
const (
	// ChangeImport: only the file changed the requirement; importing applies
	// the change to the hub.
	ChangeImport = "import"
	// ChangeExport: only the hub changed it; the file is behind until an
	// export writes it.
	ChangeExport = "export"
	// ChangeMerge: both changed it, in different fields; importing applies
	// the merge of the two.
	ChangeMerge = "merge"
	// ChangeConflict: both changed the same field, one deleted what the other
	// changed, or both added it differently. Importing needs a choice.
	ChangeConflict = "conflict"
	// ChangeRefused: the file gives a new requirement an id the hub gave one
	// it has since deleted.
	ChangeRefused = "refused"
)

// What importing a change does to the hub.
const (
	ActionAdd    = "add"
	ActionUpdate = "update"
	ActionDelete = "delete"
	// ActionRestore re-creates, under its own id, a requirement the hub
	// deleted, because a conflict was settled for the file that still has it.
	ActionRestore = "restore"
)

// How a conflict is settled.
const (
	// TakeFile makes the requirement exactly what the file says.
	TakeFile = "file"
	// KeepHub leaves the hub's requirement as it is; the next export writes it
	// to the file.
	KeepHub = "hub"
)

// SpecFields are the fields a spec file holds, as a merge names them.
var SpecFields = []string{"title", "details", "priority", "tags", "tests", "status"}

// ErrSpecConflict is what importing a spec file that conflicts with the hub
// fails with, unless every conflict was settled.
var ErrSpecConflict = errors.New("the spec file conflicts with the hub")

// Change is one requirement on which the hub and the spec file differ.
type Change struct {
	ID   int    `json:"id"`
	Kind string `json:"kind"`
	// Action is what importing does to the hub, for a change that does
	// something without a choice: add, update or delete.
	Action string `json:"action,omitempty"`
	// Fields are those in which the hub and the file differ.
	Fields []string `json:"fields,omitempty"`
	// Conflicts are the fields both changed, or "deleted" when one side
	// deleted what the other changed.
	Conflicts []string `json:"conflicts,omitempty"`
	// Reason says what happened, for people.
	Reason string `json:"reason"`
	// The requirement as the hub has it, as the file has it, as both last
	// agreed on, and — for a merge — as importing writes it.
	Hub    *Requirement `json:"hub,omitempty"`
	File   *Requirement `json:"file,omitempty"`
	Base   *Requirement `json:"base,omitempty"`
	Merged *Requirement `json:"merged,omitempty"`
	// Stales reports that importing it changes what the requirement says or
	// how it is tested, so the verdicts recorded before go stale.
	Stales bool `json:"stales,omitempty"`
}

// Plan is what merging the spec file into the hub finds: every requirement on
// which they differ, in id order, and the tallies.
type Plan struct {
	Changes []Change `json:"changes"`
	// InSync counts the requirements both hold alike.
	InSync int `json:"in_sync"`
	// Imports counts the changes importing applies without a question.
	Imports int `json:"imports"`
	// Exports counts the changes only the hub has.
	Exports   int `json:"exports"`
	Conflicts int `json:"conflicts"`
	Refused   int `json:"refused"`
	// Digest identifies what importing this plan would do, so a person who
	// reviewed one plan does not import another.
	Digest string `json:"digest"`
}

// Step is one write importing makes to the hub.
type Step struct {
	Action      string      `json:"action"`
	Requirement Requirement `json:"requirement"`
	// Previous is the hub's requirement an update or delete replaces.
	Previous *Requirement `json:"previous,omitempty"`
}

// Merge merges file, the spec file's requirements, into hub, the hub's,
// against base, what both last agreed on. assigned is the highest id the hub
// has ever given a requirement: a file may add a requirement only under an id
// above it, or under the id of one it shares a history with.
func Merge(base, hub, file []Requirement, assigned int) Plan {
	b, d, f := specByID(base), specByID(hub), specByID(file)
	ids := make([]int, 0, len(b)+len(d)+len(f))
	for _, m := range []map[int]*Requirement{b, d, f} {
		for id := range m {
			ids = append(ids, id)
		}
	}
	sort.Ints(ids)
	ids = slices.Compact(ids)

	p := Plan{Changes: []Change{}}
	for _, id := range ids {
		c, inSync := mergeOne(id, b[id], d[id], f[id], assigned)
		if inSync {
			p.InSync++
			continue
		}
		if c == nil {
			continue
		}
		switch c.Kind {
		case ChangeImport, ChangeMerge:
			p.Imports++
		case ChangeExport:
			p.Exports++
		case ChangeConflict:
			p.Conflicts++
		case ChangeRefused:
			p.Refused++
		}
		p.Changes = append(p.Changes, *c)
	}
	p.Digest = p.digest()
	return p
}

// specByID indexes reqs by id, each as a spec file holds it.
func specByID(reqs []Requirement) map[int]*Requirement {
	out := make(map[int]*Requirement, len(reqs))
	for _, r := range reqs {
		c := r.SpecCopy()
		c.Status = c.CurrentStatus()
		out[r.ID] = &c
	}
	return out
}

func mergeOne(id int, b, d, f *Requirement, assigned int) (*Change, bool) {
	switch {
	case d != nil && f != nil && SameSpec(*d, *f):
		return nil, true
	case d == nil && f == nil:
		// Gone from both: nothing to do but forget the base.
		return nil, false
	}
	c := &Change{ID: id, Base: b, Hub: d, File: f}
	switch {
	case b == nil && d == nil:
		if id <= assigned {
			c.Kind = ChangeRefused
			c.Reason = fmt.Sprintf("added in the file under %s, the id of a requirement the hub has since deleted; "+
				"an id is never given to a second requirement, so number it past R-%d", Key(id), assigned)
			return c, false
		}
		c.Kind, c.Action, c.Reason = ChangeImport, ActionAdd, "added in the file"
	case b == nil && f == nil:
		c.Kind, c.Reason = ChangeExport, "added in the hub"
	case b == nil:
		c.Kind, c.Fields = ChangeConflict, diffFields(*d, *f)
		c.Conflicts = c.Fields
		c.Reason = "added in both the hub and the file, differently: " + strings.Join(c.Fields, ", ")
	case d == nil:
		if SameSpec(*f, *b) {
			c.Kind, c.Reason = ChangeExport, "deleted in the hub"
			break
		}
		c.Kind, c.Fields, c.Conflicts = ChangeConflict, diffFields(*b, *f), []string{"deleted"}
		c.Reason = "deleted in the hub and changed in the file: " + strings.Join(c.Fields, ", ")
	case f == nil:
		if SameSpec(*d, *b) {
			c.Kind, c.Action, c.Reason = ChangeImport, ActionDelete, "deleted in the file"
			break
		}
		c.Kind, c.Fields, c.Conflicts = ChangeConflict, diffFields(*b, *d), []string{"deleted"}
		c.Reason = "changed in the hub (" + strings.Join(c.Fields, ", ") + ") and deleted in the file"
	default:
		merged, conflicts := mergeFields(*b, *d, *f)
		c.Fields = diffFields(*d, *f)
		switch {
		case len(conflicts) > 0:
			c.Kind, c.Conflicts = ChangeConflict, conflicts
			c.Reason = "changed in both the hub and the file: " + strings.Join(conflicts, ", ")
		case SameSpec(merged, *d):
			c.Kind, c.Reason = ChangeExport, "changed in the hub: "+strings.Join(diffFields(*b, *d), ", ")
		case SameSpec(merged, *f):
			c.Kind, c.Action = ChangeImport, ActionUpdate
			c.Reason = "changed in the file: " + strings.Join(diffFields(*b, *f), ", ")
		default:
			c.Kind, c.Action, c.Merged = ChangeMerge, ActionUpdate, &merged
			c.Reason = fmt.Sprintf("changed in the file (%s) and in the hub (%s)",
				strings.Join(diffFields(*b, *f), ", "), strings.Join(diffFields(*b, *d), ", "))
		}
	}
	if c.Action == ActionUpdate && d != nil {
		next := f
		if c.Merged != nil {
			next = c.Merged
		}
		c.Stales = next.Fingerprint() != d.Fingerprint()
	}
	return c, false
}

// specField is one field of a requirement as a spec file holds it.
type specField struct {
	name string
	eq   func(a, b Requirement) bool
	set  func(dst *Requirement, src Requirement)
}

var specFieldOps = []specField{
	{"title", func(a, b Requirement) bool { return a.Title == b.Title },
		func(d *Requirement, s Requirement) { d.Title = s.Title }},
	{"details", func(a, b Requirement) bool { return a.Description == b.Description },
		func(d *Requirement, s Requirement) { d.Description = s.Description }},
	{"priority", func(a, b Requirement) bool { return a.Priority == b.Priority },
		func(d *Requirement, s Requirement) { d.Priority = s.Priority }},
	{"tags", func(a, b Requirement) bool { return slices.Equal(a.Tags, b.Tags) },
		func(d *Requirement, s Requirement) { d.Tags = slices.Clone(s.Tags) }},
	{"tests", func(a, b Requirement) bool { return slices.Equal(a.Tests, b.Tests) },
		func(d *Requirement, s Requirement) { d.Tests = slices.Clone(s.Tests) }},
	{"status", func(a, b Requirement) bool { return a.CurrentStatus() == b.CurrentStatus() },
		func(d *Requirement, s Requirement) { d.Status = s.CurrentStatus() }},
}

// diffFields names the fields in which a and b differ.
func diffFields(a, b Requirement) []string {
	var out []string
	for _, op := range specFieldOps {
		if !op.eq(a, b) {
			out = append(out, op.name)
		}
	}
	return out
}

// mergeFields merges hub and file field by field against base: a field only
// one side changed takes that side's value, and a field both changed to
// different values is a conflict.
func mergeFields(base, hub, file Requirement) (Requirement, []string) {
	merged := hub.SpecCopy()
	var conflicts []string
	for _, op := range specFieldOps {
		switch {
		case op.eq(hub, file), op.eq(file, base):
			// The same either way, or only the hub changed it: merged has it.
		case op.eq(hub, base):
			op.set(&merged, file)
		default:
			conflicts = append(conflicts, op.name)
		}
	}
	return merged, conflicts
}

// digest identifies what importing p would do: every change but those only
// the hub has, which importing leaves alone.
func (p Plan) digest() string {
	type row struct {
		ID        int      `json:"id"`
		Kind      string   `json:"kind"`
		Action    string   `json:"action,omitempty"`
		Conflicts []string `json:"conflicts,omitempty"`
		Hub       string   `json:"hub,omitempty"`
		File      string   `json:"file,omitempty"`
		Merged    string   `json:"merged,omitempty"`
	}
	fp := func(r *Requirement) string {
		if r == nil {
			return ""
		}
		return r.SyncFingerprint()
	}
	rows := []row{}
	for _, c := range p.Changes {
		if c.Kind == ChangeExport {
			continue
		}
		rows = append(rows, row{c.ID, c.Kind, c.Action, c.Conflicts, fp(c.Hub), fp(c.File), fp(c.Merged)})
	}
	b, _ := json.Marshal(rows)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

// ConflictError is why a plan cannot be imported as it is: conflicts nobody
// settled, ids the file may not use, or settlements that name no conflict.
type ConflictError struct {
	Plan       Plan
	Unresolved []int
	Refused    []int
	// Unexpected are settlements Resolve could not use: an id that is not in
	// conflict, or an answer that is neither TakeFile nor KeepHub.
	Unexpected []string
}

func (e *ConflictError) Error() string {
	var parts []string
	if len(e.Unresolved) > 0 {
		parts = append(parts, fmt.Sprintf("it conflicts with the hub over %s: settle each by taking the file's "+
			"version or keeping the hub's", keys(e.Unresolved)))
	}
	if len(e.Refused) > 0 {
		parts = append(parts, fmt.Sprintf("it adds %s under the id of a requirement the hub has deleted: give it a new id",
			keys(e.Refused)))
	}
	if len(e.Unexpected) > 0 {
		parts = append(parts, "it was told how to settle what is no conflict: "+strings.Join(e.Unexpected, "; "))
	}
	return "nothing was imported from the spec file: " + strings.Join(parts, "; ")
}

// Is makes a ConflictError an ErrSpecConflict.
func (e *ConflictError) Is(target error) bool { return target == ErrSpecConflict }

func keys(ids []int) string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = Key(id)
	}
	return strings.Join(out, ", ")
}

// Resolve turns p into the writes importing it makes, each conflict settled
// as resolutions says: TakeFile makes the requirement exactly what the file
// says — deleting one the file deleted, restoring under its id one the hub
// deleted — and KeepHub leaves the hub's as it is. A plan with a refused
// change or an unsettled conflict, or settlements that name no conflict, is
// refused whole with a *ConflictError: nothing is imported in part.
//
// The steps come in the order they are applied: additions and restorations,
// then updates, then deletions.
func (p Plan) Resolve(resolutions map[int]string) ([]Step, error) {
	cerr := &ConflictError{Plan: p}
	conflicted := map[int]bool{}
	for _, c := range p.Changes {
		if c.Kind == ChangeConflict {
			conflicted[c.ID] = true
		}
	}
	ids := make([]int, 0, len(resolutions))
	for id := range resolutions {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		switch how := resolutions[id]; {
		case how != TakeFile && how != KeepHub:
			cerr.Unexpected = append(cerr.Unexpected, fmt.Sprintf("%s: %q is neither %q nor %q", Key(id),
				truncateRunes(how, 32), TakeFile, KeepHub))
		case !conflicted[id]:
			cerr.Unexpected = append(cerr.Unexpected, Key(id)+" is not in conflict")
		}
	}

	var adds, updates, deletes []Step
	for _, c := range p.Changes {
		switch c.Kind {
		case ChangeImport:
			switch c.Action {
			case ActionAdd:
				adds = append(adds, Step{Action: ActionAdd, Requirement: *c.File})
			case ActionUpdate:
				updates = append(updates, Step{Action: ActionUpdate, Requirement: *c.File, Previous: c.Hub})
			case ActionDelete:
				deletes = append(deletes, Step{Action: ActionDelete, Requirement: *c.Hub, Previous: c.Hub})
			}
		case ChangeMerge:
			updates = append(updates, Step{Action: ActionUpdate, Requirement: *c.Merged, Previous: c.Hub})
		case ChangeRefused:
			cerr.Refused = append(cerr.Refused, c.ID)
		case ChangeConflict:
			switch resolutions[c.ID] {
			case TakeFile:
				switch {
				case c.File == nil:
					deletes = append(deletes, Step{Action: ActionDelete, Requirement: *c.Hub, Previous: c.Hub})
				case c.Hub == nil:
					adds = append(adds, Step{Action: ActionRestore, Requirement: *c.File})
				default:
					updates = append(updates, Step{Action: ActionUpdate, Requirement: *c.File, Previous: c.Hub})
				}
			case KeepHub:
			default:
				cerr.Unresolved = append(cerr.Unresolved, c.ID)
			}
		}
	}
	if len(cerr.Unresolved) > 0 || len(cerr.Refused) > 0 || len(cerr.Unexpected) > 0 {
		return nil, cerr
	}
	return append(append(adds, updates...), deletes...), nil
}
