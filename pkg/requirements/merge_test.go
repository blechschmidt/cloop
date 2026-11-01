package requirements

import (
	"errors"
	"slices"
	"testing"
)

// req is a requirement for the merge tables: an id, a title, and whatever
// else the case changes.
func req(id int, title string, mods ...func(*Requirement)) Requirement {
	r := Requirement{ID: id, Title: title, Status: StatusApproved}
	for _, m := range mods {
		m(&r)
	}
	return r
}

func withTests(cmds ...string) func(*Requirement) {
	return func(r *Requirement) {
		r.Tests = nil
		for _, c := range cmds {
			r.Tests = append(r.Tests, Test{Command: c})
		}
	}
}
func withPriority(p string) func(*Requirement) { return func(r *Requirement) { r.Priority = p } }
func withStatus(s string) func(*Requirement)   { return func(r *Requirement) { r.Status = s } }
func withDetails(d string) func(*Requirement) {
	return func(r *Requirement) { r.Description = d }
}

func list(rs ...Requirement) []Requirement { return rs }

func TestMergeDecidesEachRequirement(t *testing.T) {
	base := req(1, "base", withTests("make a"), withPriority(PriorityShould))
	for _, tc := range []struct {
		name             string
		base, hub, file  []Requirement
		assigned         int
		kind, action     string
		fields, conflict []string
		merged           *Requirement
		stales           bool
	}{
		{name: "in sync", base: list(base), hub: list(base), file: list(base)},
		{name: "in sync with no base", hub: list(base), file: list(base)},
		{name: "added in the file", file: list(req(7, "new")), assigned: 6, kind: ChangeImport, action: ActionAdd},
		{name: "added in the file under a deleted id", file: list(req(5, "new")), assigned: 6, kind: ChangeRefused},
		{name: "added in the hub", hub: list(req(7, "new")), assigned: 7, kind: ChangeExport},
		{name: "added in both, differently", hub: list(req(7, "hub's")), file: list(req(7, "file's")), assigned: 7,
			kind: ChangeConflict, fields: []string{"title"}, conflict: []string{"title"}},
		{name: "deleted in the hub", base: list(base), file: list(base), assigned: 1, kind: ChangeExport},
		{name: "deleted in the hub, changed in the file", base: list(base), file: list(req(1, "renamed", withTests("make a"),
			withPriority(PriorityShould))), assigned: 1, kind: ChangeConflict, fields: []string{"title"}, conflict: []string{"deleted"}},
		{name: "deleted in the file", base: list(base), hub: list(base), assigned: 1, kind: ChangeImport, action: ActionDelete},
		{name: "deleted in the file, changed in the hub", base: list(base), hub: list(req(1, "base", withTests("make b"),
			withPriority(PriorityShould))), assigned: 1, kind: ChangeConflict, fields: []string{"tests"}, conflict: []string{"deleted"}},
		{name: "deleted in both", base: list(base), assigned: 1},
		{name: "changed in the file", base: list(base), hub: list(base),
			file: list(req(1, "base", withTests("make a", "make c"), withPriority(PriorityShould))), assigned: 1,
			kind: ChangeImport, action: ActionUpdate, fields: []string{"tests"}, stales: true},
		{name: "approved in the file", base: list(req(1, "t", withStatus(StatusDraft))), hub: list(req(1, "t", withStatus(StatusDraft))),
			file: list(req(1, "t")), assigned: 1, kind: ChangeImport, action: ActionUpdate, fields: []string{"status"}},
		{name: "changed in the hub", base: list(base), hub: list(req(1, "base", withTests("make a"), withPriority(PriorityMust))),
			file: list(base), assigned: 1, kind: ChangeExport, fields: []string{"priority"}},
		{name: "changed in both, apart", base: list(base),
			hub:  list(req(1, "base", withTests("make a"), withPriority(PriorityMust))),
			file: list(req(1, "base", withTests("make b"), withPriority(PriorityShould), withDetails("why"))), assigned: 1,
			kind: ChangeMerge, action: ActionUpdate, fields: []string{"details", "priority", "tests"},
			merged: &Requirement{ID: 1, Title: "base", Description: "why", Priority: PriorityMust, Status: StatusApproved,
				Tests: []Test{{Command: "make b"}}},
			stales: true},
		{name: "changed alike in both", base: list(base), hub: list(req(1, "same")),
			file: list(req(1, "same")), assigned: 1},
		{name: "changed in both, together", base: list(base),
			hub:  list(req(1, "hub's", withTests("make a"), withPriority(PriorityShould))),
			file: list(req(1, "file's", withTests("make a"), withPriority(PriorityMust))), assigned: 1,
			kind: ChangeConflict, fields: []string{"title", "priority"}, conflict: []string{"title"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Merge(tc.base, tc.hub, tc.file, tc.assigned)
			if tc.kind == "" {
				if len(p.Changes) != 0 {
					t.Fatalf("changes %+v, want none", p.Changes)
				}
				return
			}
			if len(p.Changes) != 1 {
				t.Fatalf("%d changes: %+v", len(p.Changes), p.Changes)
			}
			c := p.Changes[0]
			if c.Kind != tc.kind || c.Action != tc.action {
				t.Errorf("kind %q action %q (%s), want %q %q", c.Kind, c.Action, c.Reason, tc.kind, tc.action)
			}
			if tc.fields != nil && !slices.Equal(c.Fields, tc.fields) {
				t.Errorf("fields %v, want %v", c.Fields, tc.fields)
			}
			if !slices.Equal(c.Conflicts, tc.conflict) {
				t.Errorf("conflicts %v, want %v", c.Conflicts, tc.conflict)
			}
			if tc.merged != nil && (c.Merged == nil || !SameSpec(*c.Merged, *tc.merged)) {
				t.Errorf("merged %+v, want %+v", c.Merged, tc.merged)
			}
			if c.Stales != tc.stales {
				t.Errorf("stales %v, want %v", c.Stales, tc.stales)
			}
			if c.Reason == "" {
				t.Error("no reason given")
			}
		})
	}
}

func TestMergeCounts(t *testing.T) {
	a, b, c := req(1, "a"), req(2, "b"), req(3, "c")
	p := Merge(list(a, b, c), list(a, req(2, "b2"), c, req(4, "hub")), list(a, b, req(3, "c2"), req(5, "file")), 4)
	if p.InSync != 1 || p.Imports != 2 || p.Exports != 2 || p.Conflicts != 0 || p.Refused != 0 {
		t.Errorf("tallies %+v", p)
	}
	ids := []int{}
	for _, ch := range p.Changes {
		ids = append(ids, ch.ID)
	}
	if !slices.Equal(ids, []int{2, 3, 4, 5}) {
		t.Errorf("changes in the order %v", ids)
	}
}

func TestResolveSettlesOnlyWhatIsAsked(t *testing.T) {
	base := list(req(1, "one"), req(2, "two"), req(3, "three"), req(4, "four"))
	hub := list(req(1, "one, hub"), req(3, "three, hub"), req(4, "four"), req(6, "six"))
	file := list(req(1, "one, file"), req(2, "two, file"), req(4, "four, file"), req(7, "seven"), req(6, "six, file"))
	// R-1 conflicts on its title, R-2 was deleted in the hub and changed in the
	// file, R-3 changed in the hub and deleted in the file, R-6 was added on
	// both sides; R-4 imports and R-7 is new.
	p := Merge(base, hub, file, 6)
	if p.Conflicts != 4 || p.Imports != 2 || p.Refused != 0 {
		t.Fatalf("plan %+v", p)
	}

	_, err := p.Resolve(nil)
	var cerr *ConflictError
	if !errors.As(err, &cerr) || !errors.Is(err, ErrSpecConflict) || !slices.Equal(cerr.Unresolved, []int{1, 2, 3, 6}) {
		t.Fatalf("unsettled: %v", err)
	}
	if _, err := p.Resolve(map[int]string{1: TakeFile, 2: TakeFile, 3: KeepHub, 6: "theirs"}); !errors.As(err, &cerr) ||
		len(cerr.Unexpected) != 1 {
		t.Errorf("an answer that is neither: %v", err)
	}
	if _, err := p.Resolve(map[int]string{1: TakeFile, 2: TakeFile, 3: KeepHub, 6: KeepHub, 4: TakeFile}); !errors.As(err, &cerr) ||
		len(cerr.Unexpected) != 1 {
		t.Errorf("a settlement of what is no conflict: %v", err)
	}

	steps, err := p.Resolve(map[int]string{1: TakeFile, 2: TakeFile, 3: TakeFile, 6: KeepHub})
	if err != nil {
		t.Fatal(err)
	}
	type st struct {
		action string
		id     int
		title  string
	}
	var got []st
	for _, s := range steps {
		got = append(got, st{s.Action, s.Requirement.ID, s.Requirement.Title})
	}
	want := []st{
		{ActionRestore, 2, "two, file"}, {ActionAdd, 7, "seven"},
		{ActionUpdate, 1, "one, file"}, {ActionUpdate, 4, "four, file"},
		{ActionDelete, 3, "three, hub"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("steps\n%v\nwant\n%v", got, want)
	}

	// A refused id is never imported, however the rest is settled.
	p = Merge(nil, list(req(1, "one")), list(req(1, "one"), req(2, "reused")), 3)
	if _, err := p.Resolve(nil); !errors.As(err, &cerr) || !slices.Equal(cerr.Refused, []int{2}) {
		t.Errorf("a reused id: %v", err)
	}
}

func TestPlanDigestIsWhatImportingDoes(t *testing.T) {
	base := list(req(1, "one"), req(2, "two"))
	p1 := Merge(base, base, list(req(1, "one, file"), req(2, "two")), 2)
	p2 := Merge(base, base, list(req(1, "one, file"), req(2, "two")), 2)
	if p1.Digest == "" || p1.Digest != p2.Digest {
		t.Fatalf("the same merge digests %q and %q", p1.Digest, p2.Digest)
	}
	// A change only the hub has is not imported, and does not move it.
	p3 := Merge(base, list(req(1, "one"), req(2, "two, hub")), list(req(1, "one, file"), req(2, "two")), 2)
	if p3.Digest != p1.Digest {
		t.Error("an export-side change moved the digest")
	}
	// What the import would write does.
	p4 := Merge(base, base, list(req(1, "one, file, again"), req(2, "two")), 2)
	if p4.Digest == p1.Digest {
		t.Error("a different import digests the same")
	}
	p5 := Merge(base, list(req(1, "one, hub"), req(2, "two")), list(req(1, "one, file"), req(2, "two")), 2)
	if p5.Digest == p1.Digest {
		t.Error("an import that became a conflict digests the same")
	}
}
