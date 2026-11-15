package projectreaders

// The readers list (Task 20498): deny-by-default answers, the rows a list may
// never hold, and the table round trip with its audit rows.

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	shop    = "/srv/projects/shop"
	billing = "/srv/projects/billing"
	docs    = "/srv/projects/docs"
	// shopFeature is a feature of shop: a working copy, not a project.
	shopFeature = shop + "/.cloop/features/checkout"
	// billingFeature is a feature of billing.
	billingFeature = billing + "/.cloop/features/invoices"
)

// TestCanReadIsDenyByDefault: billing may read shop because shop lists it, and
// nothing else is readable by anything — a project asking about itself, a
// feature on either side, the reverse direction, and a project nobody listed.
func TestCanReadIsDenyByDefault(t *testing.T) {
	r := New([]Reader{{ID: "prd_1", ProjectPath: shop, ReaderPath: billing}})
	cases := []struct {
		reader, target string
		want           bool
	}{
		{billing, shop, true},
		{billing + "/", shop + "/.", true}, // spellings of the same paths
		{shop, billing, false},             // the list goes one way
		{docs, shop, false},                // nobody listed docs
		{shop, shop, false},                // a project is not its own reader
		{shopFeature, shop, false},         // a project's own feature reads nothing of it
		{shop, shopFeature, false},         // and the project reads nothing of its feature
		{billingFeature, shop, false},      // a feature of a listed reader is not listed
		{billing, shopFeature, false},      // a feature of a listed project is not listed
		{shop + "/.cloop/worktrees/task-3", shop, false},
		{"", shop, false},
		{billing, "", false},
	}
	for _, c := range cases {
		if got := r.CanRead(c.reader, c.target); got != c.want {
			t.Errorf("CanRead(%q, %q) = %v, want %v", c.reader, c.target, got, c.want)
		}
	}
	var none *Resolver
	if none.CanRead(billing, shop) || none.ReadableBy(billing) != nil || none.ReadersOf(shop) != nil {
		t.Error("a nil resolver permitted or listed something")
	}
	if got := New(nil).CanRead(billing, shop); got {
		t.Error("an empty list permitted a read")
	}
}

// TestReadableByAndReadersOf: the two directions of the same rows.
func TestReadableByAndReadersOf(t *testing.T) {
	r := New([]Reader{
		{ID: "prd_a", ProjectPath: shop, ReaderPath: billing},
		{ID: "prd_b", ProjectPath: docs, ReaderPath: billing},
		{ID: "prd_c", ProjectPath: shop, ReaderPath: docs},
	})
	if got := r.ReadableBy(billing); !reflect.DeepEqual(got, []string{docs, shop}) {
		t.Errorf("ReadableBy(billing) = %v", got)
	}
	if got := r.ReadableBy(shop); len(got) != 0 {
		t.Errorf("ReadableBy(shop) = %v, want nothing: nobody listed shop as a reader", got)
	}
	if got := r.ReadableBy(billingFeature); len(got) != 0 {
		t.Errorf("a feature of billing may read %v, want nothing", got)
	}
	var readers []string
	for _, e := range r.ReadersOf(shop) {
		readers = append(readers, e.ReaderPath)
	}
	if !reflect.DeepEqual(readers, []string{billing, docs}) {
		t.Errorf("ReadersOf(shop) = %v", readers)
	}
	if e, ok := r.Entry(docs, billing); !ok || e.ID != "prd_b" {
		t.Errorf("Entry(docs, billing) = %+v %v", e, ok)
	}
	var targets []string
	for _, e := range r.EntriesReadableBy(billing) {
		targets = append(targets, e.ProjectPath)
	}
	if !reflect.DeepEqual(targets, []string{docs, shop}) {
		t.Errorf("EntriesReadableBy(billing) = %v", targets)
	}
	if len(r.All()) != 3 || len(r.Skipped()) != 0 {
		t.Errorf("All = %d, Skipped = %v", len(r.All()), r.Skipped())
	}
}

// TestNewSkipsRowsItMustNotHonour: a row written around the package — a
// project listing itself, a feature on either side, a second row for a pair —
// is never honoured, and is reported.
func TestNewSkipsRowsItMustNotHonour(t *testing.T) {
	r := New([]Reader{
		{ID: "prd_self", ProjectPath: shop, ReaderPath: shop},
		{ID: "prd_feature_reads", ProjectPath: shop, ReaderPath: shopFeature},
		{ID: "prd_feature_read", ProjectPath: billingFeature, ReaderPath: shop},
		{ID: "prd_nested", ProjectPath: shop, ReaderPath: billing + "/.cloop/features/a/.cloop/features/b"},
		{ID: "prd_empty", ProjectPath: "", ReaderPath: shop},
		{ID: "prd_ok", ProjectPath: shop, ReaderPath: billing},
		{ID: "prd_dup", ProjectPath: shop + "/", ReaderPath: billing},
	})
	if !r.CanRead(billing, shop) {
		t.Fatal("the one valid row is not honoured")
	}
	for _, c := range [][2]string{{shop, shop}, {shopFeature, shop}, {shop, billingFeature}} {
		if r.CanRead(c[0], c[1]) {
			t.Errorf("CanRead(%s, %s) honours a skipped row", c[0], c[1])
		}
	}
	var skipped []string
	for _, e := range r.Skipped() {
		skipped = append(skipped, e.ID)
	}
	want := []string{"prd_self", "prd_feature_reads", "prd_feature_read", "prd_nested", "prd_empty", "prd_dup"}
	if !reflect.DeepEqual(skipped, want) {
		t.Errorf("Skipped = %v, want %v", skipped, want)
	}
	if e, _ := r.Entry(shop, billing); e.ID != "prd_ok" {
		t.Errorf("the pair's first row lost to its duplicate: %+v", e)
	}
}

func TestCheckPairAndParsePath(t *testing.T) {
	for _, c := range []struct {
		project, reader string
		want            error
	}{
		{shop, billing, nil},
		{shop, shop, ErrSelf},
		{shop, shop + "/", ErrSelf},
		{shop, shopFeature, ErrFeature},
		{shopFeature, billing, ErrFeature},
		{shop, billing + "/.cloop/worktrees/task-1", ErrFeature},
		{"", billing, ErrInvalidPath},
	} {
		err := CheckPair(c.project, c.reader)
		if (c.want == nil) != (err == nil) || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("CheckPair(%q, %q) = %v, want %v", c.project, c.reader, err, c.want)
		}
	}
	// A directory merely named .cloop above a project is no feature.
	if err := CheckPair("/home/u/.cloop/projects/shop", billing); err != nil {
		t.Errorf("a project below a directory named .cloop was refused: %v", err)
	}
	for raw, ok := range map[string]bool{
		"/srv/projects/shop":                  true,
		" /srv/projects/shop/ ":               true,
		"srv/projects/shop":                   false,
		"":                                    false,
		"/srv/pro\x00jects":                   false,
		"/srv/pro\njects":                     false,
		"/" + strings.Repeat("a", MaxPathLen): false,
	} {
		got, err := ParsePath(raw)
		if (err == nil) != ok {
			t.Errorf("ParsePath(%q) = %q, %v; want ok=%v", raw, got, err, ok)
		}
		if err != nil && !errors.Is(err, ErrInvalidPath) {
			t.Errorf("ParsePath(%q) error %v is not ErrInvalidPath", raw, err)
		}
		if ok && got != shop {
			t.Errorf("ParsePath(%q) = %q, want %q", raw, got, shop)
		}
	}
}

// auditFor builds the rows the hub commits with each change.
func auditFor(calls *[]string) Audit {
	return func(prev, next *Reader) ([]*statedb.AuditEvent, error) {
		action, e := auditaction.ActionProjectReaderAdd, next
		if next == nil {
			action, e = auditaction.ActionProjectReaderRemove, prev
		}
		*calls = append(*calls, string(action)+" "+e.ReaderPath+"→"+e.ProjectPath)
		body, _ := json.Marshal(map[string]string{"project_path": e.ProjectPath, "reader_path": e.ReaderPath, "id": e.ID})
		return []*statedb.AuditEvent{{Actor: "alice@example.com", EventType: string(action),
			EntityType: "project_reader", EntityID: e.ProjectPath + "|" + e.ReaderPath, Payload: string(body)}}, nil
	}
}

// TestTheTableRoundTrip: adding, adding again, removing by reader and by id,
// and a project's removal taking both sides of its lists with it — each change
// committed with its audit row, and a refused audit undoing the change.
func TestTheTableRoundTrip(t *testing.T) {
	db := statedbtest.Open(t).AsControlPlane()
	var calls []string
	audit := auditFor(&calls)

	e, added, err := Add(db, shop, billing, "alice@example.com", audit)
	if err != nil || !added || !strings.HasPrefix(e.ID, "prd_") || e.AddedBy != "alice@example.com" || e.AddedAt.IsZero() {
		t.Fatalf("Add = %+v %v %v", e, added, err)
	}
	again, added, err := Add(db, shop+"/", billing, "bob@example.com", audit)
	if err != nil || added || again.ID != e.ID || again.AddedBy != "alice@example.com" {
		t.Fatalf("adding a listed reader again = %+v %v %v, want the first entry unchanged", again, added, err)
	}
	for _, bad := range [][2]string{{shop, shop}, {shop, shopFeature}, {"", billing}} {
		if _, _, err := Add(db, bad[0], bad[1], "alice@example.com", audit); err == nil {
			t.Errorf("Add(%q, %q) was stored", bad[0], bad[1])
		}
	}
	if _, _, err := Add(db, docs, billing, "alice@example.com", audit); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Add(db, billing, docs, "alice@example.com", audit); err != nil {
		t.Fatal(err)
	}

	// A refused audit row undoes the change it was to record.
	refuse := func(*Reader, *Reader) ([]*statedb.AuditEvent, error) { return nil, errors.New("no trail") }
	if _, _, err := Add(db, docs, shop, "alice@example.com", refuse); err == nil {
		t.Fatal("an addition whose audit row failed was kept")
	}
	r, err := Load(db)
	if err != nil {
		t.Fatal(err)
	}
	if r.CanRead(shop, docs) {
		t.Fatal("the addition whose audit failed is in the table")
	}
	if !r.CanRead(billing, shop) || !r.CanRead(billing, docs) || !r.CanRead(docs, billing) {
		t.Fatalf("Load lost an entry: %+v", r.All())
	}

	// By reader; then nothing left to remove.
	got, err := Remove(db, docs, billing, audit)
	if err != nil || got == nil || got.ReaderPath != billing {
		t.Fatalf("Remove = %+v %v", got, err)
	}
	if got, err := Remove(db, docs, billing, audit); err != nil || got != nil {
		t.Fatalf("removing it again = %+v %v, want nothing", got, err)
	}

	// By id, only on the list the id belongs to.
	if got, err := RemoveByID(db, docs, e.ID, audit); err != nil || got != nil {
		t.Fatalf("shop's entry was removed through docs' list: %+v %v", got, err)
	}
	if got, err := RemoveByID(db, shop, e.ID, audit); err != nil || got == nil || got.ID != e.ID {
		t.Fatalf("RemoveByID = %+v %v", got, err)
	}

	// A project leaving the hub takes both sides with it: billing's reader
	// and what billing could read.
	if _, _, err := Add(db, shop, billing, "alice@example.com", audit); err != nil {
		t.Fatal(err)
	}
	gone, err := RemoveProject(db, billing, audit)
	if err != nil || len(gone) != 2 {
		t.Fatalf("RemoveProject = %+v %v, want 2 entries", gone, err)
	}
	if r, _ := Load(db); len(r.All()) != 0 {
		t.Fatalf("entries survived their project: %+v", r.All())
	}

	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EntityType: "project_reader", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var trail []string
	for _, ev := range evs { // oldest first
		var p map[string]string
		_ = json.Unmarshal([]byte(ev.Payload), &p)
		trail = append(trail, ev.EventType+" "+p["reader_path"]+"→"+p["project_path"])
	}
	wantTrail := []string{
		"project.reader.add " + billing + "→" + shop,
		"project.reader.add " + billing + "→" + docs,
		"project.reader.add " + docs + "→" + billing,
		"project.reader.remove " + billing + "→" + docs,
		"project.reader.remove " + billing + "→" + shop,
		"project.reader.add " + billing + "→" + shop,
		"project.reader.remove " + docs + "→" + billing,
		"project.reader.remove " + billing + "→" + shop,
	}
	if !reflect.DeepEqual(trail, wantTrail) {
		t.Errorf("audit trail:\n  %s\nwant\n  %s", strings.Join(trail, "\n  "), strings.Join(wantTrail, "\n  "))
	}
	// One audit row asked for per change, and none for the additions that
	// changed nothing.
	if len(calls) != len(wantTrail) {
		t.Errorf("audit was asked %d times, want %d: %v", len(calls), len(wantTrail), calls)
	}
}
