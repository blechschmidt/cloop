package adr

// Tests for the decision-record store.
//
// Everything here works against a real temporary directory rather than a
// filesystem fake, because the behaviour that matters is what survives a
// round-trip through markdown: the frontmatter writer and the parser are two
// separate pieces of code, and the only interesting question is whether they
// still agree after a record has been edited a few times.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSlug(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"simple":            {"Use SQLite for state", "use-sqlite-for-state"},
		"punctuation":       {"Why not Postgres?!", "why-not-postgres"},
		"collapses runs":    {"a   ---   b", "a-b"},
		"trims edges":       {"  -- Hello --  ", "hello"},
		"empty":             {"", "untitled"},
		"only punctuation":  {"???", "untitled"},
		"non-ascii dropped": {"naïve café", "na-ve-caf"},
		"keeps digits":      {"Migrate to Go 1.25", "migrate-to-go-1-25"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := Slug(c.in); got != c.want {
				t.Errorf("Slug(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestSlugIsBoundedForLongTitles(t *testing.T) {
	got := Slug(strings.Repeat("word ", 100))
	if len(got) > 60 {
		t.Errorf("slug is %d chars, want <= 60: %q", len(got), got)
	}
	// A bounded slug still has to be a usable filename component.
	if strings.HasSuffix(got, "-") {
		t.Errorf("slug %q ends in a separator", got)
	}
}

func TestFilename(t *testing.T) {
	if got, want := Filename(7, "Use SQLite"), "0007-use-sqlite.md"; got != want {
		t.Errorf("Filename = %q, want %q", got, want)
	}
	// Four-digit zero padding is what makes a directory listing sort the way
	// the IDs read; losing it silently reorders every record past nine.
	if got, want := Filename(12345, "x"), "12345-x.md"; got != want {
		t.Errorf("Filename = %q, want %q", got, want)
	}
}

func TestCreateAssignsSequentialIDs(t *testing.T) {
	dir := t.TempDir()

	for i := 1; i <= 3; i++ {
		got, err := Create(dir, "Decision "+string(rune('A'+i-1)), "")
		if err != nil {
			t.Fatalf("Create #%d: %v", i, err)
		}
		if got.ID != i {
			t.Errorf("Create #%d got ID %d, want %d", i, got.ID, i)
		}
		if got.Status != StatusProposed {
			t.Errorf("new record status = %q, want %q", got.Status, StatusProposed)
		}
		if _, err := os.Stat(got.Path); err != nil {
			t.Errorf("record file not on disk: %v", err)
		}
	}

	next, err := NextID(dir)
	if err != nil {
		t.Fatalf("NextID: %v", err)
	}
	if next != 4 {
		t.Errorf("NextID = %d, want 4", next)
	}
}

func TestCreateUsesTemplateAndSubstitutesID(t *testing.T) {
	dir := t.TempDir()

	record, err := Create(dir, "Adopt ADRs", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// The template ships a placeholder heading; leaving it unsubstituted is
	// the sort of thing that only shows up once a reader opens the file.
	if strings.Contains(record.Body, "ADR-XXXX") {
		t.Error("template placeholder ADR-XXXX survived into the saved body")
	}
	if !strings.Contains(record.Body, "ADR-0001") {
		t.Errorf("body does not carry the real ID heading:\n%s", record.Body)
	}
	for _, section := range []string{"## Context", "## Decision", "## Consequences"} {
		if !strings.Contains(record.Body, section) {
			t.Errorf("template is missing %q", section)
		}
	}
}

func TestCreateRejectsEmptyTitle(t *testing.T) {
	for _, title := range []string{"", "   ", "\t\n"} {
		if _, err := Create(t.TempDir(), title, ""); err == nil {
			t.Errorf("Create(%q) succeeded, want an error", title)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	adrDir, err := EnsureDir(dir)
	if err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}

	want := &ADR{
		ID:           9,
		Title:        "Split the session store",
		Status:       StatusAccepted,
		Date:         time.Date(2026, 3, 14, 0, 0, 0, 0, time.UTC),
		Deciders:     []string{"alice", "bob"},
		Tags:         []string{"storage", "security"},
		Supersedes:   []int{4, 5},
		SupersededBy: []int{12},
		Path:         filepath.Join(adrDir, Filename(9, "Split the session store")),
		Body:         "# ADR-0009\n\nSome prose.\n",
	}
	if err := want.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(want.Path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got.ID != want.ID || got.Title != want.Title || got.Status != want.Status {
		t.Errorf("scalars differ: got id=%d title=%q status=%q", got.ID, got.Title, got.Status)
	}
	if !got.Date.Equal(want.Date) {
		t.Errorf("Date = %v, want %v", got.Date, want.Date)
	}
	if strings.Join(got.Deciders, ",") != "alice,bob" {
		t.Errorf("Deciders = %v, want [alice bob]", got.Deciders)
	}
	if strings.Join(got.Tags, ",") != "storage,security" {
		t.Errorf("Tags = %v, want [storage security]", got.Tags)
	}
	if len(got.Supersedes) != 2 || got.Supersedes[0] != 4 || got.Supersedes[1] != 5 {
		t.Errorf("Supersedes = %v, want [4 5]", got.Supersedes)
	}
	if len(got.SupersededBy) != 1 || got.SupersededBy[0] != 12 {
		t.Errorf("SupersededBy = %v, want [12]", got.SupersededBy)
	}
	if !strings.Contains(got.Body, "Some prose.") {
		t.Errorf("Body lost its content: %q", got.Body)
	}
}

// TestFrontmatterSurvivesRepeatedSaves is a regression test.
//
// Save writes scalars with %q and the parser used to strip the surrounding
// quote characters with strings.Trim, which leaves the backslashes of an
// escaped inner quote behind. Because every status change is a Load followed by
// a Save, the escaping compounded: a title containing a quote grew a new pair
// of backslashes on each edit until it was unreadable. Three cycles is enough
// to catch that; one is not.
func TestFrontmatterSurvivesRepeatedSaves(t *testing.T) {
	tricky := []string{
		`He said "hi" to me`,
		`Use "strict" mode: always`,
		`a\backslash`,
		`plain title`,
		`trailing quote "`,
	}

	for _, title := range tricky {
		t.Run(Slug(title), func(t *testing.T) {
			dir := t.TempDir()
			record, err := Create(dir, title, "body\n")
			if err != nil {
				t.Fatalf("Create: %v", err)
			}

			for cycle := 1; cycle <= 3; cycle++ {
				reloaded, err := Load(record.Path)
				if err != nil {
					t.Fatalf("Load on cycle %d: %v", cycle, err)
				}
				if reloaded.Title != title {
					t.Fatalf("after %d cycle(s) title = %q, want %q", cycle, reloaded.Title, title)
				}
				if err := reloaded.Save(); err != nil {
					t.Fatalf("Save on cycle %d: %v", cycle, err)
				}
				record = reloaded
			}
		})
	}
}

func TestQuotedListItemsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	record, err := Create(dir, "Team decision", "body\n")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	record.Deciders = []string{`O'Brien`, `van "Vee" Damme`}
	if err := record.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(record.Path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Deciders) != 2 || got.Deciders[0] != `O'Brien` || got.Deciders[1] != `van "Vee" Damme` {
		t.Errorf("Deciders = %#v, want [O'Brien, van \"Vee\" Damme]", got.Deciders)
	}
}

func TestSaveDefaultsStatusAndDate(t *testing.T) {
	dir := t.TempDir()
	adrDir, _ := EnsureDir(dir)

	record := &ADR{ID: 1, Title: "No metadata", Path: filepath.Join(adrDir, "0001-no-metadata.md")}
	if err := record.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if record.Status != StatusProposed {
		t.Errorf("Status = %q, want it defaulted to %q", record.Status, StatusProposed)
	}
	if record.Date.IsZero() {
		t.Error("Date was left zero; Save should stamp it")
	}
}

func TestSaveRequiresAPath(t *testing.T) {
	record := &ADR{ID: 1, Title: "Nowhere to go"}
	if err := record.Save(); err == nil {
		t.Error("Save with an empty Path succeeded, want an error")
	}
}

func TestSaveWritesNonExecutableFile(t *testing.T) {
	dir := t.TempDir()
	record, err := Create(dir, "Permissions", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	info, err := os.Stat(record.Path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("mode = %o, want 644", perm)
	}
}

// TestLoadBackfillsFromFilename covers a hand-written record: a plain markdown
// file with no frontmatter at all still has to list, because telling a user
// their file was ignored for lacking a header they did not know about is worse
// than inferring the two fields the filename already encodes.
func TestLoadBackfillsFromFilename(t *testing.T) {
	dir := t.TempDir()
	adrDir, _ := EnsureDir(dir)
	path := filepath.Join(adrDir, "0042-hand-written-record.md")
	if err := os.WriteFile(path, []byte("just some prose\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.ID != 42 {
		t.Errorf("ID = %d, want 42 inferred from the filename", got.ID)
	}
	if got.Title != "hand written record" {
		t.Errorf("Title = %q, want it inferred from the filename", got.Title)
	}
	if !strings.Contains(got.Body, "just some prose") {
		t.Errorf("Body = %q, want the whole file treated as body", got.Body)
	}
}

func TestListIsEmptyWhenDirectoryIsMissing(t *testing.T) {
	got, err := List(t.TempDir())
	if err != nil {
		t.Fatalf("List on a project with no ADR dir returned an error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("List = %v, want empty", got)
	}
}

func TestListSortsByIDAndIgnoresNonMarkdown(t *testing.T) {
	dir := t.TempDir()
	adrDir, _ := EnsureDir(dir)

	// Created out of order on purpose: readdir order is not ID order.
	for _, id := range []int{3, 1, 10, 2} {
		record := &ADR{ID: id, Title: "Record", Status: StatusProposed,
			Path: filepath.Join(adrDir, Filename(id, "record")), Body: "b\n"}
		if err := record.Save(); err != nil {
			t.Fatalf("Save %d: %v", id, err)
		}
	}
	// Neither of these is a record, and neither may appear in a listing.
	if err := os.WriteFile(filepath.Join(adrDir, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(adrDir, "subdir.md"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := List(dir)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var ids []int
	for _, r := range got {
		ids = append(ids, r.ID)
	}
	if len(ids) != 4 || ids[0] != 1 || ids[1] != 2 || ids[2] != 3 || ids[3] != 10 {
		t.Errorf("ids = %v, want [1 2 3 10] — numeric order, no strays", ids)
	}
}

func TestFindByID(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "First", ""); err != nil {
		t.Fatal(err)
	}

	got, err := FindByID(dir, 1)
	if err != nil {
		t.Fatalf("FindByID(1): %v", err)
	}
	if got.Title != "First" {
		t.Errorf("Title = %q, want First", got.Title)
	}

	if _, err := FindByID(dir, 99); err == nil {
		t.Error("FindByID(99) succeeded, want a not-found error")
	}
}

func TestLinkSupersedesUpdatesBothRecords(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "Old way", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(dir, "New way", ""); err != nil {
		t.Fatal(err)
	}

	if err := LinkSupersedes(dir, 2, 1); err != nil {
		t.Fatalf("LinkSupersedes: %v", err)
	}

	// Re-read from disk: the point of the call is what it persisted, not what
	// it did to the structs it happened to hold.
	oldRec, err := FindByID(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	newRec, err := FindByID(dir, 2)
	if err != nil {
		t.Fatal(err)
	}

	if oldRec.Status != StatusSuperseded {
		t.Errorf("old record status = %q, want %q", oldRec.Status, StatusSuperseded)
	}
	if len(oldRec.SupersededBy) != 1 || oldRec.SupersededBy[0] != 2 {
		t.Errorf("old.SupersededBy = %v, want [2]", oldRec.SupersededBy)
	}
	if len(newRec.Supersedes) != 1 || newRec.Supersedes[0] != 1 {
		t.Errorf("new.Supersedes = %v, want [1]", newRec.Supersedes)
	}
	if newRec.Status == StatusSuperseded {
		t.Error("the superseding record was itself marked superseded")
	}
}

func TestLinkSupersedesIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "Old", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(dir, "New", ""); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if err := LinkSupersedes(dir, 2, 1); err != nil {
			t.Fatalf("LinkSupersedes call %d: %v", i+1, err)
		}
	}

	newRec, _ := FindByID(dir, 2)
	oldRec, _ := FindByID(dir, 1)
	if len(newRec.Supersedes) != 1 {
		t.Errorf("Supersedes = %v, want a single entry after repeated calls", newRec.Supersedes)
	}
	if len(oldRec.SupersededBy) != 1 {
		t.Errorf("SupersededBy = %v, want a single entry after repeated calls", oldRec.SupersededBy)
	}
}

func TestLinkSupersedesRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	if _, err := Create(dir, "Only one", ""); err != nil {
		t.Fatal(err)
	}

	if err := LinkSupersedes(dir, 1, 1); err == nil {
		t.Error("a record superseding itself was accepted")
	}
	if err := LinkSupersedes(dir, 1, 99); err == nil {
		t.Error("superseding a nonexistent record was accepted")
	}
	if err := LinkSupersedes(dir, 99, 1); err == nil {
		t.Error("a nonexistent record superseding one was accepted")
	}
	// The rejected calls must not have half-applied.
	only, err := FindByID(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(only.Supersedes) != 0 || len(only.SupersededBy) != 0 || only.Status != StatusProposed {
		t.Errorf("record was mutated by a rejected call: %+v", only)
	}
}

func TestSetStatusPersists(t *testing.T) {
	dir := t.TempDir()
	record, err := Create(dir, "Decide", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := record.SetStatus(StatusAccepted); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	got, err := FindByID(dir, record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusAccepted {
		t.Errorf("Status = %q, want %q", got.Status, StatusAccepted)
	}
}

func TestParseStatus(t *testing.T) {
	for _, want := range Statuses() {
		for _, in := range []string{want, strings.ToLower(want), strings.ToUpper(want), "  " + want + "  "} {
			got, err := ParseStatus(in)
			if err != nil {
				t.Errorf("ParseStatus(%q): %v", in, err)
				continue
			}
			if got != want {
				t.Errorf("ParseStatus(%q) = %q, want the canonical %q", in, got, want)
			}
		}
	}

	for _, in := range []string{"", "acepted", "done", "Propose"} {
		if _, err := ParseStatus(in); err == nil {
			t.Errorf("ParseStatus(%q) succeeded, want an error", in)
		} else if !strings.Contains(err.Error(), StatusAccepted) {
			// The message is the only place a user learns the valid set.
			t.Errorf("ParseStatus(%q) error %q does not list the valid statuses", in, err)
		}
	}
}

func TestStatusesAreDistinctAndNonEmpty(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range Statuses() {
		if s == "" {
			t.Error("Statuses contains an empty string")
		}
		if seen[s] {
			t.Errorf("Statuses contains %q twice", s)
		}
		seen[s] = true
	}
	if len(seen) != 5 {
		t.Errorf("got %d statuses, want the 5 documented lifecycle values", len(seen))
	}
}
