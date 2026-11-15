// Package projectreaders is every project's readers list: which other projects
// may read it (Task 20498).
//
// The list is deny-by-default. Project B may read project A only when A's list
// names B, and nothing else makes it so: not being the same project, not one
// being a feature of the other, not sharing an owner or an executor. The
// answer is the same whoever asks, because it is about projects, not people:
// who may change a list is decided by the hub (pkg/ui), which gives it to the
// project's administrators.
//
// It is the split pkg/projectmember uses: pkg/statedb owns the table,
// this package owns what a row means, how its paths are normalised and which
// rows are refused, and the Resolver answers the two questions every reader of
// the list asks:
//
//   - CanRead(reader, project): may reader's runs read project?
//   - ReadableBy(project): which projects may project's runs read?
//
// # Paths
//
// A project is named by its absolute, cleaned path on the hub: the project's
// identity there, which a rename of its registry entry leaves alone and a move
// to another executor keeps. Paths are not symlink-resolved, for the reason
// projectmember gives: the registry and every authorization scope carry the
// path as registered.
//
// # What is never on a list
//
// A project never lists itself: a run reads its own project without asking
// anybody, so such a row would grant nothing and say something false. A
// feature is never on a list on either side, and neither is anything else
// under a project's .cloop/features or .cloop/worktrees: those are working
// copies of a project, not projects of their own, and a feature neither reads
// nor is read by grace of its project's list. A row of either kind written around this
// package — by hand, or by a build that predates a rule — is skipped when the
// list is loaded and reported through Resolver.Skipped, never honoured.
package projectreaders

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// MaxPathLen bounds a project path accepted from a caller: PATH_MAX on Linux.
const MaxPathLen = 4096

// Errors a caller can tell apart, so the hub can answer each with its own
// status and the CLI with its own sentence.
var (
	// ErrInvalidPath refuses a path that cannot name a project: empty,
	// relative, too long, or carrying a control character.
	ErrInvalidPath = errors.New("projectreaders: invalid project path")
	// ErrSelf refuses a project listed as its own reader.
	ErrSelf = errors.New("projectreaders: a project does not list itself as a reader")
	// ErrFeature refuses a feature, or any other working copy under a
	// project's .cloop directory, on either side of a list.
	ErrFeature = errors.New("projectreaders: a feature is not listed on its own")
)

// Reader is one entry of a readers list: ReaderPath may read ProjectPath.
type Reader struct {
	// ID names the entry for a caller who cannot see the reader: random, so it
	// says nothing about either project.
	ID string `json:"id"`
	// ProjectPath is the project that may be read.
	ProjectPath string `json:"project_path"`
	// ReaderPath is the project that may read it.
	ReaderPath string `json:"reader_path"`
	// AddedBy and AddedAt record who added the entry, and when.
	AddedBy string    `json:"added_by,omitempty"`
	AddedAt time.Time `json:"added_at"`
}

// NormalizePath canonicalises a project path: absolute and cleaned, not
// symlink-resolved. "" for an empty one.
func NormalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if abs, err := filepath.Abs(path); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(path)
}

// ParsePath validates a project path a caller sent and returns it cleaned. A
// relative path is refused rather than resolved: it would be resolved against
// the hub's working directory, which is nothing the caller chose.
func ParsePath(raw string) (string, error) {
	path := strings.TrimSpace(raw)
	switch {
	case path == "":
		return "", fmt.Errorf("%w: a project path is required", ErrInvalidPath)
	case len(path) > MaxPathLen:
		return "", fmt.Errorf("%w: a path is at most %d bytes", ErrInvalidPath, MaxPathLen)
	case !filepath.IsAbs(path):
		return "", fmt.Errorf("%w: %q is not an absolute path", ErrInvalidPath, path)
	}
	for _, r := range path {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("%w: the path contains a control character", ErrInvalidPath)
		}
	}
	return filepath.Clean(path), nil
}

// workingCopyDirs are the directories under a project's .cloop that hold
// working copies of the project: its features (pkg/feature) and the worktrees
// parallel tasks run in (pkg/worktree). Nothing under either is a project of
// its own.
var workingCopyDirs = map[string]bool{feature.DirName: true, "worktrees": true}

// InsideControlDir reports whether path is a feature, or anything else under a
// project's .cloop/features or .cloop/worktrees, at any depth: a working copy
// of a project, never a project of its own.
func InsideControlDir(path string) bool {
	path = NormalizePath(path)
	if path == "" {
		return false
	}
	if _, _, ok := feature.ParentOf(path); ok {
		return true
	}
	// ParentOf answers for a feature of a project. A feature's own feature,
	// or anything below either, is found by its segments.
	elems := strings.Split(path, string(filepath.Separator))
	for i := 0; i+2 < len(elems); i++ {
		if elems[i] == feature.ControlDir && workingCopyDirs[elems[i+1]] && elems[i+2] != "" {
			return true
		}
	}
	return false
}

// CheckPair reports why reader may not be listed as a reader of project, or nil
// when it may. Both paths are normalised first; the hub also checks that both
// are projects it serves and that the caller can see them, which this package
// cannot know.
func CheckPair(project, reader string) error {
	project, reader = NormalizePath(project), NormalizePath(reader)
	switch {
	case project == "" || reader == "":
		return fmt.Errorf("%w: a project and a reader are required", ErrInvalidPath)
	case project == reader:
		return ErrSelf
	case InsideControlDir(project):
		return fmt.Errorf("%w: %s is a feature or another working copy of a project — change the project's list instead", ErrFeature, project)
	case InsideControlDir(reader):
		return fmt.Errorf("%w: %s is a feature or another working copy of a project — name the project instead", ErrFeature, reader)
	}
	return nil
}

type pair struct{ project, reader string }

// Resolver answers questions about every readers list on the hub from one
// snapshot of them. It is immutable; a nil Resolver lists nothing and permits
// nothing.
type Resolver struct {
	entries   []Reader // ordered by project, then reader
	byPair    map[pair]int
	byProject map[string][]int
	byReader  map[string][]int
	skipped   []Reader
}

// New builds a Resolver from entries. An entry CheckPair refuses, or a second
// entry for a pair already seen, is left out and listed by Skipped.
func New(entries []Reader) *Resolver {
	r := &Resolver{byPair: map[pair]int{}, byProject: map[string][]int{}, byReader: map[string][]int{}}
	kept := make([]Reader, 0, len(entries))
	for _, e := range entries {
		e.ProjectPath, e.ReaderPath = NormalizePath(e.ProjectPath), NormalizePath(e.ReaderPath)
		if CheckPair(e.ProjectPath, e.ReaderPath) != nil {
			r.skipped = append(r.skipped, e)
			continue
		}
		kept = append(kept, e)
	}
	sort.SliceStable(kept, func(i, j int) bool {
		if kept[i].ProjectPath != kept[j].ProjectPath {
			return kept[i].ProjectPath < kept[j].ProjectPath
		}
		return kept[i].ReaderPath < kept[j].ReaderPath
	})
	for _, e := range kept {
		p := pair{e.ProjectPath, e.ReaderPath}
		if _, dup := r.byPair[p]; dup {
			r.skipped = append(r.skipped, e)
			continue
		}
		i := len(r.entries)
		r.entries = append(r.entries, e)
		r.byPair[p] = i
		r.byProject[e.ProjectPath] = append(r.byProject[e.ProjectPath], i)
		r.byReader[e.ReaderPath] = append(r.byReader[e.ReaderPath], i)
	}
	return r
}

// CanRead reports whether readerProject's runs may read targetProject: true
// only when targetProject's readers list names readerProject. False for
// everything else, a project asking about itself and a feature on either side
// included.
func (r *Resolver) CanRead(readerProject, targetProject string) bool {
	if r == nil {
		return false
	}
	reader, target := NormalizePath(readerProject), NormalizePath(targetProject)
	if CheckPair(target, reader) != nil {
		return false
	}
	_, ok := r.byPair[pair{target, reader}]
	return ok
}

// ReadableBy returns the projects whose readers lists name project — the
// projects its runs may read — ordered by path.
func (r *Resolver) ReadableBy(project string) []string {
	if r == nil {
		return nil
	}
	path := NormalizePath(project)
	if path == "" || InsideControlDir(path) {
		return nil
	}
	var out []string
	for _, i := range r.byReader[path] {
		out = append(out, r.entries[i].ProjectPath)
	}
	sort.Strings(out)
	return out
}

// ReadersOf returns project's readers list, ordered by reader.
func (r *Resolver) ReadersOf(project string) []Reader {
	if r == nil {
		return nil
	}
	path := NormalizePath(project)
	var out []Reader
	for _, i := range r.byProject[path] {
		out = append(out, r.entries[i])
	}
	return out
}

// EntriesReadableBy returns the entries naming project as a reader, ordered by
// the project they let it read.
func (r *Resolver) EntriesReadableBy(project string) []Reader {
	if r == nil {
		return nil
	}
	path := NormalizePath(project)
	if path == "" || InsideControlDir(path) {
		return nil
	}
	var out []Reader
	for _, i := range r.byReader[path] {
		out = append(out, r.entries[i])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ProjectPath < out[j].ProjectPath })
	return out
}

// Entry returns the entry letting reader read project, if there is one.
func (r *Resolver) Entry(project, reader string) (Reader, bool) {
	if r == nil {
		return Reader{}, false
	}
	i, ok := r.byPair[pair{NormalizePath(project), NormalizePath(reader)}]
	if !ok {
		return Reader{}, false
	}
	return r.entries[i], true
}

// All returns every entry, ordered by project then reader.
func (r *Resolver) All() []Reader {
	if r == nil {
		return nil
	}
	return append([]Reader(nil), r.entries...)
}

// Skipped returns the entries New left out: a pair CheckPair refuses, or a
// second entry for a pair. A caller loading the list reports them; none of
// them is honoured.
func (r *Resolver) Skipped() []Reader {
	if r == nil {
		return nil
	}
	return append([]Reader(nil), r.skipped...)
}

// ── the table ───────────────────────────────────────────────────────────────

// Audit builds the audit events committed together with a change; prev and
// next are nil when there was no entry before or after. See
// statedb.ReaderAudit.
type Audit func(prev, next *Reader) ([]*statedb.AuditEvent, error)

// Load reads every readers list on the hub from its control-plane database.
func Load(db *statedb.DB) (*Resolver, error) {
	if db == nil {
		return nil, errors.New("projectreaders: nil database")
	}
	rows, err := db.ListProjectReaders()
	if err != nil {
		return nil, fmt.Errorf("projectreaders: load: %w", err)
	}
	entries := make([]Reader, 0, len(rows))
	for _, row := range rows {
		entries = append(entries, fromRow(row))
	}
	return New(entries), nil
}

// Add lists reader on project's readers list and returns the entry. added is
// false when it was listed already; nothing is written then and audit is not
// called. The pair is checked first (CheckPair), so a refused pair never
// reaches the table.
func Add(db *statedb.DB, project, reader, addedBy string, audit Audit) (Reader, bool, error) {
	if db == nil {
		return Reader{}, false, errors.New("projectreaders: nil database")
	}
	if err := CheckPair(project, reader); err != nil {
		return Reader{}, false, err
	}
	row, added, err := db.AddProjectReader(statedb.ProjectReaderRow{
		ProjectPath: NormalizePath(project),
		ReaderPath:  NormalizePath(reader),
		AddedBy:     strings.TrimSpace(addedBy),
	}, rowAudit(audit))
	if err != nil {
		return Reader{}, false, fmt.Errorf("projectreaders: add: %w", err)
	}
	return fromRow(row), added, nil
}

// Remove takes reader off project's readers list and returns the entry, or nil
// when the list did not name it.
func Remove(db *statedb.DB, project, reader string, audit Audit) (*Reader, error) {
	if db == nil {
		return nil, errors.New("projectreaders: nil database")
	}
	path, who := NormalizePath(project), NormalizePath(reader)
	if path == "" || who == "" {
		return nil, fmt.Errorf("%w: a project and a reader are required", ErrInvalidPath)
	}
	row, err := db.RemoveProjectReader(path, who, rowAudit(audit))
	if err != nil {
		return nil, fmt.Errorf("projectreaders: remove: %w", err)
	}
	return fromRowPtr(row), nil
}

// RemoveByID takes the entry with id off project's readers list and returns
// it, or nil when that list has no such entry. An id from another project's
// list is not found.
func RemoveByID(db *statedb.DB, project, id string, audit Audit) (*Reader, error) {
	if db == nil {
		return nil, errors.New("projectreaders: nil database")
	}
	path := NormalizePath(project)
	if path == "" || strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("%w: a project and an entry id are required", ErrInvalidPath)
	}
	row, err := db.RemoveProjectReaderByID(path, id, rowAudit(audit))
	if err != nil {
		return nil, fmt.Errorf("projectreaders: remove: %w", err)
	}
	return fromRowPtr(row), nil
}

// RemoveProject removes every entry naming path on either side, for a project
// leaving the hub, and returns them.
func RemoveProject(db *statedb.DB, path string, audit Audit) ([]Reader, error) {
	if db == nil {
		return nil, errors.New("projectreaders: nil database")
	}
	path = NormalizePath(path)
	if path == "" {
		return nil, fmt.Errorf("%w: a project path is required", ErrInvalidPath)
	}
	rows, err := db.DeleteProjectReadersOf(path, rowAudit(audit))
	if err != nil {
		return nil, fmt.Errorf("projectreaders: remove the entries naming %s: %w", path, err)
	}
	out := make([]Reader, 0, len(rows))
	for _, row := range rows {
		out = append(out, fromRow(row))
	}
	return out, nil
}

func fromRow(row statedb.ProjectReaderRow) Reader {
	return Reader{
		ID:          row.ID,
		ProjectPath: NormalizePath(row.ProjectPath),
		ReaderPath:  NormalizePath(row.ReaderPath),
		AddedBy:     row.AddedBy,
		AddedAt:     row.AddedAt,
	}
}

func fromRowPtr(row *statedb.ProjectReaderRow) *Reader {
	if row == nil {
		return nil
	}
	r := fromRow(*row)
	return &r
}

func rowAudit(audit Audit) statedb.ReaderAudit {
	if audit == nil {
		return nil
	}
	return func(prev, next *statedb.ProjectReaderRow) ([]*statedb.AuditEvent, error) {
		return audit(fromRowPtr(prev), fromRowPtr(next))
	}
}
