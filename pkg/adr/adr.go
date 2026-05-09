// Package adr manages Architectural Decision Records — markdown files with
// YAML frontmatter that capture significant design choices, their context,
// and their consequences.
package adr

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Dir is the relative path inside a project where ADR files live.
const Dir = ".cloop/adr"

// Status values an ADR can carry. Free-form strings are also tolerated when
// reading, but writes funnel through these constants.
const (
	StatusProposed   = "Proposed"
	StatusAccepted   = "Accepted"
	StatusDeprecated = "Deprecated"
	StatusSuperseded = "Superseded"
	StatusRejected   = "Rejected"
)

// ADR is one decision record.
type ADR struct {
	ID            int       // sequential, 1-indexed
	Title         string    // human title
	Status        string    // Proposed/Accepted/Deprecated/Superseded/Rejected
	Date          time.Time // creation date
	Deciders      []string
	Tags          []string
	Supersedes    []int // ADR IDs this one replaces
	SupersededBy  []int // ADR IDs that replace this one
	Path          string // absolute file path
	Body          string // markdown body (after frontmatter)
}

// Slug turns a title into a filesystem-safe slug.
func Slug(title string) string {
	s := strings.ToLower(strings.TrimSpace(title))
	re := regexp.MustCompile(`[^a-z0-9]+`)
	s = re.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "untitled"
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// Filename for a given ID and title (e.g. "0007-use-sqlite-for-state.md").
func Filename(id int, title string) string {
	return fmt.Sprintf("%04d-%s.md", id, Slug(title))
}

// EnsureDir creates the ADR directory if needed.
func EnsureDir(workdir string) (string, error) {
	dir := filepath.Join(workdir, Dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating ADR dir: %w", err)
	}
	return dir, nil
}

// NextID returns the smallest unused 1-indexed ID in the ADR directory.
func NextID(workdir string) (int, error) {
	all, err := List(workdir)
	if err != nil {
		return 0, err
	}
	max := 0
	for _, a := range all {
		if a.ID > max {
			max = a.ID
		}
	}
	return max + 1, nil
}

// List loads all ADRs sorted by ID ascending. Returns an empty slice (not error)
// if the directory does not exist.
func List(workdir string) ([]*ADR, error) {
	dir := filepath.Join(workdir, Dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var adrs []*ADR
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		full := filepath.Join(dir, e.Name())
		a, err := Load(full)
		if err != nil {
			// Skip malformed files but don't fail the whole listing.
			continue
		}
		adrs = append(adrs, a)
	}
	sort.Slice(adrs, func(i, j int) bool { return adrs[i].ID < adrs[j].ID })
	return adrs, nil
}

// FindByID resolves an ADR by its numeric ID.
func FindByID(workdir string, id int) (*ADR, error) {
	all, err := List(workdir)
	if err != nil {
		return nil, err
	}
	for _, a := range all {
		if a.ID == id {
			return a, nil
		}
	}
	return nil, fmt.Errorf("ADR %d not found", id)
}

// Load parses an ADR markdown file with YAML frontmatter.
func Load(path string) (*ADR, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	a := &ADR{Path: path}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	// State machine: 0 = expect opening "---", 1 = inside frontmatter, 2 = body.
	state := 0
	var bodyLines []string
	for scanner.Scan() {
		line := scanner.Text()
		switch state {
		case 0:
			if strings.TrimSpace(line) == "---" {
				state = 1
			} else {
				// No frontmatter — treat the whole thing as body and infer
				// the ID/title from the filename.
				bodyLines = append(bodyLines, line)
				state = 2
			}
		case 1:
			if strings.TrimSpace(line) == "---" {
				state = 2
				continue
			}
			parseFrontmatterLine(a, line)
		case 2:
			bodyLines = append(bodyLines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Backfill ID/title from filename if missing.
	if a.ID == 0 || a.Title == "" {
		base := filepath.Base(path)
		if id, title, ok := parseFilename(base); ok {
			if a.ID == 0 {
				a.ID = id
			}
			if a.Title == "" {
				a.Title = title
			}
		}
	}
	a.Body = strings.Join(bodyLines, "\n")
	return a, nil
}

var filenameRE = regexp.MustCompile(`^(\d+)-(.+)\.md$`)

func parseFilename(name string) (int, string, bool) {
	m := filenameRE.FindStringSubmatch(name)
	if len(m) != 3 {
		return 0, "", false
	}
	var id int
	fmt.Sscanf(m[1], "%d", &id)
	return id, strings.ReplaceAll(m[2], "-", " "), true
}

func parseFrontmatterLine(a *ADR, line string) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return
	}
	key := strings.TrimSpace(line[:idx])
	val := strings.TrimSpace(line[idx+1:])
	val = strings.Trim(val, `"'`)
	switch strings.ToLower(key) {
	case "id":
		fmt.Sscanf(val, "%d", &a.ID)
	case "title":
		a.Title = val
	case "status":
		a.Status = val
	case "date":
		if t, err := time.Parse("2006-01-02", val); err == nil {
			a.Date = t
		} else if t, err := time.Parse(time.RFC3339, val); err == nil {
			a.Date = t
		}
	case "deciders":
		a.Deciders = splitList(val)
	case "tags":
		a.Tags = splitList(val)
	case "supersedes":
		a.Supersedes = splitIntList(val)
	case "superseded_by", "superseded-by":
		a.SupersededBy = splitIntList(val)
	}
}

func splitList(v string) []string {
	v = strings.Trim(v, "[]")
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	var out []string
	for _, p := range parts {
		p = strings.Trim(strings.TrimSpace(p), `"'`)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitIntList(v string) []int {
	parts := splitList(v)
	var out []int
	for _, p := range parts {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err == nil && n > 0 {
			out = append(out, n)
		}
	}
	return out
}

// Save writes the ADR back to its file. If Path is empty, the caller must set
// it before calling.
//
// The write is atomic: data is staged in a sibling .tmp file, fsynced, chmod'd,
// then renamed into place. Without this, a crash mid-write — or two writers
// racing on a Status update (e.g. one process accepting, another deprecating)
// — would leave the markdown frontmatter half-written and unparseable, which
// would silently drop the ADR from listings on the next read.
func (a *ADR) Save() error {
	if a.Path == "" {
		return errors.New("ADR has no path")
	}
	if a.Date.IsZero() {
		a.Date = time.Now()
	}
	if a.Status == "" {
		a.Status = StatusProposed
	}
	var sb strings.Builder
	sb.WriteString("---\n")
	fmt.Fprintf(&sb, "id: %d\n", a.ID)
	fmt.Fprintf(&sb, "title: %q\n", a.Title)
	fmt.Fprintf(&sb, "status: %s\n", a.Status)
	fmt.Fprintf(&sb, "date: %s\n", a.Date.Format("2006-01-02"))
	if len(a.Deciders) > 0 {
		fmt.Fprintf(&sb, "deciders: [%s]\n", joinQuoted(a.Deciders))
	}
	if len(a.Tags) > 0 {
		fmt.Fprintf(&sb, "tags: [%s]\n", joinQuoted(a.Tags))
	}
	if len(a.Supersedes) > 0 {
		fmt.Fprintf(&sb, "supersedes: [%s]\n", joinInts(a.Supersedes))
	}
	if len(a.SupersededBy) > 0 {
		fmt.Fprintf(&sb, "superseded_by: [%s]\n", joinInts(a.SupersededBy))
	}
	sb.WriteString("---\n")
	body := strings.TrimLeft(a.Body, "\n")
	sb.WriteString(body)
	if !strings.HasSuffix(body, "\n") {
		sb.WriteString("\n")
	}
	dir := filepath.Dir(a.Path)
	return writeAtomic(dir, a.Path, []byte(sb.String()), 0o644)
}

// writeAtomic stages data in a sibling .tmp file in dir, fsyncs, chmods, then
// renames into path. POSIX rename is atomic with respect to readers, so
// concurrent readers always observe either the previous valid file or the new
// one — never a truncated one. The cleanup defer removes any leftover tmp
// file on error, so a failed write leaves the original at path intact.
func writeAtomic(dir, path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(dir, ".adr.*.tmp")
	if err != nil {
		return fmt.Errorf("adr: create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("adr: write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("adr: sync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("adr: close tmp: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("adr: chmod tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("adr: rename tmp: %w", err)
	}
	return nil
}

func joinQuoted(items []string) string {
	parts := make([]string, len(items))
	for i, s := range items {
		parts[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(parts, ", ")
}

func joinInts(items []int) string {
	parts := make([]string, len(items))
	for i, n := range items {
		parts[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(parts, ", ")
}

// Template returns the default body for a newly created ADR.
func Template(title string) string {
	return fmt.Sprintf(`# ADR-%s: %s

## Context

What is the problem? What forces are at play (technical, political, social,
project-local)? What are we trying to optimize for?

## Decision

What is the change we are proposing or making?

## Consequences

What becomes easier or harder as a result of this decision?

### Positive

-

### Negative

-

### Neutral / Trade-offs

-

## Alternatives Considered

-
`, "XXXX", title)
}

// Create writes a brand-new ADR with the given title and optional body.
// If body is empty, the default template is used. Returns the saved ADR.
func Create(workdir, title, body string) (*ADR, error) {
	if strings.TrimSpace(title) == "" {
		return nil, errors.New("title is required")
	}
	dir, err := EnsureDir(workdir)
	if err != nil {
		return nil, err
	}
	id, err := NextID(workdir)
	if err != nil {
		return nil, err
	}
	if body == "" {
		body = Template(title)
	}
	// Replace placeholder XXXX in the template heading with the real ID.
	body = strings.Replace(body, "ADR-XXXX", fmt.Sprintf("ADR-%04d", id), 1)

	a := &ADR{
		ID:     id,
		Title:  title,
		Status: StatusProposed,
		Date:   time.Now(),
		Path:   filepath.Join(dir, Filename(id, title)),
		Body:   body,
	}
	if err := a.Save(); err != nil {
		return nil, err
	}
	return a, nil
}

// SetStatus updates the status field and persists the file.
func (a *ADR) SetStatus(s string) error {
	a.Status = s
	return a.Save()
}

// LinkSupersedes wires this ADR to mark `oldID` as superseded by `a.ID`,
// updating both files. If the old ADR cannot be loaded, returns an error.
func LinkSupersedes(workdir string, newID, oldID int) error {
	if newID == oldID {
		return errors.New("ADR cannot supersede itself")
	}
	newADR, err := FindByID(workdir, newID)
	if err != nil {
		return fmt.Errorf("new ADR: %w", err)
	}
	oldADR, err := FindByID(workdir, oldID)
	if err != nil {
		return fmt.Errorf("old ADR: %w", err)
	}
	if !containsInt(newADR.Supersedes, oldID) {
		newADR.Supersedes = append(newADR.Supersedes, oldID)
	}
	if !containsInt(oldADR.SupersededBy, newID) {
		oldADR.SupersededBy = append(oldADR.SupersededBy, newID)
	}
	oldADR.Status = StatusSuperseded
	if err := newADR.Save(); err != nil {
		return err
	}
	return oldADR.Save()
}

func containsInt(haystack []int, needle int) bool {
	for _, n := range haystack {
		if n == needle {
			return true
		}
	}
	return false
}
