package projectmove

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// File categories under a project's .cloop directory that no database holds.
// The values are stable: they are Item names in the report.
const (
	FilesArtifacts        = "artifacts"
	FilesAttachmentOutbox = "attachment_outbox"
	FilesAttachments      = "attachment_files"
	FilesCheckpoints      = "checkpoints"
	FilesSandboxSpec      = "sandbox_spec"
	FilesRequirementsSpec = "requirements_spec"
	FilesConfig           = "config"
	FilesOther            = "other"
)

// categoryLabels say what each category is, for the report.
var categoryLabels = map[string]string{
	FilesArtifacts:        "task output and artifacts (.cloop/artifacts, .cloop/tasks)",
	FilesAttachmentOutbox: "files a run left for attaching that no run has attached yet (.cloop/attachments/outbox)",
	FilesAttachments:      "attachment contents; the database holds their records, not their bytes (.cloop/attachments)",
	FilesCheckpoints:      "task checkpoints (.cloop/checkpoints)",
	FilesSandboxSpec:      "the sandbox spec (.cloop/sandbox.yaml)",
	FilesRequirementsSpec: "the requirements spec file (.cloop/requirements.yaml)",
	FilesConfig:           "the project's configuration (.cloop/config.yaml)",
	FilesOther:            "other files under .cloop",
}

// maxInventoryEntries bounds the walk: a .cloop directory with more entries
// than this is reported as cut, the counts then being lower bounds.
const maxInventoryEntries = 200_000

// FileInventory is what one .cloop directory holds outside any database.
type FileInventory struct {
	// Dir is the .cloop directory walked.
	Dir string
	// Categories are the non-empty categories, in a fixed order.
	Categories []FileCategory
	// Links counts symbolic links met and not followed.
	Links int
	// Truncated reports the walk stopped at maxInventoryEntries.
	Truncated bool
	// Error is why the directory could not be walked, when it could not.
	Error string
}

// FileCategory is one category's tally.
type FileCategory struct {
	Name     string
	Files    int
	Bytes    int64
	Examples []string
}

// Empty reports that the inventory found nothing.
func (inv FileInventory) Empty() bool { return len(inv.Categories) == 0 }

// Files sums the categories' file counts.
func (inv FileInventory) Files() (n int, bytes int64) {
	for _, c := range inv.Categories {
		n += c.Files
		bytes += c.Bytes
	}
	return n, bytes
}

// Category returns the named category's tally.
func (inv FileInventory) Category(name string) (FileCategory, bool) {
	for _, c := range inv.Categories {
		if c.Name == name {
			return c, true
		}
	}
	return FileCategory{}, false
}

// inDatabase lists entries directly under .cloop that are a database, or the
// database's own working files: what the hub holds of the project already.
var inDatabase = map[string]bool{
	"state.db": true, "state.db-wal": true, "state.db-shm": true, "state.db-journal": true,
	// The legacy JSON state is migrated into the database on open.
	"state.json": true,
}

// notFiles lists entries directly under .cloop the inventory leaves to other
// checks: features are separate projects with their own .cloop directories,
// and worktrees are git's, inspected as working trees.
var notFiles = map[string]bool{
	"features":  true,
	"worktrees": true,
}

// categorize returns the category of a path relative to .cloop.
func categorize(rel string) string {
	first, rest, _ := strings.Cut(rel, "/")
	switch first {
	case "artifacts", "tasks":
		return FilesArtifacts
	case "attachments":
		if rest == "outbox" || strings.HasPrefix(rest, "outbox/") {
			return FilesAttachmentOutbox
		}
		return FilesAttachments
	case "checkpoints":
		return FilesCheckpoints
	case "sandbox.yaml":
		if rest == "" {
			return FilesSandboxSpec
		}
	case "requirements.yaml":
		if rest == "" {
			return FilesRequirementsSpec
		}
	case "config.yaml":
		if rest == "" {
			return FilesConfig
		}
	}
	return FilesOther
}

// categoryOrder is the order categories are reported in.
var categoryOrder = []string{
	FilesArtifacts, FilesAttachmentOutbox, FilesAttachments, FilesCheckpoints,
	FilesSandboxSpec, FilesRequirementsSpec, FilesConfig, FilesOther,
}

// maxExamples bounds how many paths each category quotes.
const maxExamples = 5

// InventoryFiles tallies the files under projectDir/.cloop that no database
// holds.
//
// It only stats: nothing is opened or read, and no symbolic link is followed —
// the directory may be one a sandbox can write (a container-bound project's),
// and a planted link must not turn the inventory into a walk of the hub.
func InventoryFiles(projectDir string) FileInventory {
	root := filepath.Join(projectDir, ".cloop")
	inv := FileInventory{Dir: root}
	info, err := os.Lstat(root)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return inv
	case err != nil:
		inv.Error = err.Error()
		return inv
	case info.Mode()&os.ModeSymlink != 0:
		inv.Links = 1
		inv.Error = ".cloop is a symbolic link, which is not followed"
		return inv
	case !info.IsDir():
		inv.Error = ".cloop is not a directory"
		return inv
	}
	tally := map[string]*FileCategory{}
	seen := 0
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return err
			}
			// An unreadable subdirectory is skipped, not fatal: what the
			// rest holds is still worth reporting.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if path == root {
			return nil
		}
		seen++
		if seen > maxInventoryEntries {
			inv.Truncated = true
			return fs.SkipAll
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if !strings.Contains(rel, "/") {
			if inDatabase[rel] || notFiles[rel] {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}
		if d.Type()&fs.ModeSymlink != 0 {
			inv.Links++
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		fi, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		name := categorize(rel)
		c := tally[name]
		if c == nil {
			c = &FileCategory{Name: name}
			tally[name] = c
		}
		c.Files++
		c.Bytes += fi.Size()
		if len(c.Examples) < maxExamples {
			c.Examples = append(c.Examples, ".cloop/"+rel)
		}
		return nil
	})
	if walkErr != nil {
		inv.Error = walkErr.Error()
	}
	for _, name := range categoryOrder {
		if c := tally[name]; c != nil {
			sort.Strings(c.Examples)
			inv.Categories = append(inv.Categories, *c)
		}
	}
	return inv
}
