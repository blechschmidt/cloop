package projectmove

// seed.go is the half of a move that runs on the target (Task 20494).
//
// A target that keeps a working copy between runs — a device, or a virtual
// executor on one — is seeded through the branch-bundle workspace a feature
// travels in (executor.BranchBundle): the hub ships one branch,
// cloop/move/<id>, whose single commit holds three files — the move's
// manifest, the repository bundle and the tar of .cloop files — and the device
// provisions the project's working directory from it exactly as it provisions
// a feature's. Then `cloop workspace move-seed` runs in that directory and
// turns it into the project's working copy: every ref of the bundle fetched,
// HEAD back on the original branch, the snapshot replayed as uncommitted
// changes, the .cloop files extracted, the carrier branch gone. It prints what
// it built as a report line; `cloop workspace move-verify` prints the same
// report for a working copy as it stands, which is what the hub's
// verification compares with the capture.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/movegit"
)

// The carrier's files.
const (
	CarrierManifest = "move.json"
	CarrierBundle   = "repo.bundle"
	CarrierFiles    = "cloop-files.tar"
)

// ReportMarker starts the line a seed, a verification or a probe prints its
// report on.
const ReportMarker = "CLOOP_MOVE_REPORT "

// MovedInFile is the record a seed leaves in the working copy's .cloop: which
// move built it, and the files it delivered.
const MovedInFile = "moved-in.json"

// MovingInFile marks a working copy a seed has started to build, with the
// move's id: written before the seed changes anything and removed once
// MovedInFile is in place, so a seed stopped half-way is recognised as that
// move's — redone, not refused as somebody's work.
const MovingInFile = "moving-in"

// maxManifestBytes bounds the carrier's manifest.
const maxManifestBytes = 32 << 20

// CarrierBranch is the branch a move's carrier ships on: under cloop/, as a
// shipped branch must be.
func CarrierBranch(moveID string) string { return "cloop/move/" + moveID }

// SeedManifest is the carrier's move.json.
type SeedManifest struct {
	MoveID string           `json:"move_id"`
	Git    movegit.Manifest `json:"git"`
	Files  []File           `json:"files,omitempty"`
	// FilesTar is the tar's digest.
	FilesTar *movegit.Digest `json:"files_tar,omitempty"`
	// Upstream is the route the hub dispatches the project's runs with, set
	// as the copy's origin so its next run recognises the checkout.
	Upstream string `json:"upstream,omitempty"`
}

// movedIn is MovedInFile's content.
type movedIn struct {
	MoveID string `json:"move_id"`
	Files  []File `json:"files,omitempty"`
}

// WorkingCopyReport is what a seed, a verification or a probe reports about
// a working copy.
type WorkingCopyReport struct {
	MoveID string `json:"move_id"`
	// Probe results: whether the directory holds nothing, which move seeded
	// it, which move's seed started on it and did not finish, and whether it
	// is still on a carrier branch of this move.
	Empty     bool     `json:"empty,omitempty"`
	SeededBy  string   `json:"seeded_by,omitempty"`
	Seeding   string   `json:"seeding,omitempty"`
	OnCarrier bool     `json:"on_carrier,omitempty"`
	Entries   int      `json:"entries,omitempty"`
	Examples  []string `json:"examples,omitempty"`
	// Git is the repository as it is; Files the delivered files' digests.
	Git   movegit.Observed          `json:"git"`
	Files map[string]movegit.Digest `json:"files,omitempty"`
	// Problems are files that could not be read.
	Problems []string `json:"problems,omitempty"`
}

// SeedWorkingCopy turns dir — provisioned from the move's carrier branch —
// into the project's working copy, and reports it. Run again on a copy this
// move already seeded, it only reports.
func SeedWorkingCopy(ctx context.Context, dir, moveID string) (WorkingCopyReport, error) {
	if !movegit.ValidMoveID(moveID) {
		return WorkingCopyReport{}, fmt.Errorf("projectmove: %q is not a move id", moveID)
	}
	dir = filepath.Clean(dir)
	branch, err := movegit.CurrentBranch(ctx, dir)
	if err != nil {
		if rec, ok := readMovedIn(dir); ok && rec.MoveID == moveID {
			return ReportWorkingCopy(ctx, dir, moveID)
		}
		return WorkingCopyReport{}, fmt.Errorf("projectmove: %s is not on the move's carrier: %w", dir, err)
	}
	if branch != "refs/heads/"+CarrierBranch(moveID) {
		if rec, ok := readMovedIn(dir); ok && rec.MoveID == moveID {
			return ReportWorkingCopy(ctx, dir, moveID)
		}
		return WorkingCopyReport{}, fmt.Errorf("projectmove: %s is on %q, not on the move's carrier %s", dir, branch, CarrierBranch(moveID))
	}

	scratch, err := os.MkdirTemp("", "cloop-move-seed-*")
	if err != nil {
		return WorkingCopyReport{}, fmt.Errorf("projectmove: %w", err)
	}
	defer os.RemoveAll(scratch)
	manifestPath := filepath.Join(scratch, CarrierManifest)
	if err := movegit.ReadCarrierFile(ctx, dir, "HEAD", CarrierManifest, manifestPath, maxManifestBytes); err != nil {
		return WorkingCopyReport{}, err
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return WorkingCopyReport{}, fmt.Errorf("projectmove: %w", err)
	}
	var sm SeedManifest
	if err := json.Unmarshal(raw, &sm); err != nil {
		return WorkingCopyReport{}, fmt.Errorf("projectmove: the carrier's manifest does not decode: %w", err)
	}
	if sm.MoveID != moveID {
		return WorkingCopyReport{}, fmt.Errorf("projectmove: the carrier is move %s's, not %s's", sm.MoveID, moveID)
	}
	cloopDir := filepath.Join(dir, ".cloop")
	if err := ensureDir(cloopDir); err != nil {
		return WorkingCopyReport{}, err
	}
	if err := writeFileAtomic(filepath.Join(cloopDir, MovingInFile), []byte(moveID)); err != nil {
		return WorkingCopyReport{}, err
	}
	tarPath := filepath.Join(scratch, CarrierFiles)
	if err := movegit.ReadCarrierFile(ctx, dir, "HEAD", CarrierFiles, tarPath, executor.MaxBranchBundleBytes); err != nil {
		return WorkingCopyReport{}, err
	}
	if sm.FilesTar != nil {
		if err := movegit.VerifyFile(tarPath, *sm.FilesTar); err != nil {
			return WorkingCopyReport{}, err
		}
	}

	if sm.Git.Repository {
		bundle := filepath.Join(scratch, CarrierBundle)
		if err := movegit.ReadCarrierFile(ctx, dir, "HEAD", CarrierBundle, bundle, executor.MaxBranchBundleBytes); err != nil {
			return WorkingCopyReport{}, err
		}
		if err := movegit.Restore(ctx, movegit.RestoreOptions{Dir: dir, BundlePath: bundle, Manifest: sm.Git, Upstream: sm.Upstream}); err != nil {
			return WorkingCopyReport{}, err
		}
		if err := movegit.DeleteRef(ctx, dir, "refs/heads/"+CarrierBranch(moveID)); err != nil {
			return WorkingCopyReport{}, err
		}
	} else {
		// The project has no repository: the one the carrier arrived in is
		// the transport's, and goes, with the carrier's files.
		for _, name := range []string{CarrierManifest, CarrierBundle, CarrierFiles} {
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return WorkingCopyReport{}, fmt.Errorf("projectmove: %w", err)
			}
		}
		if err := os.RemoveAll(filepath.Join(dir, ".git")); err != nil {
			return WorkingCopyReport{}, fmt.Errorf("projectmove: %w", err)
		}
	}

	if err := ExtractFiles(tarPath, cloopDir, sm.Files); err != nil {
		return WorkingCopyReport{}, err
	}
	rec, err := json.Marshal(movedIn{MoveID: moveID, Files: sm.Files})
	if err != nil {
		return WorkingCopyReport{}, fmt.Errorf("projectmove: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(cloopDir, MovedInFile), rec); err != nil {
		return WorkingCopyReport{}, err
	}
	if err := os.Remove(filepath.Join(cloopDir, MovingInFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return WorkingCopyReport{}, fmt.Errorf("projectmove: %w", err)
	}
	return ReportWorkingCopy(ctx, dir, moveID)
}

// ErrHubDirOccupied refuses to seed the hub's directory for a project that
// already holds files besides .cloop.
var ErrHubDirOccupied = errors.New("projectmove: the hub's directory for the project holds files a move never overwrites")

// HubDirEntries lists what dir holds besides the hub's own bookkeeping — its
// .cloop directory, and a .gitignore naming nothing but paths under .cloop,
// which `cloop init` writes — sorted: the entries a seed of the hub's own
// directory would have to overwrite.
func HubDirEntries(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("projectmove: %w", err)
	}
	var out []string
	for _, e := range entries {
		switch e.Name() {
		case ".cloop":
			continue
		case ".gitignore":
			if _, own := cloopOwnGitignore(dir); own {
				continue
			}
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out, nil
}

// maxOwnGitignore bounds the .gitignore cloopOwnGitignore reads.
const maxOwnGitignore = 64 << 10

// cloopOwnGitignore reports whether dir's .gitignore is the hub's own — a
// regular file whose every pattern names a path under .cloop — and returns
// its patterns.
func cloopOwnGitignore(dir string) ([]string, bool) {
	f, err := openNoFollow(filepath.Join(dir, ".gitignore"))
	if err != nil {
		return nil, false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxOwnGitignore {
		return nil, false
	}
	raw := make([]byte, fi.Size())
	if n, _ := io.ReadFull(f, raw); int64(n) != fi.Size() {
		return nil, false
	}
	var patterns []string
	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		p := strings.TrimPrefix(t, "/")
		if p != ".cloop" && p != ".cloop/" && !strings.HasPrefix(p, ".cloop/") {
			return nil, false
		}
		patterns = append(patterns, t)
	}
	return patterns, true
}

// HubTreeReserved is what a working copy built in the hub's own directory for
// a project may hold of .cloop: the requirements spec and the sandbox spec,
// which a project commits by design, and nothing else — never the project's
// database or configuration, which the hub keeps there. A capture from a
// device is held to it before it is accepted, and again before it is restored.
var HubTreeReserved = movegit.Reserved{Dir: ".cloop", Allow: []string{"requirements.yaml", "sandbox.yaml"}}

// SeedHubTree builds the working copy a capture recorded in dir, the hub's own
// directory for the project, for a move from a device's working copy or a
// pool runner's volume onto an executor that works in the hub's tree (Task
// 20495): the repository rebuilt from the capture's bundle — every ref, HEAD
// on its branch, the uncommitted state put back as it was — and the .cloop
// files extracted beside the hub's own. The capture's bundle and tar are read
// from c.Store and checked against their digests first.
//
// A directory holding anything besides .cloop is refused with
// ErrHubDirOccupied, unless it is this move's own seed, stopped part-way;
// one this move already finished seeding is left as it is.
func SeedHubTree(ctx context.Context, dir, moveID string, c *CaptureRecord, upstream string) error {
	if c == nil {
		return errors.New("projectmove: no capture to seed the hub's directory with")
	}
	if rec, ok := readMovedIn(dir); ok && rec.MoveID == moveID {
		return nil
	}
	entries, err := HubDirEntries(dir)
	if err != nil {
		return err
	}
	if seeding, _ := readMovingIn(dir); len(entries) > 0 && seeding != moveID {
		shown := entries
		if len(shown) > maxExamples {
			shown = shown[:maxExamples]
		}
		return fmt.Errorf("%w: %s holds %s", ErrHubDirOccupied, dir, strings.Join(shown, ", "))
	}
	cloopDir := filepath.Join(dir, ".cloop")
	if err := ensureDir(cloopDir); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(cloopDir, MovingInFile), []byte(moveID)); err != nil {
		return err
	}
	if c.Git.Repository {
		// The hub's own .gitignore names only paths under .cloop, which the
		// rebuilt repository excludes whole (below): it makes way for the
		// source's tree, which may hold a .gitignore of its own.
		if _, isOwn := cloopOwnGitignore(dir); isOwn {
			if err := os.Remove(filepath.Join(dir, ".gitignore")); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("projectmove: %w", err)
			}
		}
		if err := movegit.Restore(ctx, movegit.RestoreOptions{Dir: dir, BundlePath: filepath.Join(c.Store, c.Bundle),
			Manifest: c.Git, Upstream: upstream, Reserve: &HubTreeReserved}); err != nil {
			return err
		}
		// The hub's bookkeeping is not the project's work: a run committing
		// everything in the tree must not commit the project's database.
		if err := excludeCloop(dir); err != nil {
			return err
		}
	}
	if c.FilesTar != "" {
		tarPath := filepath.Join(c.Store, c.FilesTar)
		if c.TarSum != nil {
			if err := movegit.VerifyFile(tarPath, *c.TarSum); err != nil {
				return err
			}
		}
		if err := ExtractFiles(tarPath, cloopDir, c.Files); err != nil {
			return err
		}
	}
	rec, err := json.Marshal(movedIn{MoveID: moveID, Files: c.Files})
	if err != nil {
		return fmt.Errorf("projectmove: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(cloopDir, MovedInFile), rec); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(cloopDir, MovingInFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("projectmove: %w", err)
	}
	return nil
}

// excludeCloop adds .cloop to a repository's info/exclude, once.
func excludeCloop(dir string) error {
	info := filepath.Join(dir, ".git", "info")
	if err := ensureDir(info); err != nil {
		return err
	}
	p := filepath.Join(info, "exclude")
	if li, err := os.Lstat(p); err == nil && !li.Mode().IsRegular() {
		return fmt.Errorf("projectmove: %s is not a regular file", p)
	}
	old, err := os.ReadFile(p)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("projectmove: %w", err)
	}
	for _, line := range strings.Split(string(old), "\n") {
		if t := strings.TrimSpace(line); t == "/.cloop/" || t == ".cloop/" || t == "/.cloop" || t == ".cloop" {
			return nil
		}
	}
	text := string(old)
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return writeFileAtomic(p, []byte(text+"/.cloop/\n"))
}

// ReportWorkingCopy reports a working copy a move seeded, as it stands.
func ReportWorkingCopy(ctx context.Context, dir, moveID string) (WorkingCopyReport, error) {
	r := WorkingCopyReport{MoveID: moveID}
	rec, ok := readMovedIn(dir)
	if !ok {
		return r, fmt.Errorf("projectmove: %s records no move that seeded it", dir)
	}
	r.SeededBy = rec.MoveID
	o, err := movegit.Inspect(ctx, dir, movegit.InspectOptions{})
	if err != nil {
		return r, err
	}
	r.Git = o
	r.Files = map[string]movegit.Digest{}
	for _, f := range rec.Files {
		if !cleanRel(f.Path) {
			r.Problems = append(r.Problems, f.Path+": not a plain relative path")
			continue
		}
		p := filepath.Join(dir, ".cloop", filepath.FromSlash(f.Path))
		fh, err := openNoFollow(p)
		if err != nil {
			r.Problems = append(r.Problems, ".cloop/"+f.Path+": "+err.Error())
			continue
		}
		fh.Close()
		d, err := movegit.FileDigest(p)
		if err != nil {
			r.Problems = append(r.Problems, ".cloop/"+f.Path+": "+err.Error())
			continue
		}
		r.Files[f.Path] = d
	}
	return r, nil
}

// ProbeWorkingCopy says what dir holds before a seed: nothing, a copy this
// move already seeded or started to, or something else — which a move never
// overwrites.
func ProbeWorkingCopy(ctx context.Context, dir, moveID string) (WorkingCopyReport, error) {
	r := WorkingCopyReport{MoveID: moveID}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		r.Empty = true
		return r, nil
	}
	if err != nil {
		return r, fmt.Errorf("projectmove: %w", err)
	}
	r.Entries = len(entries)
	if len(entries) == 0 {
		r.Empty = true
		return r, nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if len(names) > maxExamples {
		names = names[:maxExamples]
	}
	r.Examples = names
	if rec, ok := readMovedIn(dir); ok {
		r.SeededBy = rec.MoveID
	}
	if id, ok := readMovingIn(dir); ok {
		r.Seeding = id
	}
	if branch, err := movegit.CurrentBranch(ctx, dir); err == nil && branch == "refs/heads/"+CarrierBranch(moveID) {
		r.OnCarrier = true
	}
	return r, nil
}

// readMovedIn reads the seed's record from dir's .cloop.
func readMovedIn(dir string) (movedIn, bool) {
	f, err := openNoFollow(filepath.Join(dir, ".cloop", MovedInFile))
	if err != nil {
		return movedIn{}, false
	}
	defer f.Close()
	var rec movedIn
	if err := json.NewDecoder(f).Decode(&rec); err != nil || rec.MoveID == "" {
		return movedIn{}, false
	}
	return rec, true
}

// readMovingIn reads which move's seed started on dir.
func readMovingIn(dir string) (string, bool) {
	f, err := openNoFollow(filepath.Join(dir, ".cloop", MovingInFile))
	if err != nil {
		return "", false
	}
	defer f.Close()
	b := make([]byte, 64)
	n, _ := f.Read(b)
	id := strings.TrimSpace(string(b[:n]))
	if !movegit.ValidMoveID(id) {
		return "", false
	}
	return id, true
}

// writeFileAtomic writes data to p through a temporary file beside it.
func writeFileAtomic(p string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(p), ".move-*")
	if err != nil {
		return fmt.Errorf("projectmove: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return fmt.Errorf("projectmove: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("projectmove: %w", err)
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("projectmove: %w", err)
	}
	return nil
}

// FormatReport renders a report as the line a command prints.
func FormatReport(r WorkingCopyReport) (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return ReportMarker + string(b), nil
}

// ParseReport finds the last report line in a workload's output.
func ParseReport(output string) (WorkingCopyReport, error) {
	idx := strings.LastIndex(output, ReportMarker)
	if idx < 0 {
		return WorkingCopyReport{}, errors.New("projectmove: the workload printed no report")
	}
	line := output[idx+len(ReportMarker):]
	if nl := strings.IndexByte(line, '\n'); nl >= 0 {
		line = line[:nl]
	}
	var r WorkingCopyReport
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &r); err != nil {
		return WorkingCopyReport{}, fmt.Errorf("projectmove: the workload's report does not decode: %w", err)
	}
	return r, nil
}

// CompareReport checks a target's report against what was captured: the
// repository through movegit.Compare, and every delivered file's digest.
func CompareReport(c *CaptureRecord, r WorkingCopyReport) []string {
	var out []string
	if c == nil {
		return []string{"nothing was captured to compare with"}
	}
	for _, mm := range movegit.Compare(c.Git, r.Git) {
		out = append(out, mm.String())
	}
	if !c.Git.Repository && r.Git.Repository {
		out = append(out, "the working copy holds a repository the source did not have")
	}
	for _, f := range c.Files {
		got, ok := r.Files[f.Path]
		switch {
		case !ok:
			out = append(out, ".cloop/"+f.Path+": missing")
		case got.Bytes != f.Bytes || got.SHA256 != f.SHA256:
			out = append(out, fmt.Sprintf(".cloop/%s: %d bytes with digest %s, want %d with %s", f.Path, got.Bytes, short16(got.SHA256), f.Bytes, short16(f.SHA256)))
		}
	}
	out = append(out, r.Problems...)
	return out
}
