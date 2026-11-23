package attachments

// held.go: files a seeded run sent the hub while it ran, before the hub knows
// which of its tasks they belong to (Task 20513).
//
// A run whose project was seeded into its sandbox — on an edge device, in a
// Kubernetes Pod — attaches files in its own copy of the project. Until this
// file, the only way those files reached the hub was inside the run's result,
// one transport frame that carries at most 384 KiB of them; everything else
// was recorded on the hub without its bytes. Now the run sends each file to
// the hub as soon as it is attached, over its run session. The hub attaches it
// to the task straight away when it can tell which task that is, and otherwise
// holds it here until the run's result says: a task the run created has an id
// the hub may have given to another task, and only the merge, which renumbers
// such tasks, knows where it went.
//
//	<store>/held/<run key>/<id>        the file, as the run sent it
//	<store>/held/<run key>/<id>.json   what the run said about it (HeldFile)
//
// The run key is a digest of the run's id, so a run id of any shape names one
// directory, and the id is the run's own id for the attachment — the id the
// hub records it under, which is what makes a file that arrives twice (sent,
// and also carried in the result) one attachment rather than two.
//
// Everything here goes through the store's os.Root, like the rest of the
// store, and every file is checked to be a regular file both before and after
// it is opened: the hub is often root, and the store is in reach of any
// workload that ever ran this project on a shared-filesystem executor.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// HeldDirName is the store's subdirectory holding what seeded runs sent.
const HeldDirName = "held"

// MaxHeldPerRun bounds the files the hub holds for one run: as many as one
// run's result may describe.
const MaxHeldPerRun = 200

// maxHeldMetaBytes bounds a held file's description as it is read back.
const maxHeldMetaBytes = 8 << 10

// HeldFile is one file a run sent that the hub holds for it, as the run
// described it.
type HeldFile struct {
	// ID is the run's own id for the attachment, and the id the hub records
	// it under.
	ID string `json:"id"`
	// Task is the task's id in the run's plan, and TitleSHA256 the SHA-256 of
	// its title there (knowledgerun.TitleDigest): the run's task may be one
	// the hub numbers differently, or one whose id the hub gave to another.
	Task        int    `json:"task"`
	TitleSHA256 string `json:"title_sha256"`
	Name        string `json:"name"`
	// Size and SHA256 are of the bytes as the run sent them, which the hub
	// checked as they arrived.
	Size       int64     `json:"size"`
	SHA256     string    `json:"sha256"`
	CreatedAt  time.Time `json:"created_at"`
	ReceivedAt time.Time `json:"received_at"`
	// Created says the run created the task, or retitled it: only the run's
	// result can say which of the hub's tasks it is.
	Created bool `json:"created,omitempty"`
}

// RunKey is the directory a run's held files are kept in.
func RunKey(runID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(runID)))
	return hex.EncodeToString(sum[:16])
}

func heldRunRel(runID string) string { return HeldDirName + "/" + RunKey(runID) }

// validDigest reports whether s is a lower-case hex SHA-256.
func validDigest(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// check is what Hold requires of a description before it reads anything.
func (f HeldFile) check() error {
	switch {
	case !statedb.ValidAttachmentID(f.ID):
		return fmt.Errorf("attachments: hold: id %q is not 32 lower-case hex characters", clipID(f.ID))
	case f.Task <= 0:
		return fmt.Errorf("attachments: hold %s: invalid task id %d", f.ID, f.Task)
	case !validDigest(f.TitleSHA256):
		return fmt.Errorf("attachments: hold %s: title_sha256 is not a lower-case hex SHA-256", f.ID)
	case f.Size < 0 || f.Size > MaxFileBytes:
		return fmt.Errorf("%w: %s claims %d bytes, outside 0..%d", ErrTooLarge, f.ID, f.Size, MaxFileBytes)
	case !validDigest(f.SHA256):
		return fmt.Errorf("attachments: hold %s: sha256 is not a lower-case hex SHA-256", f.ID)
	case strings.TrimSpace(f.Name) == "":
		return fmt.Errorf("attachments: hold %s: a name is required", f.ID)
	}
	return nil
}

// openHeldRun opens the directory a run's held files are in, creating it when
// create is set. A held directory or run directory that is not a directory —
// a link put there — is refused.
func openHeldRun(dbPath, runID string, create bool) (*os.Root, *os.Root, error) {
	if strings.TrimSpace(runID) == "" {
		return nil, nil, errors.New("attachments: held files belong to a run, and none was named")
	}
	root, err := statedb.OpenAttachmentStore(dbPath, create)
	if err != nil {
		return nil, nil, err
	}
	rel := heldRunRel(runID)
	if create {
		if err := root.MkdirAll(rel, 0o755); err != nil {
			root.Close()
			return nil, nil, fmt.Errorf("attachments: create the hold of run %s: %w", RunKey(runID), err)
		}
	}
	for _, dir := range []string{HeldDirName, rel} {
		info, err := root.Lstat(dir)
		if err != nil {
			root.Close()
			return nil, nil, err
		}
		if !info.IsDir() {
			root.Close()
			return nil, nil, fmt.Errorf("%w: %s in the store is not a directory", ErrNotRegular, dir)
		}
	}
	before, _ := root.Lstat(rel)
	run, err := root.OpenRoot(rel)
	if err != nil {
		root.Close()
		return nil, nil, err
	}
	if now, err := run.Stat("."); err != nil || !os.SameFile(before, now) {
		run.Close()
		root.Close()
		return nil, nil, fmt.Errorf("%w: the hold of run %s changed while it was opened", ErrNotRegular, RunKey(runID))
	}
	return root, run, nil
}

// HeldNow returns the description of a file the hub already holds for the
// run under id, and whether it holds one: a run that sends a file again —
// because the answer to the first send never reached it — is told it arrived
// without sending it a second time.
func HeldNow(dbPath, runID, id string) (HeldFile, bool) {
	if !statedb.ValidAttachmentID(id) {
		return HeldFile{}, false
	}
	root, run, err := openHeldRun(dbPath, runID, false)
	if err != nil {
		return HeldFile{}, false
	}
	defer root.Close()
	defer run.Close()
	f, err := readHeldMeta(run, id)
	if err != nil {
		return HeldFile{}, false
	}
	if info, err := run.Lstat(id); err != nil || !info.Mode().IsRegular() || info.Size() != f.Size {
		return HeldFile{}, false
	}
	return f, true
}

// Hold receives one file a run sends and keeps it for the run.
//
// src is read to at most f.Size bytes and one more, and must be exactly f.Size
// bytes whose SHA-256 is f.SHA256: anything else is refused, and nothing of it
// is kept. The file is written under a temporary name and renamed into place
// once it checks out, and its description after it, so a process that dies
// part-way leaves nothing a reader would take for a held file. A file the run
// already holds under the id is replaced only by one that checked out.
func Hold(dbPath, runID string, f HeldFile, src io.Reader) (HeldFile, error) {
	f.Name = CleanName(f.Name)
	if err := f.check(); err != nil {
		return f, err
	}
	root, run, err := openHeldRun(dbPath, runID, true)
	if err != nil {
		return f, err
	}
	defer root.Close()
	defer run.Close()

	part := "." + f.ID + ".part"
	_ = run.Remove(part)
	out, err := run.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return f, fmt.Errorf("attachments: hold %q: %w", f.Name, err)
	}
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, sum), io.LimitReader(src, f.Size+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	fail := func(err error) (HeldFile, error) {
		_ = run.Remove(part)
		return f, err
	}
	switch {
	case err != nil:
		return fail(fmt.Errorf("attachments: hold %q: %w", f.Name, err))
	case n != f.Size:
		return fail(fmt.Errorf("%w: %q: %d bytes arrived, not the %d the run said it sent", ErrUnavailable, f.Name, n, f.Size))
	case hex.EncodeToString(sum.Sum(nil)) != f.SHA256:
		return fail(fmt.Errorf("%w: %q: the bytes that arrived do not match the SHA-256 the run sent", ErrUnavailable, f.Name))
	}
	if err := run.Rename(part, f.ID); err != nil {
		return fail(fmt.Errorf("attachments: hold %q: %w", f.Name, err))
	}
	f.ReceivedAt = time.Now().UTC()
	meta, err := json.Marshal(f)
	if err == nil {
		err = writeHeldMeta(run, f.ID, meta)
	}
	if err != nil {
		_ = run.Remove(f.ID)
		return f, fmt.Errorf("attachments: hold %q: %w", f.Name, err)
	}
	return f, nil
}

// writeHeldMeta writes a held file's description beside it, under a
// temporary name renamed into place.
func writeHeldMeta(run *os.Root, id string, meta []byte) error {
	tmp := "." + id + ".json.part"
	_ = run.Remove(tmp)
	out, err := run.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = out.Write(meta)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = run.Rename(tmp, id+".json")
	}
	if err != nil {
		_ = run.Remove(tmp)
	}
	return err
}

// readHeldMeta reads the description of the file held under id, refusing one
// that is not a regular file, is over its bound, or describes another file.
func readHeldMeta(run *os.Root, id string) (HeldFile, error) {
	name := id + ".json"
	before, err := run.Lstat(name)
	if err != nil {
		return HeldFile{}, err
	}
	if !before.Mode().IsRegular() {
		return HeldFile{}, fmt.Errorf("%w: %s", ErrNotRegular, name)
	}
	f, err := run.OpenFile(name, os.O_RDONLY|nonBlock, 0)
	if err != nil {
		return HeldFile{}, err
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !os.SameFile(before, info) {
		return HeldFile{}, fmt.Errorf("%w: %s changed while it was opened", ErrNotRegular, name)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxHeldMetaBytes+1))
	if err != nil {
		return HeldFile{}, err
	}
	if len(data) > maxHeldMetaBytes {
		return HeldFile{}, fmt.Errorf("attachments: %s is over %d bytes", name, maxHeldMetaBytes)
	}
	var h HeldFile
	if err := json.Unmarshal(data, &h); err != nil {
		return HeldFile{}, fmt.Errorf("attachments: %s: %w", name, err)
	}
	if h.ID != id {
		return HeldFile{}, fmt.Errorf("attachments: %s describes %q", name, clipID(h.ID))
	}
	if err := h.check(); err != nil {
		return HeldFile{}, err
	}
	return h, nil
}

// Held returns the files the hub holds for a run, oldest first. Anything in
// the run's directory that is not a held file and its description — a part
// of one still arriving, or something no hub wrote — is left out.
func Held(dbPath, runID string) ([]HeldFile, error) {
	root, run, err := openHeldRun(dbPath, runID, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	defer run.Close()
	d, err := run.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return nil, err
	}
	var out []HeldFile
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !statedb.ValidAttachmentID(id) {
			continue
		}
		f, err := readHeldMeta(run, id)
		if err != nil {
			continue
		}
		if info, err := run.Lstat(id); err != nil || !info.Mode().IsRegular() || info.Size() != f.Size {
			continue
		}
		out = append(out, f)
		if len(out) >= MaxHeldPerRun {
			break
		}
	}
	sortHeld(out)
	return out, nil
}

// sortHeld orders held files by when the run attached them, then by id.
func sortHeld(files []HeldFile) {
	sort.SliceStable(files, func(i, j int) bool {
		if !files[i].CreatedAt.Equal(files[j].CreatedAt) {
			return files[i].CreatedAt.Before(files[j].CreatedAt)
		}
		return files[i].ID < files[j].ID
	})
}

// HeldCount returns how many files the hub holds for a run, counting one
// still arriving: what bounds how many more it may send.
func HeldCount(dbPath, runID string) int {
	root, run, err := openHeldRun(dbPath, runID, false)
	if err != nil {
		return 0
	}
	defer root.Close()
	defer run.Close()
	d, err := run.Open(".")
	if err != nil {
		return 0
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".json") {
			continue
		}
		if id := strings.TrimSuffix(strings.TrimPrefix(name, "."), ".part"); statedb.ValidAttachmentID(id) {
			n++
		}
	}
	return n
}

// HeldBytes returns what the hub holds for every run of the project, in
// bytes: room the project's attachments are short of while it is held.
func HeldBytes(dbPath string) int64 {
	root, err := statedb.OpenAttachmentStore(dbPath, false)
	if err != nil {
		return 0
	}
	defer root.Close()
	if info, err := root.Lstat(HeldDirName); err != nil || !info.IsDir() {
		return 0
	}
	held, err := root.OpenRoot(HeldDirName)
	if err != nil {
		return 0
	}
	defer held.Close()
	var total int64
	_ = fs.WalkDir(held.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if strings.Count(p, "/") >= 1 {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".json") || !d.Type().IsRegular() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

// OpenHeld opens a file the hub holds for a run, refusing what is not the
// regular file of the size its description gives.
func OpenHeld(dbPath, runID string, f HeldFile) (*os.File, error) {
	if !statedb.ValidAttachmentID(f.ID) {
		return nil, fmt.Errorf("%w: invalid id", ErrUnavailable)
	}
	root, run, err := openHeldRun(dbPath, runID, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: the hub holds nothing for the run", ErrUnavailable)
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	defer run.Close()
	before, err := run.Lstat(f.ID)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: the hub does not hold it", ErrUnavailable)
	}
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrNotRegular, f.ID)
	}
	file, err := run.OpenFile(f.ID, os.O_RDONLY|nonBlock, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err == nil && (!info.Mode().IsRegular() || !os.SameFile(before, info)) {
		err = fmt.Errorf("%w: %s changed while it was opened", ErrNotRegular, f.ID)
	}
	if err == nil && info.Size() != f.Size {
		err = fmt.Errorf("%w: it is %d bytes, not the %d the run sent", ErrUnavailable, info.Size(), f.Size)
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

// AttachHeld stores a file the hub holds for a run as an attachment of the
// hub's task taskID, under the run's id for it, scrubbing it with scrub on the
// way in. meta.ID is set to the file's.
//
// The held copy stays: the caller lets go of it (RemoveHeld) once it is sure
// of the attachment — a check of the task's limits after the attach can still
// take the attachment back, and the file must not be lost with it.
//
// The caller has checked the task's room (Room) and that the task is the one
// the run attached the file to. An attach that finds the id already recorded
// fails with ErrExists, for the caller to tell a file that arrived twice from
// an id somebody else holds.
func AttachHeld(db *statedb.DB, dbPath, runID string, f HeldFile, taskID int, meta Meta, scrub *redact.Set) (statedb.AttachmentRow, error) {
	file, err := OpenHeld(dbPath, runID, f)
	if err != nil {
		return statedb.AttachmentRow{}, err
	}
	defer file.Close()
	meta.ID = f.ID
	return Put(db, dbPath, taskID, meta, io.NewSectionReader(file, 0, f.Size), MaxFileBytes, scrub)
}

// RemoveHeld lets go of one file the hub holds for a run.
func RemoveHeld(dbPath, runID, id string) {
	if !statedb.ValidAttachmentID(id) {
		return
	}
	root, run, err := openHeldRun(dbPath, runID, false)
	if err != nil {
		return
	}
	defer root.Close()
	defer run.Close()
	_ = run.Remove(id)
	_ = run.Remove(id + ".json")
}

// RemoveHeldRun lets go of everything the hub holds for a run: what its merge
// did not take, once the merge is done.
func RemoveHeldRun(dbPath, runID string) {
	if strings.TrimSpace(runID) == "" {
		return
	}
	root, err := statedb.OpenAttachmentStore(dbPath, false)
	if err != nil {
		return
	}
	defer root.Close()
	if info, err := root.Lstat(HeldDirName); err != nil || !info.IsDir() {
		return
	}
	// RemoveAll through the root unlinks a link rather than following it.
	_ = root.RemoveAll(heldRunRel(runID))
}

// SweepHeld removes what the hub holds for runs that are over and whose result
// was never merged — the hub lost track of them — whose files would otherwise
// stay for good. live names the runs still going, by RunKey: theirs are left
// whatever their age. Of the rest, only what nothing was sent to for longer
// than maxAge goes, so a run that has just ended keeps its files until its
// merge has taken them. It returns how many runs' files it removed.
func SweepHeld(dbPath string, live map[string]bool, maxAge time.Duration) int {
	root, err := statedb.OpenAttachmentStore(dbPath, false)
	if err != nil {
		return 0
	}
	defer root.Close()
	if info, err := root.Lstat(HeldDirName); err != nil || !info.IsDir() {
		return 0
	}
	d, err := root.Open(HeldDirName)
	if err != nil {
		return 0
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return 0
	}
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for _, e := range entries {
		rel := HeldDirName + "/" + e.Name()
		if !e.IsDir() {
			// Nothing but run directories belongs here.
			if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff) {
				_ = root.Remove(rel)
			}
			continue
		}
		if live[e.Name()] || newestUnder(root, rel).After(cutoff) {
			continue
		}
		if root.RemoveAll(rel) == nil {
			removed++
		}
	}
	return removed
}

// newestUnder is the latest modification time of dir and what is directly in
// it, read without following anything.
func newestUnder(root *os.Root, dir string) time.Time {
	var newest time.Time
	if info, err := root.Lstat(dir); err == nil {
		newest = info.ModTime()
	}
	d, err := root.Open(dir)
	if err != nil {
		return newest
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return newest
	}
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return newest
}
