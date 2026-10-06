package runbuild

// candidate.go: the binary a run might adopt, and whether it may.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// ProbeTimeout bounds `<binary> version --json`. A build that cannot say what
// it is within it is refused rather than waited for: the run is holding a task
// boundary open while it asks.
const ProbeTimeout = 10 * time.Second

// probeOutputLimit bounds what the probe reads. The report is a few hundred
// bytes; anything near this is not a cloop version report.
const probeOutputLimit = 64 << 10

// Candidate is the binary at a run's start path, held open.
//
// Holding it is the point. A deploy writes the new binary in place (install
// unlinks the path and copies), so between a check of the path and an execve
// of the path the file there can be another one — or a half-written one. The
// probe and the exec both go through this descriptor, so the file that
// answered `version --json` is, byte for byte, the file that is executed,
// whatever happens to the path meanwhile.
type Candidate struct {
	Path string
	file *os.File
	info os.FileInfo
}

// FileID identifies the file a path held at one moment, so a refusal is
// remembered for that file and not repeated at every boundary — while a later
// deploy (a new inode, or new contents) is looked at afresh.
type FileID struct {
	Dev, Ino uint64
	Size     int64
	MTime    int64
}

// FileIDOf reads info's identity.
func FileIDOf(info os.FileInfo) FileID {
	id := FileID{Size: info.Size(), MTime: info.ModTime().UnixNano()}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		id.Dev, id.Ino = uint64(st.Dev), uint64(st.Ino)
	}
	return id
}

// ErrSameBinary means the path still holds the binary this process runs:
// there is nothing to adopt.
var ErrSameBinary = errors.New("the path still holds the binary this run is executing")

// Open opens the binary at path for adoption. It refuses, before running
// anything, a path that does not hold a regular executable ELF file, one that
// someone other than root or this process's user could have written, and the
// binary this process already runs (ErrSameBinary).
func Open(path string) (*Candidate, error) {
	// Non-blocking, so a FIFO planted at the path cannot hang the run's
	// boundary in open(2); the type check below then refuses it.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	c := &Candidate{Path: path, file: f}
	if err := c.check(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return c, nil
}

func (c *Candidate) check() error {
	info, err := c.file.Stat()
	if err != nil {
		return err
	}
	c.info = info
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", c.Path)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s is not executable", c.Path)
	}
	if self, err := os.Stat("/proc/self/exe"); err == nil && os.SameFile(self, info) {
		return ErrSameBinary
	}
	// A root run that adopts whatever an unprivileged user could put at its
	// start path would hand that user root at the next task boundary. A
	// restart from the same path has the same exposure, but a restart is a
	// person's decision; this is automatic, so it insists on what an
	// installed binary looks like.
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by its group or by everyone (mode %#o)", c.Path, info.Mode().Perm())
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if euid := os.Geteuid(); st.Uid != 0 && int(st.Uid) != euid {
			return fmt.Errorf("%s belongs to uid %d, neither root nor this run's user (uid %d)", c.Path, st.Uid, euid)
		}
	}
	magic := make([]byte, 4)
	if _, err := c.file.ReadAt(magic, 0); err != nil || !bytes.Equal(magic, []byte{0x7f, 'E', 'L', 'F'}) {
		return fmt.Errorf("%s is not an ELF executable", c.Path)
	}
	return nil
}

// ID is the identity of the file held.
func (c *Candidate) ID() FileID { return FileIDOf(c.info) }

// InstalledAt is when the file held last changed as an inode — its ctime,
// which, unlike its mtime, no copy tool can set back: the moment a deploy put
// it in place.
func (c *Candidate) InstalledAt() time.Time { return ctimeOf(c.info) }

// Fd is the descriptor Exec runs.
func (c *Candidate) Fd() uintptr { return c.file.Fd() }

// Close releases the file.
func (c *Candidate) Close() error {
	if c == nil || c.file == nil {
		return nil
	}
	return c.file.Close()
}

// Probe runs `<the held file> version --json` and reads what it says it is.
//
// The child runs the held descriptor, passed as its fd 3, through
// /proc/self/fd/3 — never the path. It runs in "/" in its own process group,
// with this process's environment less the handoff variable, and is killed
// with its group if it has not answered within timeout. `version` has no
// side effects by design (cmd/version.go overrides the root pre-run), which is
// what makes running an unvalidated binary to ask it acceptable at all.
func (c *Candidate) Probe(ctx context.Context, timeout time.Duration) (Build, error) {
	out, _, err := c.run(ctx, timeout, "version", "--json")
	if err != nil {
		return Build{}, fmt.Errorf("`version --json` %w", err)
	}
	return ParseReport(out)
}

// CheckArgs asks the held file whether it accepts args — the run's own command
// line — by parsing them with --help appended: cobra parses every flag and
// prints usage before any pre-run hook, so a flag the new build dropped or
// renamed is an error here instead of a run that dies the moment it is
// re-executed.
func (c *Candidate) CheckArgs(ctx context.Context, timeout time.Duration, args []string) error {
	_, stderr, err := c.run(ctx, timeout, append(append([]string(nil), args...), "--help")...)
	if err != nil {
		if line := firstLine(stderr); line != "" {
			return fmt.Errorf("does not accept this run's command line (%s): %s", line, err)
		}
		return fmt.Errorf("does not accept this run's command line: %w", err)
	}
	return nil
}

// run executes the held file — as its fd 3, through /proc/self/fd/3, never by
// path — in "/" in its own process group, with an environment of nothing but
// PATH and HOME: it is a binary nothing has vouched for yet, and the run's
// environment carries its credentials.
func (c *Candidate) run(ctx context.Context, timeout time.Duration, args ...string) (stdout, stderr []byte, err error) {
	if timeout <= 0 {
		timeout = ProbeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	cmd.ExtraFiles = []*os.File{c.file}
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "NO_COLOR=1"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	var out, errOut bytes.Buffer
	cmd.Stdout = &limitWriter{w: &out, n: probeOutputLimit}
	cmd.Stderr = &limitWriter{w: &errOut, n: probeOutputLimit}
	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, nil, fmt.Errorf("did not answer within %s", timeout)
	}
	if runErr != nil {
		return out.Bytes(), errOut.Bytes(), fmt.Errorf("failed: %w", runErr)
	}
	return out.Bytes(), errOut.Bytes(), nil
}

func firstLine(b []byte) string {
	line, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	if len(line) > 200 {
		line = line[:200]
	}
	return line
}

// ParseReport reads a `cloop version --json` report.
func ParseReport(raw []byte) (Build, error) {
	var rep struct {
		Version  string `json:"version"`
		Commit   string `json:"commit"`
		Sequence int    `json:"sequence"`
		Schema   int    `json:"schema"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(raw), &rep); err != nil {
		return Build{}, fmt.Errorf("`version --json` printed no version report: %w", err)
	}
	if strings.TrimSpace(rep.Version) == "" {
		return Build{}, errors.New("`version --json` reported no version")
	}
	if rep.Sequence < 0 || rep.Schema < 0 {
		return Build{}, errors.New("`version --json` reported a negative sequence or schema")
	}
	return Build{Version: rep.Version, Commit: rep.Commit, Sequence: rep.Sequence, Schema: rep.Schema}, nil
}

// Judge decides whether a run on self may adopt cand, given the schema the
// project's database is at. Nil means adopt; otherwise the error says why
// not, in words for the run's journal.
//
// The sequence must be strictly greater: an equal one is the same build (or a
// rebuild of it), an earlier one a rollback, and a missing one cannot be
// ordered at all — and a run that moved to any of those would be the one thing
// worse than a run that is behind. The schema must be at least the database's:
// a build that embeds less would be running against tables from its future.
func Judge(self, cand Build, dbSchema int) error {
	switch {
	case self.Sequence <= 0:
		return fmt.Errorf("this run's build %s carries no sequence, so no build can be shown to be newer", self.Short())
	case cand.Sequence <= 0:
		return fmt.Errorf("%s carries no sequence, so it cannot be shown to be newer than %s", cand.Short(), self.Label())
	case cand.Sequence == self.Sequence:
		return fmt.Errorf("%s is at the same sequence as this run's build (%d)", cand.Short(), self.Sequence)
	case cand.Sequence < self.Sequence:
		return fmt.Errorf("%s is %d builds older than this run's build (sequence %d against %d)",
			cand.Short(), self.Sequence-cand.Sequence, cand.Sequence, self.Sequence)
	case cand.Schema <= 0:
		return fmt.Errorf("%s does not report the schema it embeds", cand.Short())
	case dbSchema > 0 && cand.Schema < dbSchema:
		return fmt.Errorf("%s embeds schema %d, behind the project database at %d", cand.Short(), cand.Schema, dbSchema)
	}
	return nil
}

// limitWriter keeps at most n bytes and discards the rest.
type limitWriter struct {
	w io.Writer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	q := p
	if len(q) > l.n {
		q = q[:l.n]
	}
	l.n -= len(q)
	if _, err := l.w.Write(q); err != nil {
		return 0, err
	}
	return len(p), nil
}
