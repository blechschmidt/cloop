package runbuild

// proc.go: telling one process from another through procfs.
//
// A pid alone is not a name: it is a small recycled integer, and a record
// that says "pid 4242 runs build X" is false the moment 4242 exits and the
// number is handed to something else. So every record here names a process by
// the pair the local executor driver already trusts (pkg/executor/localprocess,
// Task 20191): its start time in clock ticks since boot (/proc/<pid>/stat field
// 22), which the kernel assigns at fork and never changes — not even across
// execve, which is what lets a run replace its image and stay the same run —
// and the boot id, which closes the one hole ticks leave after a reboot.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Ident names one process for as long as it lives.
type Ident struct {
	PID        int    `json:"pid"`
	StartTicks uint64 `json:"start_ticks"`
	BootID     string `json:"boot_id"`
}

// Same reports whether a and b name the same process. An identity missing its
// start time or boot names nothing, and matches nothing.
func (a Ident) Same(b Ident) bool {
	return a.PID > 0 && a.PID == b.PID && a.StartTicks != 0 && a.StartTicks == b.StartTicks &&
		a.BootID != "" && a.BootID == b.BootID
}

const procBootIDPath = "/proc/sys/kernel/random/boot_id"

// bootID is the running kernel's boot id, read once: it cannot change while
// this process lives.
var bootID = sync.OnceValues(func() (string, error) {
	raw, err := os.ReadFile(procBootIDPath)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(raw))
	if id == "" {
		return "", fmt.Errorf("%s is empty", procBootIDPath)
	}
	return id, nil
})

// procStat is what this package reads from /proc/<pid>/stat.
type procStat struct {
	state      string
	ppid       int
	startTicks uint64
}

// parseStat pulls state (field 3), ppid (4) and starttime (22) out of one
// /proc/<pid>/stat line. The second field is the command name in parentheses,
// unescaped, so the fields are counted from the last ')' — the documented way
// to read the file, and the one localprocess uses.
func parseStat(line string) (procStat, error) {
	end := strings.LastIndexByte(line, ')')
	if end < 0 || end+1 >= len(line) {
		return procStat{}, errors.New("no command field")
	}
	f := strings.Fields(line[end+1:])
	const startIdx = 19 // field 22, counted from field 3 at index 0
	if len(f) <= startIdx {
		return procStat{}, fmt.Errorf("%d fields after the command, want more than %d", len(f), startIdx)
	}
	ppid, err := strconv.Atoi(f[1])
	if err != nil {
		return procStat{}, fmt.Errorf("ppid %q: %w", f[1], err)
	}
	ticks, err := strconv.ParseUint(f[startIdx], 10, 64)
	if err != nil {
		return procStat{}, fmt.Errorf("starttime %q: %w", f[startIdx], err)
	}
	return procStat{state: f[0], ppid: ppid, startTicks: ticks}, nil
}

func readStat(pid int) (procStat, error) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return procStat{}, err
	}
	return parseStat(string(raw))
}

// IdentOf reads pid's identity. alive is false for a process that has exited
// but not been reaped (state Z): it holds its pid and its start time, and runs
// nothing.
func IdentOf(pid int) (id Ident, alive bool, err error) {
	if pid <= 0 {
		return Ident{}, false, fmt.Errorf("%d is not a pid", pid)
	}
	boot, err := bootID()
	if err != nil {
		return Ident{}, false, err
	}
	st, err := readStat(pid)
	if err != nil {
		return Ident{}, false, err
	}
	return Ident{PID: pid, StartTicks: st.startTicks, BootID: boot}, st.state != "Z" && st.state != "X", nil
}

// SelfIdent is this process's identity.
func SelfIdent() (Ident, error) {
	id, _, err := IdentOf(os.Getpid())
	return id, err
}

// Running reports whether the process id names is still executing. known is
// false when procfs could not answer — no /proc, or a pid namespace that hides
// it — and then running means nothing.
func Running(id Ident) (running, known bool) {
	cur, alive, err := IdentOf(id.PID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if _, bootErr := bootID(); bootErr == nil {
				return false, true // procfs works; the pid is gone
			}
		}
		return false, false
	}
	return alive && cur.Same(id), true
}

// Child is a process whose parent is this one.
type Child struct {
	PID  int
	Comm string
}

func (c Child) String() string {
	if c.Comm == "" {
		return "pid " + strconv.Itoa(c.PID)
	}
	return fmt.Sprintf("pid %d (%s)", c.PID, c.Comm)
}

// LiveChildren lists the processes this one started that are still running.
//
// It exists because an execve does not take children with it: they stay this
// pid's children, but the new image knows nothing of them — no goroutine waits
// for them, no pipe reads their output, and when they exit nobody reaps them.
// A run only replaces its image when this is empty. Exited-but-unreaped
// children are not counted: they run nothing.
func LiveChildren() ([]Child, error) {
	self := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []Child
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		st, err := readStat(pid)
		if err != nil || st.ppid != self || st.state == "Z" || st.state == "X" {
			continue
		}
		comm, _ := os.ReadFile("/proc/" + e.Name() + "/comm")
		out = append(out, Child{PID: pid, Comm: strings.TrimSpace(string(comm))})
	}
	return out, nil
}

// ── The path a run was started from ─────────────────────────────────────────

// startPath is where this process's binary was found when it started,
// resolved before anything could change the working directory (`--workspace`
// does, in the root command's pre-run).
var startPath, startPathErr = resolveStartPath(os.Args, os.Getwd, os.Stat, exec.LookPath)

// StartPath is the path this process's binary was started from: the one a
// deploy replaces, and the one adoption validates. Not /proc/self/exe: that is
// the file the process *is*, which after a deploy is the deleted old binary —
// and for a run started through a symlink a deploy re-points, the old target.
func StartPath() (string, error) { return startPath, startPathErr }

// resolveStartPath finds argv[0] the way the kernel did — relative to the
// working directory when it has a slash, through PATH when it does not — and
// accepts it only if it is still the file this process runs; otherwise it
// falls back to the executable's own path.
func resolveStartPath(args []string, getwd func() (string, error), stat func(string) (os.FileInfo, error),
	lookPath func(string) (string, error)) (string, error) {
	self, selfErr := os.Executable()
	if len(args) > 0 && args[0] != "" {
		cand := args[0]
		if strings.Contains(cand, "/") {
			if !filepath.IsAbs(cand) {
				if wd, err := getwd(); err == nil {
					cand = filepath.Join(wd, cand)
				}
			}
		} else if p, err := lookPath(cand); err == nil {
			cand = p
		}
		if filepath.IsAbs(cand) {
			if a, err := stat(cand); err == nil {
				if b, err := stat("/proc/self/exe"); err == nil && os.SameFile(a, b) {
					return filepath.Clean(cand), nil
				}
			}
		}
	}
	if selfErr != nil {
		return "", selfErr
	}
	return self, nil
}

// RestoreComm puts the process's name back after an adoption.
//
// The new image was executed through /proc/self/fd/<n> (see Exec), so the
// kernel named the process "<n>" — which is what ps, top and pgrep would show
// for the rest of the run. Writing /proc/self/comm renames the main thread,
// which is what all of them read. Best effort: a run named "7" works, it is
// only harder to find.
func RestoreComm(path string) {
	name := filepath.Base(path)
	if name == "" || name == "." || name == "/" {
		return
	}
	if len(name) > 15 { // TASK_COMM_LEN - 1; the kernel truncates, but say so
		name = name[:15]
	}
	_ = os.WriteFile("/proc/self/comm", []byte(name), 0)
}
