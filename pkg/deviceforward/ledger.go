package deviceforward

// ledger.go records what a consumer process attached to its host — vhci ports
// and TAP interfaces — so that a successor can undo it if the process dies
// holding them (Task 20430).
//
// Both kinds of attachment mostly clean up after themselves: a TAP is not
// persistent and vanishes with the last descriptor, and a vhci port is freed by
// the kernel when its socket's peer — this process's end of the socketpair —
// closes. The ledger is for what "mostly" leaves: a port the kernel parked in
// its error state, a TAP that something made persistent. An agent and a hub
// both sweep their ledger directory when they start.
//
// A sweep touches only what a ledger names, and only for a process that is
// gone. It is the guarantee that a consumer never detaches a port it did not
// attach: an operator's own `usbip attach`, or another consumer's device, is in
// no ledger this process wrote and is never looked at.
//
// One file per process, named for its pid and start time, so two processes
// sharing a directory — hub members on one host — never sweep each other's
// live attachments, and a recycled pid is not mistaken for the process that
// wrote the file.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LedgerKind is what an entry records.
type LedgerKind string

const (
	// LedgerVHCI is a vhci_hcd port this process attached a device to.
	LedgerVHCI LedgerKind = "vhci"
	// LedgerTAP is a TAP interface this process created.
	LedgerTAP LedgerKind = "tap"
)

// LedgerEntry is one attachment.
type LedgerEntry struct {
	ID       string     `json:"id"`
	Kind     LedgerKind `json:"kind"`
	VHCIRoot string     `json:"vhci_root,omitempty"`
	VHCIPort int        `json:"vhci_port,omitempty"`
	DevID    uint32     `json:"dev_id,omitempty"`
	TAP      string     `json:"tap,omitempty"`
	At       time.Time  `json:"at"`
}

// Ledger is this process's record of its live attachments.
type Ledger struct {
	path string
	logf func(string, ...any)

	mu      sync.Mutex
	seq     int
	entries map[string]LedgerEntry
}

// ledgerFile is the on-disk form.
type ledgerFile struct {
	PID       int           `json:"pid"`
	StartTime uint64        `json:"start_time"`
	Entries   []LedgerEntry `json:"entries"`
}

// OpenLedger opens this process's ledger in dir, creating dir 0700.
func OpenLedger(dir string, logf func(string, ...any)) (*Ledger, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("deviceforward: ledger directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("deviceforward: create ledger directory %s: %w", dir, err)
	}
	pid, start := os.Getpid(), processStartTime(os.Getpid())
	return &Ledger{
		path:    filepath.Join(dir, ledgerName(pid, start)),
		logf:    logf,
		entries: map[string]LedgerEntry{},
	}, nil
}

func ledgerName(pid int, start uint64) string {
	return fmt.Sprintf("%d-%d.json", pid, start)
}

func parseLedgerName(name string) (pid int, start uint64, ok bool) {
	base, found := strings.CutSuffix(name, ".json")
	if !found {
		return 0, 0, false
	}
	p, s, found := strings.Cut(base, "-")
	if !found {
		return 0, 0, false
	}
	pid, err1 := strconv.Atoi(p)
	start, err2 := strconv.ParseUint(s, 10, 64)
	if err1 != nil || err2 != nil || pid <= 0 {
		return 0, 0, false
	}
	return pid, start, true
}

// Add records an attachment and returns its ledger id.
func (l *Ledger) Add(e LedgerEntry) string {
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e.ID = strconv.Itoa(l.seq)
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	l.entries[e.ID] = e
	l.writeLocked()
	return e.ID
}

// Remove forgets an attachment that was undone.
func (l *Ledger) Remove(id string) {
	if l == nil || id == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, id)
	l.writeLocked()
}

// Entries returns the live entries, for diagnostics and tests.
func (l *Ledger) Entries() []LedgerEntry {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]LedgerEntry, 0, len(l.entries))
	for _, e := range l.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// writeLocked persists the ledger, or removes the file when it is empty. A
// write that fails is logged, not returned: the attachment it describes is
// already live, and refusing it would not undo it.
func (l *Ledger) writeLocked() {
	if len(l.entries) == 0 {
		if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) && l.logf != nil {
			l.logf("deviceforward: remove ledger %s: %v", l.path, err)
		}
		return
	}
	f := ledgerFile{PID: os.Getpid(), StartTime: processStartTime(os.Getpid())}
	for _, e := range l.entries {
		f.Entries = append(f.Entries, e)
	}
	sort.Slice(f.Entries, func(i, j int) bool { return f.Entries[i].ID < f.Entries[j].ID })
	b, err := json.Marshal(f)
	if err != nil {
		return
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		if l.logf != nil {
			l.logf("deviceforward: write ledger %s: %v", l.path, err)
		}
		return
	}
	if err := os.Rename(tmp, l.path); err != nil && l.logf != nil {
		l.logf("deviceforward: write ledger %s: %v", l.path, err)
	}
}

// SweepReport says what a sweep found and undid.
type SweepReport struct {
	// Detached are the vhci ports detached, as "port N".
	Detached []string
	// Removed are the TAP interfaces removed.
	Removed []string
	// Errors are the entries that could not be undone.
	Errors []string
}

// SweepLedgers undoes the attachments recorded in dir by processes that are no
// longer running, and removes their ledgers. A live process's ledger — this
// one's, or another member's on the same host — is left alone.
func SweepLedgers(dir string, logf func(string, ...any)) SweepReport {
	var rep SweepReport
	entries, err := os.ReadDir(dir)
	if err != nil {
		return rep
	}
	for _, de := range entries {
		pid, start, ok := parseLedgerName(de.Name())
		if !ok {
			continue
		}
		if processAlive(pid, start) {
			continue
		}
		path := filepath.Join(dir, de.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var f ledgerFile
		if err := json.Unmarshal(b, &f); err != nil {
			// Unreadable is not ours to guess at; drop it so it is not read
			// again forever.
			_ = os.Remove(path)
			continue
		}
		for _, e := range f.Entries {
			undoLedgerEntry(e, &rep, logf)
		}
		_ = os.Remove(path)
	}
	return rep
}
