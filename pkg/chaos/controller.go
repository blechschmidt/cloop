package chaos

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
)

// activeFileName is the JSON mirror of currently-injected faults. Lives under
// .cloop/chaos/ so it travels with the project state and is wiped by the
// existing `cloop reset` machinery.
const (
	chaosDirName    = "chaos"
	activeFileName  = "active.json"
	defaultRefresh  = 1 * time.Second
	defaultBallast  = "ballast"
	maxFaultBackoff = 30 * time.Second
)

// Controller is the in-process owner of currently-active faults. A single
// instance is shared across the orchestrator, provider HTTP clients, and any
// other subsystem that wants to participate in chaos.
//
// Concurrency: the active set is guarded by a sync.RWMutex, with reads
// dominating in the hot HTTP path. The refresher goroutine is the sole
// writer outside the public Inject/Clear methods.
//
// Lifecycle: NewController returns an idle controller with an empty active
// set; call Start(ctx) to begin file-watching. The controller is safe to
// instantiate even when no chaos is intended — every ShouldInject fast-path
// returns false in zero time when the active set is empty (atomic counter).
type Controller struct {
	workDir string

	mu      sync.RWMutex
	active  []Fault
	loadErr error // last refresh error, surfaced via LastError()

	// activeCount mirrors len(active) without the mutex so the hot path can
	// short-circuit without locking when no faults are configured. This is
	// the reason the chaos transport adds essentially zero overhead in
	// production where chaos is never injected.
	activeCount atomic.Int32

	// rng is owned by the controller so all probability rolls are
	// reproducible per-instance under tests (callers can swap WithRand).
	rng *rand.Rand

	started atomic.Bool
	stop    chan struct{}
	doneWg  sync.WaitGroup
}

// NewController creates a controller scoped to the given .cloop project root.
// workDir must be a directory that contains, or is allowed to contain, a
// .cloop subdirectory; for non-project use cases (tests, suites) any writable
// directory works.
func NewController(workDir string) *Controller {
	// math/rand/v2's NewPCG is deterministic given fixed seeds — fine for
	// chaos because we explicitly want users to be able to script repeatable
	// fault campaigns. Production callers seed off the wall clock.
	src := rand.NewPCG(uint64(time.Now().UnixNano()), 0xC10B5)
	return &Controller{
		workDir: workDir,
		rng:     rand.New(src),
		stop:    make(chan struct{}),
	}
}

// Start launches the file-watcher goroutine that refreshes the active set
// every defaultRefresh. Idempotent: subsequent calls are no-ops.
func (c *Controller) Start(ctx context.Context) {
	if !c.started.CompareAndSwap(false, true) {
		return
	}
	// Prime the in-memory set immediately so the first ShouldInject call after
	// Start sees a consistent view, not the empty default.
	_ = c.Refresh()

	c.doneWg.Add(1)
	go c.watch(ctx)
}

// Stop terminates the watcher goroutine. Safe to call multiple times.
func (c *Controller) Stop() {
	if !c.started.Load() {
		return
	}
	select {
	case <-c.stop:
		// already closed
	default:
		close(c.stop)
	}
	c.doneWg.Wait()
}

// watch refreshes the active set on a fixed cadence. We deliberately do not
// use fsnotify here — polling once a second is cheap (the file is tiny) and
// avoids platform-specific watcher edge cases (NFS, file replaced via rename
// on Linux, missing inotify on some containers).
func (c *Controller) watch(ctx context.Context) {
	defer c.doneWg.Done()
	t := time.NewTicker(defaultRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stop:
			return
		case <-t.C:
			_ = c.Refresh()
		}
	}
}

// activePath returns the absolute path of the on-disk fault mirror file.
func (c *Controller) activePath() string {
	return filepath.Join(c.workDir, ".cloop", chaosDirName, activeFileName)
}

// Refresh reloads the active set from disk. Returns the last load error so
// callers can surface mirror-corruption to the user.
func (c *Controller) Refresh() error {
	path := c.activePath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			c.setActive(nil)
			c.mu.Lock()
			c.loadErr = nil
			c.mu.Unlock()
			return nil
		}
		c.mu.Lock()
		c.loadErr = fmt.Errorf("chaos: read %s: %w", path, err)
		c.mu.Unlock()
		return c.loadErr
	}
	if len(data) == 0 {
		c.setActive(nil)
		return nil
	}
	var loaded []Fault
	if err := json.Unmarshal(data, &loaded); err != nil {
		c.mu.Lock()
		c.loadErr = fmt.Errorf("chaos: parse %s: %w", path, err)
		c.mu.Unlock()
		return c.loadErr
	}
	now := time.Now()
	pruned := loaded[:0]
	for _, f := range loaded {
		if f.Active(now) {
			pruned = append(pruned, f)
		}
	}
	c.setActive(pruned)
	c.mu.Lock()
	c.loadErr = nil
	c.mu.Unlock()
	return nil
}

func (c *Controller) setActive(faults []Fault) {
	c.mu.Lock()
	c.active = faults
	c.mu.Unlock()
	c.activeCount.Store(int32(len(faults)))
}

// LastError returns the last error encountered while refreshing the active
// set, or nil if the most recent refresh succeeded.
func (c *Controller) LastError() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loadErr
}

// Active returns a snapshot copy of the currently-active faults. Safe to
// retain — the slice does not alias the controller's internal storage.
func (c *Controller) Active() []Fault {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.active) == 0 {
		return nil
	}
	out := make([]Fault, len(c.active))
	copy(out, c.active)
	return out
}

// ShouldInject reports whether a fault of the given type is currently active
// and the probability roll succeeded. The hot path on the no-fault case is
// a single atomic load and a comparison — designed so chaos middleware adds
// no measurable overhead in production.
func (c *Controller) ShouldInject(t FaultType) bool {
	if c.activeCount.Load() == 0 {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := time.Now()
	for _, f := range c.active {
		if f.Type != t || !f.Active(now) {
			continue
		}
		p := f.Probability
		if p <= 0 {
			p = 1.0
		}
		if p >= 1.0 || c.rng.Float64() < p {
			return true
		}
	}
	return false
}

// FaultsOfType returns active faults matching t. Useful for callers that need
// the configured Probability or Note (e.g. SlowDisk reads its delay from the
// note field).
func (c *Controller) FaultsOfType(t FaultType) []Fault {
	if c.activeCount.Load() == 0 {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := time.Now()
	var out []Fault
	for _, f := range c.active {
		if f.Type == t && f.Active(now) {
			out = append(out, f)
		}
	}
	return out
}

// Inject persists the fault to the on-disk mirror so all listening processes
// pick it up on their next refresh. The fault's StartedAt is set to now if
// zero. ID is left unset — callers that want the fault recorded in chaos_runs
// must additionally call (*Store).Insert and update the persisted entry.
func (c *Controller) Inject(f Fault) error {
	if f.Type == "" {
		return fmt.Errorf("chaos: inject: empty fault type")
	}
	if _, err := ParseFaultType(string(f.Type)); err != nil {
		return err
	}
	if f.StartedAt.IsZero() {
		f.StartedAt = time.Now()
	}
	if f.Until.IsZero() {
		f.Until = f.StartedAt.Add(30 * time.Second)
	}
	if !f.Until.After(f.StartedAt) {
		return fmt.Errorf("chaos: inject: until %v not after started_at %v", f.Until, f.StartedAt)
	}
	if f.Probability < 0 || f.Probability > 1 {
		return fmt.Errorf("chaos: inject: probability %v out of [0,1]", f.Probability)
	}

	if err := c.ensureDir(); err != nil {
		return err
	}

	current := c.loadFromDisk()
	current = append(current, f)
	return c.persist(current)
}

// Clear removes every persisted fault. Intended for cleanup at the end of a
// chaos run or when the operator wants to abort an in-flight injection.
func (c *Controller) Clear() error {
	path := c.activePath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("chaos: clear %s: %w", path, err)
	}
	c.setActive(nil)
	return nil
}

// loadFromDisk reads the persisted set, returning an empty slice if the file
// is missing or unreadable. Used by Inject so the mirror file is the source
// of truth even when multiple writers race.
func (c *Controller) loadFromDisk() []Fault {
	data, err := os.ReadFile(c.activePath())
	if err != nil {
		return nil
	}
	var loaded []Fault
	if err := json.Unmarshal(data, &loaded); err != nil {
		return nil
	}
	now := time.Now()
	out := loaded[:0]
	for _, f := range loaded {
		if f.Active(now) {
			out = append(out, f)
		}
	}
	return out
}

// persist atomically writes the fault set to the mirror file and refreshes
// the in-memory cache so the writing process sees the change immediately.
func (c *Controller) persist(faults []Fault) error {
	if err := c.ensureDir(); err != nil {
		return err
	}
	buf, err := json.MarshalIndent(faults, "", "  ")
	if err != nil {
		return fmt.Errorf("chaos: marshal active.json: %w", err)
	}
	if err := atomicfile.Write(c.activePath(), buf, 0o644); err != nil {
		return err
	}
	c.setActive(faults)
	return nil
}

// ensureDir makes sure the .cloop/chaos/ directory exists. Mode 0o755 matches
// the rest of the .cloop tree.
func (c *Controller) ensureDir() error {
	dir := filepath.Join(c.workDir, ".cloop", chaosDirName)
	return os.MkdirAll(dir, 0o755)
}

// global is the package-level singleton consulted by the HTTP transport when
// the user has not registered a per-call controller. Tests using a custom
// controller should call SetGlobal/ResetGlobal to scope their changes.
var (
	globalMu sync.RWMutex
	global   *Controller
)

// SetGlobal installs c as the package-wide controller. Returns the previous
// controller so tests can restore it.
func SetGlobal(c *Controller) *Controller {
	globalMu.Lock()
	defer globalMu.Unlock()
	prev := global
	global = c
	return prev
}

// Global returns the currently-installed controller, or nil when none has
// been configured. The HTTP transport treats a nil controller as "chaos
// disabled" — the safe production default.
func Global() *Controller {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return global
}
