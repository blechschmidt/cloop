package agent

// agent.go is the device-side main loop: dial out, handshake, serve frames,
// reconnect forever.
//
// The loop never gives up on its own. An edge device that stops retrying after
// N failures needs a human to walk over and restart it, which defeats the
// purpose of unattended deployment — so the only things that end the loop are
// the operator (ctx cancellation) and the control plane explicitly saying
// "do not come back" (a bye frame with Reconnect=false, sent on revocation).

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// Reconnect backoff bounds. These mirror pkg/provider/retry.go's semantics —
// exponential growth from an initial delay, capped, with ±25% jitter — but
// with a much higher ceiling: a provider call retries within one request's
// lifetime, whereas an agent may be waiting out a multi-hour outage and must
// not spin on a control plane that is down.
const (
	reconnectInitialDelay = time.Second
	reconnectMaxDelay     = 2 * time.Minute
)

// Config parameterises an agent.
type Config struct {
	// Server is the control-plane WebSocket URL,
	// e.g. wss://cloop.example.com/api/executors/connect.
	Server string
	// Token is an enrollment token, used only until a credential is issued.
	Token string
	// TokenFile is the file Token was read from, when it came from one.
	//
	// The agent deletes it once the token has been redeemed. An enrollment
	// token is single-use, so after redemption the file holds a dead secret
	// that still looks live: it would be carried into every backup and disk
	// image of the device, and an operator finding it later cannot tell
	// whether it is spent. Removing it makes the credential's lifetime match
	// its usefulness. Set by `cloop executor agent --token-file`, which is
	// how the installed service receives its token without it appearing in
	// ExecStart.
	TokenFile string
	// CredentialPath is where the long-lived credential is persisted.
	// Empty uses DefaultCredentialPath().
	CredentialPath string
	// WorkDirRoot confines every workload. Empty uses ~/.cloop/work.
	WorkDirRoot string
	// MaxConcurrent bounds simultaneous workloads. Zero means NumCPU.
	MaxConcurrent int
	// Labels are operator-supplied scheduler selectors.
	Labels map[string]string
	// RetainBytes overrides DefaultRetainBytes per workload.
	RetainBytes int
	// Pin is the control plane's expected SPKI fingerprint,
	// "sha256:<base64>". Several may be given comma-separated so a key
	// rotation can be staged. Empty means ordinary PKI verification only.
	// Taken from the stored credential when the flag is not passed.
	Pin string
	// RootCAFile adds a PEM bundle to the trusted roots, for a control plane
	// whose certificate the system store does not know — a private CA, or a
	// `cloop hub tls-init` development certificate. This is the supported way
	// to reach such a server; there is deliberately no way to disable
	// verification instead.
	RootCAFile string
	// InsecureTransport permits plaintext ws:// to a non-loopback host.
	// It exists for links already protected some other way (an established
	// mTLS tunnel, a lab with no network). Every connection attempt logs a
	// warning while it is on.
	InsecureTransport bool
	// Logf receives operational messages. Nil discards them.
	Logf func(format string, args ...any)
	// Now overrides the clock for tests.
	Now func() time.Time
	// Dial overrides connection establishment, so tests can drive the agent
	// over an in-memory pipe instead of a real socket.
	Dial func(ctx context.Context, server, token string) (remote.Conn, error)
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// Agent is the device-side executor client.
type Agent struct {
	cfg   Config
	local *localprocess.Executor
	root  string

	// Transport settings resolved once in New and read-only thereafter, so
	// the reconnect loop never re-derives them and cannot drift mid-life.
	httpClient      *http.Client
	pinned          bool
	pinDescription  string
	insecureWarning string

	// vault indexes the brokered credentials this device is holding, by
	// lease, so a revoke frame can take one back without walking every
	// workload's environment. It has its own lock: a scrub holds it across
	// file unlinks, and blocking every other agent operation behind that
	// would stall heartbeats.
	vault *vault

	mu        sync.Mutex
	cred      Credential
	workloads map[string]*workload
	sess      *deviceSession
	hbSeq     uint64
	// connected records that the last attempt got as far as a welcome, so
	// the reconnect ladder resets rather than creeping to its ceiling on a
	// device that reconnects successfully every few hours.
	connected bool
}

// workload is one running task on this device.
type workload struct {
	handleID  string // assigned by the control plane
	localID   string // localprocess handle
	startedAt time.Time
	buf       *retainBuffer

	// sendMu serialises flushes so two goroutines (the output pump and a
	// reconnect resume) cannot interleave chunks and produce out-of-order
	// offsets on the wire.
	sendMu     sync.Mutex
	sentOffset int64

	mu       sync.Mutex
	status   executor.Status
	finished bool
	// cancelProvision aborts an in-flight workspace fetch. It is the only
	// handle anything has on a workload between the start frame and the launch
	// — a clone can run for minutes, and during that window there is no process
	// for a signal to reach. Nil whenever nothing is being fetched.
	cancelProvision context.CancelFunc
	// reported records that the terminal status reached the control plane.
	// A workload that exits while the link is down must keep its slot until
	// a later session can deliver the outcome, or its exit code and log tail
	// would be lost and the control plane would eventually mis-resolve it as
	// failed.
	reported bool
}

// New builds an agent. It does not connect; call Run.
func New(cfg Config) (*Agent, error) {
	if strings.TrimSpace(cfg.CredentialPath) == "" {
		p, err := DefaultCredentialPath()
		if err != nil {
			return nil, err
		}
		cfg.CredentialPath = p
	}

	a := &Agent{
		cfg:       cfg,
		local:     localprocess.New("agent-local"),
		workloads: make(map[string]*workload),
		vault:     newVault(),
	}

	// A stored credential supplies defaults for anything the operator did not
	// pass, so `cloop executor agent` with no flags works after enrollment.
	if cred, err := LoadCredential(cfg.CredentialPath); err == nil {
		a.cred = cred
		if strings.TrimSpace(cfg.Server) == "" {
			a.cfg.Server = cred.Server
		}
		if strings.TrimSpace(cfg.WorkDirRoot) == "" {
			a.cfg.WorkDirRoot = cred.WorkDirRoot
		}
		// An explicit --pin wins, so an operator can re-pin a device after a
		// key rotation without deleting and re-enrolling it.
		if strings.TrimSpace(cfg.Pin) == "" {
			a.cfg.Pin = cred.Pin
		}
		if warn := CheckCredentialPermissions(cfg.CredentialPath); warn != "" {
			a.cfg.logf("warning: %s", warn)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if strings.TrimSpace(a.cfg.Server) == "" {
		return nil, fmt.Errorf("agent: --server is required (no credential at %s to take it from)",
			cfg.CredentialPath)
	}
	if !a.cred.Valid() && strings.TrimSpace(cfg.Token) == "" {
		return nil, fmt.Errorf(
			"agent: this device is not enrolled and no --token was given.\n" +
				"Run `cloop executor enroll --name <name>` on the control plane, then re-run with --token <token>")
	}

	// Settle transport security before anything is dialled. Failing here
	// costs the operator one error message; failing later, mid-handshake,
	// costs them a spent enrollment token and a credential on the wire.
	if err := a.resolveTransport(); err != nil {
		return nil, err
	}

	// Persist a pin supplied by flag on an already-enrolled device.
	//
	// persistCredential only runs at enrollment, so without this a re-pin after
	// a key rotation would apply to this process and vanish on restart — the
	// agent would come back unpinned and say so cheerfully in its banner. It
	// also gives devices enrolled before pinning existed a way to acquire one
	// without being torn down and re-enrolled. Placed after resolveTransport so
	// only a pin that parsed, and is compatible with the endpoint, is written.
	if a.cred.Valid() && strings.TrimSpace(a.cfg.Pin) != strings.TrimSpace(a.cred.Pin) {
		a.cred.Pin = a.cfg.Pin
		if err := SaveCredential(a.cfg.CredentialPath, a.cred); err != nil {
			// Non-fatal: the pin is in effect for this process either way, and
			// refusing to start would be a worse outcome than a warning.
			a.cfg.logf("warning: could not persist the updated pin to %s: %v",
				a.cfg.CredentialPath, err)
		}
	}

	// Normalise the concurrency ceiling once, here, so the value advertised
	// in Capabilities is the same one admission control enforces. Leaving it
	// at zero would advertise NumCPU to the scheduler while accepting an
	// unbounded number of workloads — the control plane would believe in a
	// limit the device does not apply.
	if a.cfg.MaxConcurrent <= 0 {
		a.cfg.MaxConcurrent = defaultConcurrency()
	}

	root, err := resolveRoot(a.cfg.WorkDirRoot)
	if err != nil {
		return nil, err
	}
	a.root = root
	a.cfg.WorkDirRoot = root
	return a, nil
}

// resolveRoot resolves and creates the workdir confinement root.
func resolveRoot(configured string) (string, error) {
	root := strings.TrimSpace(configured)
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("agent: locate home directory for the default workdir root: %w", err)
		}
		root = filepath.Join(home, ".cloop", "work")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("agent: resolve workdir root %q: %w", root, err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return "", fmt.Errorf("agent: create workdir root %s: %w", abs, err)
	}
	// Resolve symlinks once, at startup, so every later containment check
	// compares two fully-resolved paths. Comparing a resolved candidate
	// against an unresolved root would reject legitimate paths on any system
	// where the root traverses a symlink — /home → /var/home on several
	// distributions, /tmp → /private/tmp on macOS.
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	return abs, nil
}

// AgentID returns the enrolled identity, or "" before enrollment.
func (a *Agent) AgentID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cred.AgentID
}

// WorkDirRoot returns the confinement root.
func (a *Agent) WorkDirRoot() string { return a.root }

// Capabilities reports what this device advertises. MaxConcurrent is
// normalised in New, so this is exactly the ceiling admission control applies.
func (a *Agent) Capabilities() remote.AgentCapabilities {
	return Detect(DetectOptions{
		WorkDirRoot:   a.root,
		MaxConcurrent: a.cfg.MaxConcurrent,
		Labels:        a.cfg.Labels,
	})
}

// Run connects and serves until ctx is cancelled or the control plane refuses
// this agent permanently.
func (a *Agent) Run(ctx context.Context) error {
	attempt := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		err := a.runOnce(ctx)
		switch {
		case err == nil:
			// Clean shutdown requested by the control plane.
			return nil
		case errors.Is(err, errDoNotReconnect):
			a.cfg.logf("control plane refused this agent permanently: %v", errors.Unwrap(err))
			return err
		case errors.Is(err, context.Canceled):
			return nil
		}

		attempt++
		delay := reconnectDelay(attempt)
		a.cfg.logf("disconnected (%v); reconnecting in %s", err, delay.Round(time.Millisecond))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
		// A successful session resets the ladder; that is handled in runOnce
		// by clearing the counter through the returned sentinel below.
		if a.consumeConnectedFlag() {
			attempt = 0
		}
	}
}

// connectedFlag lets a session that got as far as a welcome reset the backoff
// ladder, so a device that reconnects successfully every few hours does not
// creep up to the two-minute ceiling and stay there.
var errDoNotReconnect = errors.New("agent: control plane declined reconnection")

func (a *Agent) consumeConnectedFlag() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	was := a.connected
	a.connected = false
	return was
}

// reconnectDelay mirrors pkg/provider/retry.go: exponential growth capped at
// reconnectMaxDelay with ±25% jitter. The jitter matters more here than for
// provider calls — a control plane restarting with a thousand agents attached
// would otherwise get all thousand back in the same millisecond, forever.
func reconnectDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	exp := math.Pow(2, float64(attempt-1))
	delay := time.Duration(float64(reconnectInitialDelay) * exp)
	if delay > reconnectMaxDelay || delay <= 0 {
		delay = reconnectMaxDelay
	}
	jitter := time.Duration((rand.Float64() - 0.5) * 2 * remote.JitterFraction * float64(delay))
	delay += jitter
	if delay < 0 {
		delay = 0
	}
	return delay
}

func defaultConcurrency() int {
	if n := runtime.NumCPU(); n > 0 {
		return n
	}
	return 1
}

// AgentVersion identifies this agent build to the control plane, so version
// skew across a fleet is visible from the Executors panel rather than being
// inferred from behaviour.
const AgentVersion = "1"

// rand64 returns a uniform [0,1) float. Wrapped so the jitter call sites read
// clearly and so a test can substitute a deterministic source if one is ever
// needed.
func rand64() float64 { return rand.Float64() }
