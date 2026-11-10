// Package executorpool is the hub's side of executor pools (Task 20482): sets
// of ephemeral runners that a controller outside the hub starts on demand,
// modelled on GitHub's Actions Runner Controller scale sets.
//
// The division of labour is the scale set's. The hub knows what is waiting
// and who may run it; the controller knows how to start a machine. So:
//
//   - An administrator creates a pool: its name, the labels and capabilities
//     its runners will advertise, max_runners, an owner, and the access list
//     that executors already use. A project is bound to the pool — not to any
//     one runner, which does not exist until a run asks for one.
//   - The administrator mints a controller credential, cloop_pool1_<id>.<secret>,
//     long-lived and revocable, stored only as a SHA-256. The controller
//     presents it over the same pinned-TLS transport agents use.
//   - The controller watches the pool's demand feed: how many queued runs the
//     pool could take, and how many of its runners are busy, idle and still
//     starting. The hub pushes a change; the controller does not poll.
//   - The controller asks for N runner configurations. Each carries a
//     single-use runner token bound to the pool, valid for ten minutes at most,
//     marked ephemeral: the agent it enrolls takes one run and is retired. The
//     hub refuses a request that would take the pool past max_runners, and
//     everything once the pool or the credential is revoked.
//
// This package decides; pkg/statedb stores, atomically; pkg/ui serves the
// routes and runs the queue. What a pool may learn about the queue is the part
// with a security argument, and it lives in demand.go: a run counts towards a
// pool's demand — and is handed to its runners — only while its project is
// still bound to that pool, the pool's access list is the one the run was
// admitted under, the pool's owner (if it has one) may read the project, and
// the pool's runners can satisfy what the run needs, judged by the scheduler's
// own placement rules. A pool never learns of a run it could not take.
package executorpool

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Bounds on a pool's definition.
const (
	// MaxRunnersCeiling caps max_runners. A pool is a fleet one controller
	// scales; a number past this is a typo, not a plan.
	MaxRunnersCeiling = 1000
	// MaxRunAttempts bounds how many runners a queued run is handed. A run
	// every runner fails to start — an image without the harness the pool
	// declared, say — is failed after this many, with the last runner's
	// reason, instead of being handed to runner after runner for ever.
	MaxRunAttempts = 3
	// MaxRunnersPerRequest caps how many runner tokens one controller request
	// may ask for. A controller asks for what its demand says, a few at a
	// time; a request for hundreds is a controller gone wrong.
	MaxRunnersPerRequest = 50
	// maxNameLen bounds a pool's name.
	maxNameLen = 63
	// IDPrefix starts every pool ID.
	IDPrefix = "pool-"
)

// Errors a caller distinguishes with errors.Is.
var (
	// ErrInvalidSpec: a pool definition the hub will not store.
	ErrInvalidSpec = errors.New("executorpool: invalid pool definition")
	// ErrNotFound: no such pool.
	ErrNotFound = statedb.ErrExecutorPoolNotFound
	// ErrRevoked: the pool was revoked.
	ErrRevoked = statedb.ErrExecutorPoolRevoked
	// ErrAtCapacity: a runner mint would exceed max_runners.
	ErrAtCapacity = statedb.ErrExecutorPoolAtCapacity
	// ErrCredentialInvalid: a controller credential that is malformed, unknown,
	// or whose secret does not match.
	ErrCredentialInvalid = errors.New("executorpool: invalid pool credential")
	// ErrCredentialRevoked: a controller credential that was revoked.
	ErrCredentialRevoked = errors.New("executorpool: pool credential revoked")
	// ErrCordoned: a runner mint for a pool an administrator holds (Task
	// 20486).
	ErrCordoned = statedb.ErrExecutorPoolCordoned
)

// namePattern is what a pool's name may be: what a Kubernetes object may be
// called, so a controller can name its runners after it.
var namePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// Capabilities is what a pool's runners advertise, as the administrator
// declares it. Placement matches a queued run against it (Template) before a
// runner exists, and against the runner itself once one does.
type Capabilities struct {
	// Harnesses are the agent CLIs a runner has ("claude", "git"). Empty
	// claims nothing and, as for a device, satisfies any harness requirement.
	Harnesses []string `json:"harnesses,omitempty"`
	// ContainerRuntimes a runner can drive; empty for none.
	ContainerRuntimes []string `json:"container_runtimes,omitempty"`
	// Platform and Arch are GOOS/GOARCH style; empty claims nothing.
	Platform string `json:"platform,omitempty"`
	Arch     string `json:"arch,omitempty"`
	// MemoryMB and CPUs size one runner; 0 is unknown.
	MemoryMB int `json:"memory_mb,omitempty"`
	CPUs     int `json:"cpus,omitempty"`
}

// normalize trims, lowercases, sorts and deduplicates the lists.
func (c Capabilities) normalize() Capabilities {
	clean := func(in []string) []string {
		seen := map[string]bool{}
		var out []string
		for _, v := range in {
			v = strings.ToLower(strings.TrimSpace(v))
			if v == "" || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
		sort.Strings(out)
		return out
	}
	c.Harnesses = clean(c.Harnesses)
	c.ContainerRuntimes = clean(c.ContainerRuntimes)
	c.Platform = strings.ToLower(strings.TrimSpace(c.Platform))
	c.Arch = strings.ToLower(strings.TrimSpace(c.Arch))
	return c
}

// validate refuses what no runner could honestly advertise.
func (c Capabilities) validate() error {
	if c.MemoryMB < 0 || c.CPUs < 0 {
		return fmt.Errorf("%w: memory_mb and cpus cannot be negative", ErrInvalidSpec)
	}
	for _, list := range [][]string{c.Harnesses, c.ContainerRuntimes} {
		if len(list) > 32 {
			return fmt.Errorf("%w: at most 32 harnesses or container runtimes", ErrInvalidSpec)
		}
		for _, v := range list {
			if len(v) > 64 || strings.ContainsAny(v, " \t\n,") {
				return fmt.Errorf("%w: %q is not a harness or runtime name", ErrInvalidSpec, v)
			}
		}
	}
	return nil
}

// Spec is a pool's definition as an administrator writes it.
type Spec struct {
	Name         string            `json:"name"`
	Labels       map[string]string `json:"labels,omitempty"`
	Capabilities Capabilities      `json:"capabilities"`
	MaxRunners   int               `json:"max_runners"`
	// Owner is the pool's owner in oidcauth.Identity's OwnerKey namespace (a
	// lowercased email, or "sub:<subject>"); "" for an organisation pool.
	Owner string `json:"owner,omitempty"`
	// WorkDirRoot is the root its runners confine workloads to; "" lets the
	// runner choose.
	WorkDirRoot string `json:"workdir_root,omitempty"`
}

// Normalize returns the spec as it is stored.
func (s Spec) Normalize() Spec {
	s.Name = strings.ToLower(strings.TrimSpace(s.Name))
	s.Labels = executor.NormalizeLabels(s.Labels)
	s.Capabilities = s.Capabilities.normalize()
	// An owner key is a lowercased email or "sub:<subject>", and a subject is
	// case-sensitive: only an email is folded.
	owner := strings.TrimSpace(s.Owner)
	if len(owner) >= 4 && strings.EqualFold(owner[:4], "sub:") {
		s.Owner = "sub:" + strings.TrimSpace(owner[4:])
	} else {
		s.Owner = strings.ToLower(owner)
	}
	s.WorkDirRoot = strings.TrimSpace(s.WorkDirRoot)
	return s
}

// Validate reports whether the (normalized) spec may be stored.
func (s Spec) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("%w: a pool needs a name", ErrInvalidSpec)
	}
	if len(s.Name) > maxNameLen || !namePattern.MatchString(s.Name) {
		return fmt.Errorf("%w: name %q must be 1-%d lowercase letters, digits and dashes, starting and ending "+
			"with a letter or digit", ErrInvalidSpec, s.Name, maxNameLen)
	}
	if s.MaxRunners < 1 || s.MaxRunners > MaxRunnersCeiling {
		return fmt.Errorf("%w: max_runners must be between 1 and %d, not %d", ErrInvalidSpec, MaxRunnersCeiling, s.MaxRunners)
	}
	if err := executor.ValidateLabels(s.Labels); err != nil {
		return fmt.Errorf("%w: labels: %v", ErrInvalidSpec, err)
	}
	if err := s.Capabilities.validate(); err != nil {
		return err
	}
	if s.WorkDirRoot != "" && !strings.HasPrefix(s.WorkDirRoot, "/") {
		return fmt.Errorf("%w: workdir_root %q must be an absolute path", ErrInvalidSpec, s.WorkDirRoot)
	}
	if strings.ContainsAny(s.Owner, " \t\n") || len(s.Owner) > 320 {
		return fmt.Errorf("%w: owner %q is not an identity", ErrInvalidSpec, s.Owner)
	}
	return nil
}

// Pool is one executor pool.
type Pool struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Labels       map[string]string `json:"labels,omitempty"`
	Capabilities Capabilities      `json:"capabilities"`
	MaxRunners   int               `json:"max_runners"`
	Owner        string            `json:"owner,omitempty"`
	WorkDirRoot  string            `json:"workdir_root,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	CreatedBy    string            `json:"created_by,omitempty"`
	UpdatedAt    time.Time         `json:"updated_at"`
	UpdatedBy    string            `json:"updated_by,omitempty"`
	RevokedAt    time.Time         `json:"revoked_at,omitempty"`
	RevokedBy    string            `json:"revoked_by,omitempty"`
	// CordonedAt, CordonedBy and CordonReason are set while an administrator
	// holds the pool (Task 20486): its runners are handed no queued run, its
	// controller is told no demand and minted no runner, and runners already
	// busy finish their runs.
	CordonedAt   time.Time `json:"cordoned_at,omitzero"`
	CordonedBy   string    `json:"cordoned_by,omitempty"`
	CordonReason string    `json:"cordon_reason,omitempty"`
}

// Revoked reports whether the pool was revoked.
func (p Pool) Revoked() bool { return !p.RevokedAt.IsZero() }

// Cordoned reports whether an administrator holds the pool.
func (p Pool) Cordoned() bool { return !p.CordonedAt.IsZero() }

// Binding is the project binding value that names this pool.
func (p Pool) Binding() string { return executor.PoolBinding(p.ID) }

// Spec is the pool's definition.
func (p Pool) Spec() Spec {
	return Spec{Name: p.Name, Labels: p.Labels, Capabilities: p.Capabilities, MaxRunners: p.MaxRunners,
		Owner: p.Owner, WorkDirRoot: p.WorkDirRoot}
}

// fromRow decodes a stored pool. Capabilities that do not decode are dropped
// rather than failing the read: they are what the pool claims, and claiming
// nothing is the conservative reading.
func fromRow(r statedb.ExecutorPoolRow) Pool {
	p := Pool{ID: r.ID, Name: r.Name, Labels: r.Labels, MaxRunners: r.MaxRunners, Owner: r.Owner,
		WorkDirRoot: r.WorkDirRoot, CreatedAt: r.CreatedAt, CreatedBy: r.CreatedBy, UpdatedAt: r.UpdatedAt,
		UpdatedBy: r.UpdatedBy, RevokedAt: r.RevokedAt, RevokedBy: r.RevokedBy, CordonedAt: r.CordonedAt,
		CordonedBy: r.CordonedBy, CordonReason: r.CordonReason}
	if strings.TrimSpace(r.Capabilities) != "" {
		_ = json.Unmarshal([]byte(r.Capabilities), &p.Capabilities)
	}
	return p
}

// toRow encodes a pool for storage.
func toRow(p Pool) (statedb.ExecutorPoolRow, error) {
	caps, err := json.Marshal(p.Capabilities)
	if err != nil {
		return statedb.ExecutorPoolRow{}, fmt.Errorf("executorpool: encode capabilities: %w", err)
	}
	return statedb.ExecutorPoolRow{ID: p.ID, Name: p.Name, Labels: p.Labels, Capabilities: string(caps),
		MaxRunners: p.MaxRunners, Owner: p.Owner, WorkDirRoot: p.WorkDirRoot, CreatedAt: p.CreatedAt,
		CreatedBy: p.CreatedBy, UpdatedAt: p.UpdatedAt, UpdatedBy: p.UpdatedBy, RevokedAt: p.RevokedAt,
		RevokedBy: p.RevokedBy, CordonedAt: p.CordonedAt, CordonedBy: p.CordonedBy, CordonReason: p.CordonReason}, nil
}

// b64 renders random bytes without padding, so IDs and secrets are one
// shell word.
var b64 = base64.RawURLEncoding

// randomString returns n random bytes, base64url encoded.
func randomString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b64.EncodeToString(buf), nil
}

// newPoolID mints a pool ID: IDPrefix and 16 characters, lowercase so it may
// be part of a Kubernetes object name.
func newPoolID() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("executorpool: generate pool id: %w", err)
	}
	for i, b := range buf {
		buf[i] = alphabet[int(b)%len(alphabet)]
	}
	return IDPrefix + string(buf), nil
}
