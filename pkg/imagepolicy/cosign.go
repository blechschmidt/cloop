package imagepolicy

// cosign.go verifies image signatures by shelling out to the cosign binary.
//
// # Why a subprocess and not a library
//
// sigstore's Go verification path pulls in a large transitive tree — Fulcio,
// Rekor, TUF, a certificate chain implementation — into the process that holds
// every project's brokered credentials. cosign is a single static binary an
// operator installs deliberately, it is the thing whose behaviour the sigstore
// documentation actually describes, and it is what the operator will use by
// hand when a verification fails and they want to know why. The cost is a
// process spawn per unique digest, amortised by the cache below.
//
// # Fail closed, loudly
//
// The failure that matters is not "the signature is bad" — that is a clean
// refusal. It is "cosign is not installed", which a naive implementation turns
// into a skipped check: the hub reports every image as fine while verifying
// nothing, and the misconfiguration is invisible precisely because it looks
// like success. So a missing binary is a *denial* with an installation
// diagnostic, never a pass and never a warning.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// CosignBinary is the executable looked up on PATH.
const CosignBinary = "cosign"

// cosignTimeout bounds one verification. Keyless verification contacts Fulcio
// and Rekor, so it is a network operation; the bound is generous but must
// exist, or an unreachable transparency log wedges a workload start.
const cosignTimeout = 2 * time.Minute

// verifyCacheTTL bounds how long a successful verification is reused.
//
// Only successes are cached. A digest's signature does not change — that is
// what content addressing means — so the cache is sound, and the TTL exists so
// a revoked key or a rotated policy takes effect within the hour rather than at
// the next hub restart. Failures are never cached: an operator who has just
// signed the image should not have to wait out a TTL to see it work.
const verifyCacheTTL = time.Hour

// ErrCosignMissing reports that the cosign binary is not installed. It is a
// sentinel so the UI can render an install hint rather than a generic failure.
var ErrCosignMissing = errors.New("imagepolicy: cosign is not installed")

// CosignVerifier verifies signatures with the cosign CLI.
//
// The zero value is usable and looks cosign up on PATH.
type CosignVerifier struct {
	// Binary overrides the executable path. Tests set it; deployments do not.
	Binary string

	mu    sync.Mutex
	cache map[string]time.Time
}

// NewCosignVerifier returns a verifier using cosign from PATH.
func NewCosignVerifier() *CosignVerifier { return &CosignVerifier{} }

// Verify implements Verifier. ref must be digest-pinned.
func (v *CosignVerifier) Verify(ctx context.Context, ref string, p Policy) error {
	n := p.Normalize()
	if len(n.CosignPublicKeys) == 0 && len(n.CosignIdentities) == 0 {
		return errors.New("no cosign keys or identities are configured")
	}

	key := n.Fingerprint() + "|" + ref
	if v.cached(key) {
		return nil
	}

	bin := v.Binary
	if bin == "" {
		found, err := exec.LookPath(CosignBinary)
		if err != nil {
			d := deny(RuleSignature,
				fmt.Sprintf("this hub requires signed images, but %q is not installed on it, so "+
					"the signature of %s could not be checked", CosignBinary, ref),
				"Install cosign on the hub (https://docs.sigstore.dev/cosign/installation/) and "+
					"restart it, or turn off sandbox.image_policy.require_signature. The image is "+
					"refused rather than admitted unverified.")
			return fmt.Errorf("%w: %w", ErrCosignMissing, d.Err())
		}
		bin = found
	}

	// The registry login the caller resolved the tag with, when it carries one
	// for this image's registry: cosign fetches the signature from the same
	// registry, and must do so as the same identity (Task 20457).
	env, cleanup, err := cosignLoginEnv(ctx, ref)
	if err != nil {
		return err
	}
	defer cleanup()

	// Any one accepted key or identity is enough: they are alternatives, not a
	// quorum. An operator listing two keys is describing a rotation or two
	// trusted publishers, not a requirement that both signed.
	var failures []string
	for _, keyPath := range n.CosignPublicKeys {
		err := v.run(ctx, bin, ref, env, "--key", keyPath)
		if err == nil {
			v.remember(key)
			return nil
		}
		failures = append(failures, fmt.Sprintf("key %s: %v", keyPath, err))
	}
	for _, id := range n.CosignIdentities {
		if _, err := compileIdentity(id); err != nil {
			failures = append(failures, fmt.Sprintf("identity %s: %v", id.Issuer, err))
			continue
		}
		err := v.run(ctx, bin, ref, env,
			"--certificate-oidc-issuer", id.Issuer,
			"--certificate-identity-regexp", id.SubjectRegexp)
		if err == nil {
			v.remember(key)
			return nil
		}
		failures = append(failures, fmt.Sprintf("identity %s: %v", id.Issuer, err))
	}
	return fmt.Errorf("no configured key or identity verified %s (%s)", ref, strings.Join(failures, "; "))
}

// run executes one cosign verify invocation. env, when not nil, is the
// environment to run it with instead of this process's.
func (v *CosignVerifier) run(ctx context.Context, bin, ref string, env []string, args ...string) error {
	runCtx, cancel := context.WithTimeout(ctx, cosignTimeout)
	defer cancel()

	// "--" before the reference: it is the one argument derived from a
	// repo-committed file, and although ParseReference has already refused a
	// leading '-', the terminator makes that a defence in depth rather than
	// the only thing standing between a project and cosign's flag parser.
	argv := append([]string{"verify"}, args...)
	argv = append(argv, "--output", "text", "--", ref)

	cmd := exec.CommandContext(runCtx, bin, argv...)
	// cosign reads $HOME and registry credentials from the ambient
	// environment; it is the hub's own identity that pulls the signature, not
	// the project's, so the environment is inherited rather than scrubbed —
	// with DOCKER_CONFIG pointed at the caller's login when it has one.
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	if runCtx.Err() != nil {
		return fmt.Errorf("cosign timed out after %s", cosignTimeout)
	}
	return errors.New(lastLine(string(out), err))
}

// cosignLoginEnv returns the environment a cosign run for ref takes the login
// ctx carries for ref's registry from (WithRegistryLogins), with the cleanup
// that removes it. With none, it returns a nil environment — this process's,
// as before — and a cleanup that does nothing.
//
// cosign has no way to take a password but a file or an argument, and an
// argument is readable by every user on the host in /proc. So the one login is
// written, alone, to a config.json in a private directory (0700, the file
// 0600) that DOCKER_CONFIG names for this run and that is removed when the
// verification ends. Nothing but the login for this registry is in it, so the
// cosign run cannot present any other.
func cosignLoginEnv(ctx context.Context, ref string) ([]string, func(), error) {
	nothing := func() {}
	logins, ok := registryLoginsFrom(ctx)
	if !ok || logins.Empty() {
		return nil, nothing, nil
	}
	parsed, err := ParseReference(ref)
	if err != nil {
		return nil, nothing, nil
	}
	cfg, ok := logins.dockerConfigFor(parsed.Registry)
	if !ok {
		return nil, nothing, nil
	}
	dir, err := os.MkdirTemp("", "cloop-cosign-login-")
	if err != nil {
		return nil, nothing, fmt.Errorf("imagepolicy: stage the registry login for cosign: %w", err)
	}
	cleanup := func() {
		// Overwritten before it is removed, so the bytes do not outlive the
		// file in a filesystem that keeps freed blocks around.
		path := filepath.Join(dir, "config.json")
		if fi, err := os.Stat(path); err == nil {
			_ = os.WriteFile(path, make([]byte, fi.Size()), 0o600)
		}
		_ = os.RemoveAll(dir)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), cfg, 0o600); err != nil {
		cleanup()
		return nil, nothing, fmt.Errorf("imagepolicy: stage the registry login for cosign: %w", err)
	}
	for i := range cfg {
		cfg[i] = 0
	}
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "DOCKER_CONFIG=") {
			env = append(env, kv)
		}
	}
	return append(env, "DOCKER_CONFIG="+dir), cleanup, nil
}

// cached reports a still-valid successful verification.
func (v *CosignVerifier) cached(key string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	at, ok := v.cache[key]
	return ok && time.Since(at) < verifyCacheTTL
}

func (v *CosignVerifier) remember(key string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.cache == nil {
		v.cache = make(map[string]time.Time)
	}
	// Bounded: the key space is (policy fingerprint, digest), so it grows with
	// the number of distinct images a hub runs. A hard cap keeps a hub that
	// churns through images from accumulating entries forever.
	const maxEntries = 512
	if len(v.cache) >= maxEntries {
		v.cache = make(map[string]time.Time)
	}
	v.cache[key] = time.Now()
}

// compileIdentity checks that an identity's subject pattern is a usable regexp.
func compileIdentity(id Identity) (*regexp.Regexp, error) {
	re, err := regexp.Compile(id.SubjectRegexp)
	if err != nil {
		return nil, fmt.Errorf("subject_regexp %q does not compile: %w", id.SubjectRegexp, err)
	}
	return re, nil
}

// lastLine returns the most useful line of cosign's output — its errors are on
// the final line, under a banner of tlog and certificate chatter.
func lastLine(out string, fallback error) string {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if s := strings.TrimSpace(lines[i]); s != "" {
			return s
		}
	}
	return fallback.Error()
}
