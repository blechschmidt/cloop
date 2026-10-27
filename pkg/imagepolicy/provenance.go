package imagepolicy

// provenance.go checks cloop's own published images against the signing
// identity of the workflow that publishes them (Task 20453).
//
// The image policy in policy.go is a project's: it governs what a repository's
// .cloop/sandbox.yaml may name, and an operator's own image is chosen beside it
// and exempt. That left the image nearly every sandbox actually runs — the
// default, ghcr.io/blechschmidt/cloop-harness:latest — checked by nothing.
// Whoever could push to that package decided what ran beside every lease's
// credentials on every hub that kept the default.
//
// So an image from one of cloop's own repositories is held to a pin of its
// own, whoever chose it: the operator's default, an executor configured with it
// explicitly, a device's or a virtual executor's sandbox image, or a project
// that names it. The digest is resolved — from the local store after the pull
// on the container driver, at the registry for a device — verified with cosign
// against provenance.ImagesIdentity(), and the dispatch names the digest.
//
// # What refuses and what warns
//
// A signature that is present and wrong — another identity, another issuer,
// bytes that do not match — always refuses: there is no reading of it in which
// running the image is what anyone intended. An image with no signature at all
// is what every hub holds the day it upgrades to this, because nothing was
// signed before; a hub without cosign cannot check either way. Both are a
// warning by default, on the run and in `cloop hub doctor`, so an upgrade never
// stops a working hub. executors.image_provenance: required turns them into
// refusals, and with it nothing of cloop's runs unless it was verified.
//
// The warning is a real residual, and the docs say so: under the default,
// someone who can push to the registry and leaves their image unsigned has it
// run, with a warning. Deleting a signature is always possible, so telling
// "unsigned" apart from "could not be checked" buys nothing against them; only
// "required" does.

import (
	"context"
	"debug/buildinfo"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/blechschmidt/cloop/pkg/provenance"
)

// OwnRepositories are the repositories .github/workflows/publish-images.yml
// publishes, as registry/repository. tests/docs holds the list equal to that
// workflow's matrix, so an image added there is verified here.
var OwnRepositories = []string{
	"ghcr.io/blechschmidt/cloop",
	"ghcr.io/blechschmidt/cloop-harness",
	"ghcr.io/blechschmidt/cloop-harness-copilot",
}

// IsOwnImage reports whether ref names one of OwnRepositories.
//
// On the parsed reference, whole names only: "ghcr.io/blechschmidt/cloop-harness"
// is one of them, a repository that merely begins with that name, the same path
// on another registry, and a reference naming no registry at all are not.
func IsOwnImage(ref string) bool {
	parsed, err := ParseReference(strings.TrimSpace(ref))
	if err != nil || !parsed.Qualified {
		return false
	}
	name := parsed.Name()
	for _, own := range OwnRepositories {
		if name == own {
			return true
		}
	}
	return false
}

// ProvenanceStatus is the verdict on one of cloop's own images.
type ProvenanceStatus string

const (
	// ProvenanceVerified: cosign verified the digest against the pin.
	ProvenanceVerified ProvenanceStatus = "verified"
	// ProvenanceUnsigned: the digest carries no signature at all — an image
	// published before signing began, or one somebody pushed unsigned.
	ProvenanceUnsigned ProvenanceStatus = "unsigned"
	// ProvenanceUnverifiable: nothing could say either way — no cosign on the
	// hub, a tag the executor cannot resolve to a digest, an image built
	// locally with no registry digest, a registry or transparency log the hub
	// cannot reach.
	ProvenanceUnverifiable ProvenanceStatus = "unverifiable"
	// ProvenanceMismatch: a signature is present and it is not the pinned
	// workflow's. Always refused.
	ProvenanceMismatch ProvenanceStatus = "mismatch"
)

// RuleProvenance names the refusal of one of cloop's own images, in a
// DenyError, the audit row and the API response.
const RuleProvenance = "image-provenance"

// Provenance is the record of one verification: what was configured, what was
// dispatched, and what cosign found. It rides the executor's handle, the run's
// sandbox record — and through it every task artifact and task.dispatch row —
// and the doctor's report.
type Provenance struct {
	// Image is the reference as it was configured or named.
	Image string `json:"image"`
	// Ref is what the dispatch names: the digest-pinned form when a digest
	// was resolved, otherwise Image.
	Ref string `json:"ref"`
	// Digest is the digest that was checked, empty when none was resolved.
	Digest string `json:"digest,omitempty"`
	// Status is the verdict.
	Status ProvenanceStatus `json:"status"`
	// Issuer and Identity are the pin the digest was checked against.
	Issuer   string `json:"issuer,omitempty"`
	Identity string `json:"identity,omitempty"`
	// Detail is why, in cosign's words where cosign ran.
	Detail string `json:"detail,omitempty"`
	// Warning is the sentence a run carries when the image ran unverified,
	// empty when it was verified.
	Warning string `json:"warning,omitempty"`
	// CheckedAt is when the verdict was reached.
	CheckedAt time.Time `json:"checked_at"`
}

// Verified reports whether the image ran as a digest cosign verified.
func (p *Provenance) Verified() bool { return p != nil && p.Status == ProvenanceVerified }

// VerifiedDigest is the digest that was verified, empty unless Verified.
func (p *Provenance) VerifiedDigest() string {
	if !p.Verified() {
		return ""
	}
	return p.Digest
}

// ProvenanceVerdict is what a ProvenanceVerifier found for one digest.
type ProvenanceVerdict struct {
	Status ProvenanceStatus
	// Detail is the diagnosis, in the verifier's own words.
	Detail string
}

// ProvenanceVerifier checks a digest-pinned reference against the images pin.
type ProvenanceVerifier interface {
	// VerifyProvenance never returns ProvenanceVerified for anything but an
	// explicit pass.
	VerifyProvenance(ctx context.Context, ref string) ProvenanceVerdict
	// TrustRoot is the pin it verifies against, for the record.
	TrustRoot() (issuer, identity string)
}

// provenanceTimeout bounds one cosign run for one of cloop's own images. It is
// shorter than cosignTimeout because this check sits in front of every
// dispatch of the default image, warning-only by default: a transparency log
// the hub cannot reach must cost a run a minute at most, not two, and the
// verdict is then remembered (provenanceTTL) so it does not cost the next one.
var provenanceTimeout = 60 * time.Second

// provenanceTTL is how long a verdict is reused. A digest's signatures are
// added by the workflow that pushes it, within minutes, and never change after,
// so a verified one is reused for the hour the project policy's cache reuses
// one; the others are re-asked sooner, and a mismatch — a refusal — is never
// cached, so a corrected trust root takes effect on the next dispatch.
func provenanceTTL(s ProvenanceStatus) time.Duration {
	switch s {
	case ProvenanceVerified:
		return time.Hour
	case ProvenanceUnsigned:
		return 10 * time.Minute
	case ProvenanceUnverifiable:
		return 2 * time.Minute
	}
	return 0
}

// CosignProvenanceVerifier verifies cloop's own images with the cosign CLI
// against provenance.ImagesIssuer and provenance.ImagesIdentity. The zero value
// is usable and finds cosign on PATH.
type CosignProvenanceVerifier struct {
	// Binary overrides the cosign executable. Tests set it.
	Binary string
	// Issuer and Identity override the pin. Empty reads the provenance
	// package's, environment overrides included, at each verification.
	Issuer, Identity string

	group singleflight.Group
	mu    sync.Mutex
	cache map[string]cachedVerdict
}

type cachedVerdict struct {
	verdict ProvenanceVerdict
	until   time.Time
}

// TrustRoot is the pin a verification requires.
func (v *CosignProvenanceVerifier) TrustRoot() (issuer, identity string) {
	issuer, identity = provenance.ImagesIssuer(), provenance.ImagesIdentity()
	if s := strings.TrimSpace(v.Issuer); s != "" {
		issuer = s
	}
	if s := strings.TrimSpace(v.Identity); s != "" {
		identity = s
	}
	return issuer, identity
}

// Path returns the cosign executable that would run, or ErrCosignMissing.
func (v *CosignProvenanceVerifier) Path() (string, error) {
	if s := strings.TrimSpace(v.Binary); s != "" {
		return s, nil
	}
	p, err := exec.LookPath(CosignBinary)
	if err != nil {
		return "", fmt.Errorf("%w: %s is not on this host's PATH", ErrCosignMissing, CosignBinary)
	}
	return p, nil
}

// VerifyProvenance implements ProvenanceVerifier.
func (v *CosignProvenanceVerifier) VerifyProvenance(ctx context.Context, ref string) ProvenanceVerdict {
	parsed, err := ParseReference(ref)
	if err != nil || !parsed.Pinned() {
		// A tag is never verified: the signature would describe whatever the
		// tag pointed at during the check.
		return ProvenanceVerdict{Status: ProvenanceUnverifiable,
			Detail: fmt.Sprintf("%q is not pinned to a digest, so there is nothing a signature could be verified on", ref)}
	}
	bin, err := v.Path()
	if err != nil {
		return ProvenanceVerdict{Status: ProvenanceUnverifiable, Detail: err.Error()}
	}
	issuer, identity := v.TrustRoot()
	key := issuer + "\x00" + identity + "\x00" + parsed.Canonical()
	if got, ok := v.cached(key); ok {
		return got
	}
	out, _, _ := v.group.Do(key, func() (any, error) {
		verdict := runCosignVerify(ctx, bin, parsed.Canonical(), issuer, identity)
		v.remember(key, verdict)
		return verdict, nil
	})
	return out.(ProvenanceVerdict)
}

// runCosignVerify runs one `cosign verify` and classifies its answer.
//
// The classes are read from cosign's own words, measured against cosign v2.6
// and v3.1 (Task 20453): "no signatures found", exit status 10, for a digest
// nothing signed; "no matching signatures", "no matching attestations" or "no
// matching CertificateIdentity" for a signature from someone else; anything
// else — a registry that is unreachable or refuses, a transparency log or TUF
// mirror out of reach, a timeout — is a check that could not be made. The
// reading errs only between the two warning classes: a refusal is never
// produced from a check that did not find a wrong signature, and a pass never
// from anything but exit status 0.
func runCosignVerify(ctx context.Context, bin, ref, issuer, identity string) ProvenanceVerdict {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, provenanceTimeout)
	defer cancel()
	// "--" before the reference, as in CosignVerifier.run: a defence in depth
	// behind ParseReference, which refuses a leading '-' already.
	cmd := exec.CommandContext(runCtx, bin, "verify",
		"--certificate-oidc-issuer", issuer,
		"--certificate-identity-regexp", identity,
		"--output", "text", "--", ref)
	// The hub's own environment: cosign reads its TUF cache under $HOME and
	// registry logins from the Docker configuration there, as the project
	// policy's verifier does.
	out, err := cmd.CombinedOutput()
	if err == nil {
		return ProvenanceVerdict{Status: ProvenanceVerified,
			Detail: "cosign verified the signature against " + identity}
	}
	if runCtx.Err() != nil {
		return ProvenanceVerdict{Status: ProvenanceUnverifiable,
			Detail: fmt.Sprintf("cosign did not finish within %s", provenanceTimeout)}
	}
	text := string(out)
	detail := cosignDiagnosis(text, err)
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr) && exitErr.ExitCode() == 10, strings.Contains(text, "no signatures found"):
		return ProvenanceVerdict{Status: ProvenanceUnsigned, Detail: detail}
	case strings.Contains(text, "no matching signatures"),
		strings.Contains(text, "no matching attestations"),
		strings.Contains(text, "no matching CertificateIdentity"),
		strings.Contains(text, "none of the expected identities matched"),
		strings.Contains(text, "invalid signature"):
		return ProvenanceVerdict{Status: ProvenanceMismatch, Detail: detail}
	}
	return ProvenanceVerdict{Status: ProvenanceUnverifiable, Detail: detail}
}

// cosignDiagnosis keeps the lines of cosign's output that say what went wrong,
// bounded: its errors come last, under a banner of tlog and certificate
// chatter, and one of them repeats as "error during command execution".
func cosignDiagnosis(out string, fallback error) string {
	var keep []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "error during command execution:") {
			continue
		}
		keep = append(keep, line)
	}
	if len(keep) > 2 {
		keep = keep[len(keep)-2:]
	}
	s := strings.Join(keep, "; ")
	if s == "" && fallback != nil {
		s = fallback.Error()
	}
	const maxDetail = 600
	if len(s) > maxDetail {
		s = s[:maxDetail] + "…"
	}
	return s
}

func (v *CosignProvenanceVerifier) cached(key string) (ProvenanceVerdict, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	c, ok := v.cache[key]
	if !ok || time.Now().After(c.until) {
		return ProvenanceVerdict{}, false
	}
	return c.verdict, true
}

func (v *CosignProvenanceVerifier) remember(key string, verdict ProvenanceVerdict) {
	ttl := provenanceTTL(verdict.Status)
	if ttl <= 0 {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.cache == nil || len(v.cache) >= 512 {
		v.cache = make(map[string]cachedVerdict)
	}
	v.cache[key] = cachedVerdict{verdict: verdict, until: time.Now().Add(ttl)}
}

// sharedProvenanceVerifier is the verifier the drivers use when their options
// name none, so its cache is the process's and a hub running one image all day
// runs cosign for it once an hour.
var (
	sharedProvenanceOnce     sync.Once
	sharedProvenanceVerifier *CosignProvenanceVerifier
)

// SharedProvenanceVerifier returns the process's cosign provenance verifier.
func SharedProvenanceVerifier() *CosignProvenanceVerifier {
	sharedProvenanceOnce.Do(func() { sharedProvenanceVerifier = &CosignProvenanceVerifier{} })
	return sharedProvenanceVerifier
}

// OwnImageCheck verifies one dispatch of one of cloop's own images.
type OwnImageCheck struct {
	// Image is the reference as configured or named.
	Image string
	// Resolver turns a tag into the digest that will run. Nil means this
	// executor cannot resolve a tag (Kubernetes): only a digest is checked.
	Resolver Resolver
	// Verifier checks the digest. Nil means nothing can check it here.
	Verifier ProvenanceVerifier
	// Required refuses anything not verified (executors.image_provenance:
	// required). Unset, only a mismatch refuses.
	Required bool
	// Subject names where the image runs, for the messages: "this executor",
	// "agent edge-1 (abc)".
	Subject string
	// Field names where the image was chosen, for the remedies:
	// "executors.container.image", "the device's sandbox image".
	Field string
}

// Run resolves, verifies and decides. It returns the record of the
// verification and, on refusal, a *DenyError under RuleProvenance. An error
// that is not a verdict — the container driver's "image is not present
// locally", naming the pull — is returned as it is, for the driver's own
// diagnostic to reach the operator.
func (c OwnImageCheck) Run(ctx context.Context) (Provenance, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	image := strings.TrimSpace(c.Image)
	p := Provenance{Image: image, Ref: image, CheckedAt: time.Now().UTC()}
	p.Issuer, p.Identity = provenance.ImagesIssuer(), provenance.ImagesIdentity()
	if c.Verifier != nil {
		p.Issuer, p.Identity = c.Verifier.TrustRoot()
	}
	parsed, err := ParseReference(image)
	if err != nil {
		d := deny(RuleSyntax, err.Error(),
			"Write the image as registry/repository:tag or registry/repository@sha256:….")
		return p, &DenyError{Ref: image, Rule: d.Rule, Reason: d.Reason, Remediation: d.Remediation}
	}

	digest := parsed.Digest
	switch {
	case digest != "":
	case c.Resolver == nil:
		return c.decide(p, ProvenanceVerdict{Status: ProvenanceUnverifiable, Detail: fmt.Sprintf(
			"%s is a tag, and %s cannot resolve a tag to a digest, so there is nothing a signature "+
				"could be verified on", image, c.subject())})
	default:
		resolved, err := c.Resolver.ResolveDigest(ctx, parsed.String())
		switch {
		case errors.Is(err, ErrNoDigest):
			return c.decide(p, ProvenanceVerdict{Status: ProvenanceUnverifiable, Detail: fmt.Sprintf(
				"%s has no registry digest — it was built locally or loaded from a tarball — so no "+
					"signature can be verified for it", image)})
		case errors.Is(err, ErrRegistry):
			return c.decide(p, ProvenanceVerdict{Status: ProvenanceUnverifiable, Detail: err.Error()})
		case err != nil:
			return p, err
		}
		digest = resolved
	}
	pinned, err := parsed.WithDigest(digest)
	if err != nil {
		return p, fmt.Errorf("imagepolicy: the digest resolved for %q is unusable: %w", image, err)
	}
	p.Digest, p.Ref = pinned.Digest, pinned.Canonical()
	if c.Verifier == nil {
		return c.decide(p, ProvenanceVerdict{Status: ProvenanceUnverifiable,
			Detail: "no signature verifier is configured on this hub"})
	}
	return c.decide(p, c.Verifier.VerifyProvenance(ctx, p.Ref))
}

// decide applies the verdict: a pass, a warning, or a refusal.
func (c OwnImageCheck) decide(p Provenance, v ProvenanceVerdict) (Provenance, error) {
	p.Status, p.Detail = v.Status, v.Detail
	if p.Status == "" {
		p.Status = ProvenanceUnverifiable
	}
	switch p.Status {
	case ProvenanceVerified:
		return p, nil
	case ProvenanceMismatch:
		return p, &DenyError{
			Ref:  p.Image,
			Rule: RuleProvenance,
			Reason: fmt.Sprintf("%s is one of cloop's own images, and the signature on %s is not from the "+
				"workflow that publishes them (%s, issuer %s): %s", p.Image, p.Ref, p.Identity, p.Issuer, p.Detail),
			Remediation: "Do not run it. Pull the image again from " + parsedName(p.Image) +
				" and compare its digest with the one the release names; if the registry serves this one, " +
				"report it. A rebuilt image signed by another workflow is checked against that workflow " +
				"once " + provenance.ImagesIdentityEnv + " names it.",
		}
	}
	what, ran := "could not be verified", "unverified"
	if p.Status == ProvenanceUnsigned {
		what, ran = "is unsigned", "without a signature"
	}
	if c.Required {
		return p, &DenyError{
			Ref:  p.Image,
			Rule: RuleProvenance,
			Reason: fmt.Sprintf("%s is one of cloop's own images and %s, and executors.image_provenance is "+
				"required: %s", p.Image, what, p.Detail),
			Remediation: c.remedy(p.Status),
		}
	}
	p.Warning = fmt.Sprintf("%s ran %s on %s: %s. %s", p.Image, ran, c.subject(),
		strings.TrimSuffix(p.Detail, "."), c.remedy(p.Status))
	return p, nil
}

// Remedy is what to do about an image this check did not verify: the sentence
// a refusal ends with, and the one `cloop hub doctor` prints.
func (c OwnImageCheck) Remedy(s ProvenanceStatus) string { return c.remedy(s) }

// remedy is what to do about an image that was not verified.
func (c OwnImageCheck) remedy(s ProvenanceStatus) string {
	field := c.Field
	if field == "" {
		field = "the image"
	}
	switch {
	case s == ProvenanceUnsigned:
		return "Pull a build published since signing began — :edge, or a release after v0.0.7 — and " +
			"check it with `cloop hub verify-image " + parsedName(c.Image) + ":<tag>`; with " +
			"executors.image_provenance: required an unsigned image is refused."
	case c.Resolver == nil:
		return "Pin " + field + " by digest (`docker buildx imagetools inspect " + parsedName(c.Image) +
			":<tag>` prints it), so the hub can verify it before a Pod runs it."
	}
	return "Install cosign on the hub (the published hub image bundles it) and let the hub reach the " +
		"registry and Sigstore (rekor.sigstore.dev, tuf-repo-cdn.sigstore.dev), or pin " + field +
		" by digest; `cloop hub doctor` reports what is missing."
}

func (c OwnImageCheck) subject() string {
	if s := strings.TrimSpace(c.Subject); s != "" {
		return s
	}
	return "this executor"
}

// parsedName is registry/repository of ref, or ref as written when it does not
// parse.
func parsedName(ref string) string {
	if parsed, err := ParseReference(strings.TrimSpace(ref)); err == nil {
		return parsed.Name()
	}
	return ref
}

// ── what the doctor reads ───────────────────────────────────────────────────

// ProvenanceRecord is one verdict as the process last reached it, for the
// doctor: where the image was checked, and what was found.
type ProvenanceRecord struct {
	Executor string `json:"executor"`
	Provenance
}

var recent = struct {
	sync.Mutex
	byKey map[string]ProvenanceRecord
}{byKey: map[string]ProvenanceRecord{}}

// RecordProvenance remembers the latest verdict for an image on an executor,
// so the hub's own doctor — Settings → Hub health — reports what dispatches
// found without running cosign itself.
func RecordProvenance(executorID string, p Provenance) {
	recent.Lock()
	defer recent.Unlock()
	if len(recent.byKey) >= 256 {
		recent.byKey = map[string]ProvenanceRecord{}
	}
	recent.byKey[executorID+"\x00"+p.Image] = ProvenanceRecord{Executor: executorID, Provenance: p}
}

// RecentProvenance returns the latest verdicts, newest first.
func RecentProvenance() []ProvenanceRecord {
	recent.Lock()
	out := make([]ProvenanceRecord, 0, len(recent.byKey))
	for _, r := range recent.byKey {
		out = append(out, r)
	}
	recent.Unlock()
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].CheckedAt.After(out[j-1].CheckedAt); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// ResetRecentProvenance forgets every recorded verdict. Tests use it.
func ResetRecentProvenance() {
	recent.Lock()
	recent.byKey = map[string]ProvenanceRecord{}
	recent.Unlock()
}

// CosignVersion reads the version of the cosign binary at path from the Go
// build information it carries — "v3.1.4" — without executing it. cosign is a
// Go program, and its release builds record their module version; a binary
// that records none, or is not a Go program, reports an error, and the doctor
// says the version is unknown rather than guessing.
func CosignVersion(path string) (string, error) {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("imagepolicy: read the build information of %s: %w", path, err)
	}
	if v := strings.TrimSpace(info.Main.Version); v != "" && v != "(devel)" {
		return v, nil
	}
	for _, s := range info.Settings {
		if s.Key == "-ldflags" {
			// A build from a checkout stamps the version through
			// sigs.k8s.io/release-utils instead of the module version.
			const key = "sigs.k8s.io/release-utils/version.gitVersion="
			if i := strings.Index(s.Value, key); i >= 0 {
				v := s.Value[i+len(key):]
				if j := strings.IndexAny(v, " '\""); j >= 0 {
					v = v[:j]
				}
				if v != "" {
					return v, nil
				}
			}
		}
	}
	return "", fmt.Errorf("imagepolicy: %s records no version in its build information", path)
}
