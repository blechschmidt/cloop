package container

// provenance_test.go: the container driver's check of cloop's own images (Task
// 20453), against a stand-in runtime whose store holds what each test needs and
// a stand-in verifier that answers what cosign would.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
	"github.com/blechschmidt/cloop/pkg/provenance"
)

const ownDigest = "sha256:" + "3ad7a636d68631752784810d823b827a1747022840f3c8877af15decc831b213"

// pinnedDefault is the default image by the digest the stand-in store holds.
var pinnedDefault = "ghcr.io/blechschmidt/cloop-harness@" + ownDigest

// storeRuntime is a runtime CLI whose store holds the given references, each
// with the repo digests `{{json .RepoDigests}}` would print, and which logs
// every call. Anything else is not present.
func storeRuntime(t *testing.T, images map[string]string) (Runtime, string) {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh for the fake runtime")
	}
	dir := t.TempDir()
	calls, store := filepath.Join(dir, "calls"), filepath.Join(dir, "store")
	var b strings.Builder
	for ref, digests := range images {
		b.WriteString(ref + "\t" + digests + "\n")
	}
	if err := os.WriteFile(store, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
echo "$@" >> '` + calls + `'
if [ "$1" = image ] && [ "$2" = inspect ]; then
  ref=; for a in "$@"; do ref=$a; done
  line=$(awk -F '\t' -v r="$ref" '$1 == r { print $2; exit }' '` + store + `')
  [ -n "$line" ] || { echo "Error: No such image: $ref" >&2; exit 1; }
  printf '%s\037sha256:` + strings.Repeat("cd", 32) + `\037{}\n' "$line"
  exit 0
fi
exit 0
`
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return Runtime{Name: RuntimeDocker, Path: path}, calls
}

// defaultStore holds the default image under its tag and its digest, as a
// pull of the tag leaves it.
func defaultStore() map[string]string {
	return map[string]string{
		DefaultImage:  `["` + pinnedDefault + `"]`,
		pinnedDefault: `["` + pinnedDefault + `"]`,
	}
}

// standInVerifier answers one verdict for every digest and counts the asks.
type standInVerifier struct {
	verdict imagepolicy.ProvenanceVerdict
	asked   atomic.Int32
	last    atomic.Value
}

func (v *standInVerifier) VerifyProvenance(_ context.Context, ref string) imagepolicy.ProvenanceVerdict {
	v.asked.Add(1)
	v.last.Store(ref)
	return v.verdict
}

func (v *standInVerifier) TrustRoot() (string, string) {
	return provenance.DefaultIssuer, provenance.ImagesIdentityRegexp
}

func verdict(s imagepolicy.ProvenanceStatus, detail string) *standInVerifier {
	return &standInVerifier{verdict: imagepolicy.ProvenanceVerdict{Status: s, Detail: detail}}
}

// provenanceExecutor is a hub's container driver — VerifyOwnImages set — over
// the given store, verifier and options.
func provenanceExecutor(t *testing.T, images map[string]string, v imagepolicy.ProvenanceVerifier,
	mutate func(*Options)) (*Executor, string) {
	t.Helper()
	opts := Options{VerifyOwnImages: true}
	if mutate != nil {
		mutate(&opts)
	}
	ex := fakeExecutor(t, opts)
	rt, calls := storeRuntime(t, images)
	ex.rt, ex.provenance = rt, v
	t.Cleanup(imagepolicy.ResetRecentProvenance)
	return ex, calls
}

// requireMode sets executors.image_provenance for one test.
func requireMode(t *testing.T, required bool) {
	t.Helper()
	prev := executor.SetImageProvenanceRequired(required)
	t.Cleanup(func() { executor.SetImageProvenanceRequired(prev) })
}

// TestTheDefaultImageRunsAsTheDigestCosignVerified: the default image's digest
// comes from the store, is what is verified, and is what the workload runs;
// the verdict rides the identity onto the handle. A project naming the same
// image gets the same check.
func TestTheDefaultImageRunsAsTheDigestCosignVerified(t *testing.T) {
	for _, required := range []bool{false, true} {
		requireMode(t, required)
		v := verdict(imagepolicy.ProvenanceVerified, "ok")
		ex, _ := provenanceExecutor(t, defaultStore(), v, nil)
		for name, spec := range map[string]executor.Spec{
			"the default":        {},
			"named by a project": {Image: DefaultImage},
		} {
			id, err := ex.sandboxImage(context.Background(), spec)
			if err != nil {
				t.Fatalf("required=%t, %s: %v", required, name, err)
			}
			if id.Pinned() != pinnedDefault {
				t.Errorf("required=%t, %s: runs %q, want the verified digest %q", required, name, id.Pinned(), pinnedDefault)
			}
			if !id.Provenance.Verified() || id.Provenance.Digest != ownDigest || id.Provenance.Warning != "" {
				t.Errorf("required=%t, %s: provenance = %+v", required, name, id.Provenance)
			}
			if got, _ := v.last.Load().(string); got != pinnedDefault {
				t.Errorf("cosign was asked about %q, want the digest %q", got, pinnedDefault)
			}
		}
	}
	if recs := imagepolicy.RecentProvenance(); len(recs) == 0 || recs[0].Executor != DefaultID {
		t.Errorf("the verdict was not recorded for the doctor: %+v", recs)
	}
}

// TestAWrongSignatureRefusesTheStartInEveryMode: present and wrong is never a
// warning, and nothing runs.
func TestAWrongSignatureRefusesTheStartInEveryMode(t *testing.T) {
	for _, required := range []bool{false, true} {
		requireMode(t, required)
		ex, calls := provenanceExecutor(t, defaultStore(),
			verdict(imagepolicy.ProvenanceMismatch, "no matching CertificateIdentity found"), nil)
		_, err := ex.sandboxImage(context.Background(), executor.Spec{})
		var denied *imagepolicy.DenyError
		if !errors.As(err, &denied) || denied.Rule != imagepolicy.RuleProvenance {
			t.Fatalf("required=%t: sandboxImage = %v, want a %s refusal", required, err, imagepolicy.RuleProvenance)
		}
		if errors.Is(err, executor.ErrInvalidSpec) {
			t.Error("a wrong signature was reported as a malformed spec")
		}
		if log, _ := os.ReadFile(calls); strings.Contains(string(log), " run") || strings.Contains(string(log), "build") {
			t.Errorf("the runtime was asked to do more than inspect:\n%s", log)
		}
	}
}

// TestAnUnsignedImageWarnsOrIsRefused: an image pulled before signing began
// runs — by its digest — with a warning by default, and is refused when
// executors.image_provenance is required. So is one nothing can check.
func TestAnUnsignedImageWarnsOrIsRefused(t *testing.T) {
	for name, v := range map[string]*standInVerifier{
		"unsigned":       verdict(imagepolicy.ProvenanceUnsigned, "Error: no signatures found"),
		"no cosign here": verdict(imagepolicy.ProvenanceUnverifiable, "imagepolicy: cosign is not installed"),
	} {
		t.Run(name, func(t *testing.T) {
			requireMode(t, false)
			ex, _ := provenanceExecutor(t, defaultStore(), v, nil)
			id, err := ex.sandboxImage(context.Background(), executor.Spec{})
			if err != nil {
				t.Fatalf("warn: %v", err)
			}
			if id.Pinned() != pinnedDefault || id.Provenance == nil || id.Provenance.Verified() ||
				!strings.Contains(id.Provenance.Warning, v.verdict.Detail) {
				t.Errorf("warn: runs %q with provenance %+v, want the store's digest and a warning", id.Pinned(), id.Provenance)
			}
			if provenanceWarning(id.Provenance) == "" {
				t.Error("the run's log would carry no warning")
			}

			requireMode(t, true)
			_, err = ex.sandboxImage(context.Background(), executor.Spec{})
			var denied *imagepolicy.DenyError
			if !errors.As(err, &denied) || denied.Rule != imagepolicy.RuleProvenance ||
				!strings.Contains(denied.Reason, "required") {
				t.Fatalf("required: sandboxImage = %v, want a refusal naming the setting", err)
			}
		})
	}
}

// TestALocallyBuiltImageUnderCloopsNameIsNotVerified: a stand-in built and
// tagged as the default — what the test rigs do — has no registry digest, so
// there is nothing to verify: it runs by its tag with a warning, or is refused.
func TestALocallyBuiltImageUnderCloopsNameIsNotVerified(t *testing.T) {
	requireMode(t, false)
	v := verdict(imagepolicy.ProvenanceVerified, "ok")
	ex, _ := provenanceExecutor(t, map[string]string{DefaultImage: "null"}, v, nil)
	id, err := ex.sandboxImage(context.Background(), executor.Spec{})
	if err != nil {
		t.Fatalf("warn: %v", err)
	}
	if id.Provenance.Status != imagepolicy.ProvenanceUnverifiable || !strings.Contains(id.Provenance.Detail, "built locally") ||
		v.asked.Load() != 0 {
		t.Errorf("provenance = %+v after %d verifications", id.Provenance, v.asked.Load())
	}
	requireMode(t, true)
	if _, err := ex.sandboxImage(context.Background(), executor.Spec{}); !errors.Is(err, imagepolicy.ErrDenied) {
		t.Fatalf("required: %v, want a refusal", err)
	}
}

// TestAMissingImageStillNamesThePull: "not present locally" is the store's
// diagnosis, passed through rather than turned into a provenance verdict.
func TestAMissingImageStillNamesThePull(t *testing.T) {
	requireMode(t, true)
	ex, _ := provenanceExecutor(t, map[string]string{}, verdict(imagepolicy.ProvenanceVerified, "ok"), nil)
	_, err := ex.sandboxImage(context.Background(), executor.Spec{})
	if err == nil || errors.Is(err, imagepolicy.ErrDenied) || !strings.Contains(err.Error(), "pull "+DefaultImage) {
		t.Fatalf("sandboxImage = %v, want the pull diagnostic", err)
	}
}

// TestAnOperatorImageIsLeftAloneUnlessGoverned: an operator's image that is not
// cloop's is not checked against cloop's pin, and not against the project rules
// either — until govern_operator_images asks for them.
func TestAnOperatorImageIsLeftAloneUnlessGoverned(t *testing.T) {
	requireMode(t, true)
	const operator = "ghcr.io/acme/base:1"
	store := map[string]string{operator: `["ghcr.io/acme/base@` + ownDigest + `"]`,
		"ghcr.io/acme/base@" + ownDigest: `["ghcr.io/acme/base@` + ownDigest + `"]`}
	v := verdict(imagepolicy.ProvenanceMismatch, "never asked")
	policy := imagepolicy.Policy{AllowedRegistries: []string{"quay.io"}, RequireDigest: true}

	ex, _ := provenanceExecutor(t, store, v, func(o *Options) { o.Image, o.ImagePolicy = operator, policy })
	id, err := ex.sandboxImage(context.Background(), executor.Spec{})
	if err != nil || id.Provenance != nil || v.asked.Load() != 0 {
		t.Fatalf("the operator's own image = %+v, %v after %d verifications; want it run as configured",
			id, err, v.asked.Load())
	}

	policy.GovernOperatorImages = true
	ex, _ = provenanceExecutor(t, store, v, func(o *Options) { o.Image, o.ImagePolicy = operator, policy })
	_, err = ex.sandboxImage(context.Background(), executor.Spec{})
	var denied *imagepolicy.DenyError
	if !errors.As(err, &denied) || denied.Rule != imagepolicy.RuleRegistry {
		t.Fatalf("governed: sandboxImage = %v, want the registry allowlist's refusal", err)
	}

	// Governed and admitted: pinned, as a project's image would be.
	ex, _ = provenanceExecutor(t, store, v, func(o *Options) {
		o.Image = operator
		o.ImagePolicy = imagepolicy.Policy{AllowedRegistries: []string{"ghcr.io"}, GovernOperatorImages: true}
	})
	id, err = ex.sandboxImage(context.Background(), executor.Spec{})
	if err != nil || id.Pinned() != "ghcr.io/acme/base@"+ownDigest || v.asked.Load() != 0 {
		t.Fatalf("governed and admitted: %+v, %v", id, err)
	}
}

// TestCloopsOwnImageIsNotGovernedByTheProjectRules: govern_operator_images
// reaches only the operator images that are not cloop's own; those have their
// own pin, and a policy that names no ghcr.io must not refuse the default.
func TestCloopsOwnImageIsNotGovernedByTheProjectRules(t *testing.T) {
	requireMode(t, false)
	ex, _ := provenanceExecutor(t, defaultStore(), verdict(imagepolicy.ProvenanceVerified, "ok"), func(o *Options) {
		o.ImagePolicy = imagepolicy.Policy{AllowedRegistries: []string{"quay.io"}, GovernOperatorImages: true}
	})
	id, err := ex.sandboxImage(context.Background(), executor.Spec{})
	if err != nil || !id.Provenance.Verified() {
		t.Fatalf("the default under a governing policy = %+v, %v", id, err)
	}
}

// TestADevicesDriverChecksNothingItself: a device's agent builds its driver
// without VerifyOwnImages — the hub verified what it dispatched — so the
// device asks no verifier and records no verdict.
func TestADevicesDriverChecksNothingItself(t *testing.T) {
	requireMode(t, true)
	v := verdict(imagepolicy.ProvenanceMismatch, "never asked")
	ex, _ := provenanceExecutor(t, defaultStore(), v, func(o *Options) { o.VerifyOwnImages = false })
	id, err := ex.sandboxImage(context.Background(), executor.Spec{Image: pinnedDefault})
	if err != nil || id.Provenance != nil || v.asked.Load() != 0 {
		t.Fatalf("a device's driver = %+v, %v after %d verifications", id, err, v.asked.Load())
	}
}

// TestResolveDigestPrefersTheImagesOwnRepository: an image held under two
// repositories lists a digest for each, and the one a signature on cloop's
// repository is over is the one for that repository.
func TestResolveDigestPrefersTheImagesOwnRepository(t *testing.T) {
	ex, _ := provenanceExecutor(t, map[string]string{
		DefaultImage: `["registry.example/mirror/cloop-harness@sha256:` + strings.Repeat("ab", 32) + `","` + pinnedDefault + `"]`,
	}, nil, nil)
	got, err := ex.ResolveDigest(context.Background(), DefaultImage)
	if err != nil || got != ownDigest {
		t.Fatalf("ResolveDigest = %q, %v; want %s", got, err, ownDigest)
	}
}
