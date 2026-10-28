package hubdoctor

// The images.provenance check (Task 20453): whether this hub can verify the
// images it runs that are cloop's own, and what it found when it did.
//
// cloop's published images — ghcr.io/blechschmidt/cloop, cloop-harness and
// cloop-harness-copilot — are signed by the workflow that publishes them, and a
// hub verifies one before a sandbox runs it, whoever chose it: the default, an
// executor configured with it, a device's sandbox image, a project. A signature
// present and wrong refuses the dispatch. An unsigned image — every image
// published before signing began — and a hub without cosign are a warning by
// default, so an upgrade never stops a working hub, and this check is where the
// warning is said before a run says it: with executors.image_provenance:
// required both become refusals.
//
// The verdicts come from the verifications this process made. The hub's own
// diagnosis — Settings → Hub health — reads what its dispatches found and runs
// nothing: no cosign, no registry request, no image inspect, which the request
// path must not reach (tests/security). `cloop hub doctor` verifies the images
// in use first, through the drivers it reconciled and at the registry for a
// device, so its report says what the next run would find. cosign's version is
// read from its build information either way, without executing it.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/version"
)

// minCosignForBundles is the oldest cosign known to read the Sigstore bundle
// format cloop's images are signed in — measured against v2.6.3 and v3.1.4.
const minCosignForBundles = "v2.6.0"

// ownImageUse is one of cloop's own images an executor here is configured to
// run: the container or Kubernetes driver's image, or a device's or a virtual
// executor's sandbox image.
type ownImageUse struct {
	executor string
	kind     string
	field    string
	image    string
}

// ownImagesInUse lists the images of cloop's own the configuration and the
// fleet run when no project names one. Devices are read from the hub's
// database, like imageDevices; a database that cannot be read lists none of
// them, and the check says the fleet is unknown rather than clean.
func ownImagesInUse(dir string, cfg *config.Config) (uses []ownImageUse, fleetKnown bool) {
	if cfg.Executors.Container.Enabled {
		image := strings.TrimSpace(cfg.Executors.Container.Image)
		if image == "" {
			image = executor.DefaultHarnessImage
		}
		if imagepolicy.IsOwnImage(image) {
			uses = append(uses, ownImageUse{executor: containerID(cfg), kind: executor.KindContainer,
				field: "executors.container.image", image: image})
		}
	}
	if cfg.Executors.Kubernetes.Enabled {
		image := strings.TrimSpace(cfg.Executors.Kubernetes.Image)
		if image == "" {
			image = executor.DefaultHarnessImage
		}
		if imagepolicy.IsOwnImage(image) {
			uses = append(uses, ownImageUse{executor: kubernetesID(cfg), kind: executor.KindKubernetes,
				field: "executors.kubernetes.image", image: image})
		}
	}
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		// No database: no device has ever enrolled here.
		return uses, true
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return uses, false
	}
	defer func() { _ = db.Close() }()
	rows, err := db.ListExecutors()
	if err != nil {
		return uses, false
	}
	for _, row := range rows {
		if row.Kind != executor.KindRemoteAgent && row.Kind != executor.KindVirtual {
			continue
		}
		settings, err := statedb.SandboxSettingsFor(db, row.ID)
		if err != nil {
			return uses, false
		}
		settings = settings.Normalize()
		if !settings.RunsProjectImages() {
			continue
		}
		image, field := strings.TrimSpace(settings.Image), "the sandbox image of "+row.Name
		if image == "" {
			image, field = executor.DefaultHarnessImage, field+" (unset, so the default)"
		}
		if imagepolicy.IsOwnImage(image) {
			uses = append(uses, ownImageUse{executor: row.ID, kind: row.Kind, field: field, image: image})
		}
	}
	return uses, true
}

// verifyOwnImagesNow is `cloop hub doctor`'s half: it verifies each image of
// cloop's own in use, as the next dispatch would, and records the verdicts the
// check then reports. The hub's own diagnosis never calls it.
func verifyOwnImagesNow(ctx context.Context, dir string, cfg *config.Config, opts Options) {
	if opts.Offline {
		return
	}
	uses, _ := ownImagesInUse(dir, cfg)
	for _, use := range uses {
		switch use.kind {
		case executor.KindContainer, executor.KindKubernetes:
			// Through the driver reconciliation registered: the container
			// driver resolves the digest in its own image store.
			ex, err := executor.DefaultRegistry.Get(use.executor)
			if err != nil {
				continue
			}
			if v, ok := ex.(interface {
				VerifyOwnImage(context.Context) (*imagepolicy.Provenance, error)
			}); ok {
				_, _ = v.VerifyOwnImage(ctx)
			}
		default:
			// A device's store is the device's, so the registry is asked, as
			// the hub asks it before a dispatch.
			p, _ := imagepolicy.OwnImageCheck{
				Image:    use.image,
				Resolver: imagepolicy.NewRegistryResolver(),
				Verifier: imagepolicy.SharedProvenanceVerifier(),
				Required: provenanceRequired(cfg),
				Subject:  use.executor,
				Field:    use.field,
			}.Run(ctx)
			if p.Status != "" {
				imagepolicy.RecordProvenance(use.executor, p)
			}
		}
	}
}

// provenanceRequired reports whether unverified images of cloop's own are
// refused: what the configuration says, or what this process enforces.
func provenanceRequired(cfg *config.Config) bool {
	return strings.TrimSpace(cfg.Executors.ImageProvenance) == executor.ImageProvenancePolicyRequired ||
		executor.ImageProvenanceRequired()
}

func checkImageProvenance(dir string, cfg *config.Config, opts Options, add addFn) {
	const check, title = "images.provenance", "Image provenance"
	required := provenanceRequired(cfg)
	mode := executor.ImageProvenancePolicyWarn
	if required {
		mode = executor.ImageProvenancePolicyRequired
	}
	uses, fleetKnown := ownImagesInUse(dir, cfg)
	recorded := imagepolicy.RecentProvenance()
	inUse := len(uses) > 0 || len(recorded) > 0
	unverifiedSeverity := SeverityWarn
	if required {
		unverifiedSeverity = SeverityFail
	}

	// --- cosign ------------------------------------------------------------
	look := opts.LookPath
	if look == nil {
		look = exec.LookPath
	}
	details := map[string]any{"image_provenance": mode}
	if path, err := look(imagepolicy.CosignBinary); err != nil {
		f := Finding{Check: check, Title: title, Severity: SeverityPass, Details: details,
			Message: "cosign is not on this host's PATH; no executor here is configured to run one of cloop's " +
				"own images, so nothing needs it yet — a project naming one runs it unverified, with a warning"}
		if required {
			f.Message = "cosign is not on this host's PATH; executors.image_provenance is required, so a " +
				"project naming one of cloop's own images is refused"
		}
		if inUse {
			f.Severity = unverifiedSeverity
			f.Message = "cosign is not on this host's PATH, so cloop's own images run unverified, with a " +
				"warning on every run"
			if required {
				f.Message = "cosign is not on this host's PATH and executors.image_provenance is required, so " +
					"every dispatch of one of cloop's own images is refused"
			}
		}
		f.Remediation = "Install cosign on the hub — the published hub image bundles it " +
			"(https://docs.sigstore.dev/cosign/system_config/installation/)"
		add(f)
	} else {
		details["cosign"] = path
		v, verr := imagepolicy.CosignVersion(path)
		switch {
		case verr != nil:
			add(Finding{Check: check, Title: title, Severity: SeverityPass, Details: details,
				Message: fmt.Sprintf("cosign at %s verifies cloop's own images before they run (its build "+
					"records no version: %v)", path, verr)})
		default:
			details["cosign_version"] = v
			f := Finding{Check: check, Title: title, Severity: SeverityPass, Details: details,
				Message: fmt.Sprintf("cosign %s at %s verifies cloop's own images before they run; "+
					"executors.image_provenance is %s", v, path, mode)}
			if cmp, ok := version.Compare(v, minCosignForBundles); ok && cmp < 0 {
				f.Severity = SeverityWarn
				f.Message = fmt.Sprintf("cosign %s at %s is older than %s, the oldest known to read the Sigstore "+
					"bundles cloop's images are signed in; a signed image may be reported unsigned", v, path,
					minCosignForBundles)
				f.Remediation = "Install cosign v3.1.4, the version the published hub image bundles"
			}
			add(f)
		}
	}
	if !fleetKnown {
		add(Finding{Check: check, Title: title, Severity: SeverityWarn,
			Message: "the hub's database could not be read, so which devices run one of cloop's own images is " +
				"not known", Remediation: "Run `cloop hub doctor` where the hub's .cloop/state.db is readable"})
	}

	// --- the images ----------------------------------------------------------
	latest := map[string]imagepolicy.ProvenanceRecord{}
	for _, r := range recorded {
		k := r.Executor + "\x00" + r.Image
		if _, seen := latest[k]; !seen {
			latest[k] = r
		}
	}
	reported := map[string]bool{}
	for _, use := range uses {
		k := use.executor + "\x00" + use.image
		reported[k] = true
		if r, ok := latest[k]; ok {
			add(provenanceFinding(r, use.field, unverifiedSeverity))
			continue
		}
		msg := fmt.Sprintf("%s on %s is %s, one of cloop's own; no dispatch from this process has checked it "+
			"yet, and the first one will", use.field, use.executor, use.image)
		if opts.Offline {
			msg = fmt.Sprintf("%s on %s is %s, one of cloop's own; not checked: --offline was passed",
				use.field, use.executor, use.image)
		}
		add(Finding{Check: check, Title: title, Severity: SeverityPass, Message: msg,
			Details: map[string]any{"executor": use.executor, "image": use.image}})
	}
	// What dispatches found for images the configuration does not name —
	// one a project's sandbox.yaml named, an executor since reconfigured.
	keys := make([]string, 0, len(latest))
	for k := range latest {
		if !reported[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		r := latest[k]
		add(provenanceFinding(r, "the image a project named", unverifiedSeverity))
	}
}

// provenanceFinding reports one recorded verdict.
//
// Every executor resolves a tag of cloop's own images to the digest it checks —
// from its own store, or at the registry for a device and, since Task 20457, a
// Kubernetes Pod — so the remedy for one that was not verified is the same
// everywhere.
func provenanceFinding(r imagepolicy.ProvenanceRecord, field string, unverified Severity) Finding {
	f := Finding{Check: "images.provenance", Title: "Image provenance",
		Details: map[string]any{"executor": r.Executor, "image": r.Image, "ref": r.Ref, "status": string(r.Status),
			"identity": r.Identity, "checked_at": r.CheckedAt}}
	if r.Digest != "" {
		f.Details["digest"] = r.Digest
	}
	// Any resolver: the remedy differs only for an executor that has none.
	check := imagepolicy.OwnImageCheck{Image: r.Image, Field: field, Resolver: imagepolicy.NewRegistryResolver()}
	switch r.Status {
	case imagepolicy.ProvenanceVerified:
		f.Severity = SeverityPass
		f.Message = fmt.Sprintf("%s on %s runs as %s, verified against the workflow that publishes cloop's images",
			r.Image, r.Executor, r.Ref)
	case imagepolicy.ProvenanceMismatch:
		f.Severity = SeverityFail
		f.Message = fmt.Sprintf("%s on %s resolved to %s, whose signature is not from the workflow that publishes "+
			"cloop's images, so every dispatch of it is refused: %s", r.Image, r.Executor, r.Ref, r.Detail)
		f.Remediation = "Do not run it. Pull the image again from its registry and compare the digest with the " +
			"one the release names; if the registry serves this one, report it"
	default:
		f.Severity = unverified
		what := "carries no signature"
		if r.Status == imagepolicy.ProvenanceUnverifiable {
			what = "could not be verified"
		}
		f.Message = fmt.Sprintf("%s on %s %s (%s)%s", r.Image, r.Executor, what, r.Detail,
			refusedSuffix(unverified == SeverityFail))
		f.Remediation = strings.TrimSuffix(check.Remedy(r.Status), ".")
	}
	return f
}

// refusedSuffix ends an unverified image's message with what happens to it.
func refusedSuffix(required bool) string {
	if required {
		return "; executors.image_provenance is required, so its dispatch is refused"
	}
	return "; it runs with a warning on the run"
}

// containerID and kubernetesID are the IDs the configured drivers register
// under, as their option normalisation chooses them.
func containerID(cfg *config.Config) string {
	if opts, err := cfg.Executors.Container.DriverOptions(); err == nil {
		return opts.ID
	}
	return fallbackID(cfg.Executors.Container.ID, "container")
}

func kubernetesID(cfg *config.Config) string {
	if opts, err := cfg.Executors.Kubernetes.DriverOptions(); err == nil {
		return opts.ID
	}
	return fallbackID(cfg.Executors.Kubernetes.ID, "kubernetes")
}

func fallbackID(id, def string) string {
	if id = strings.TrimSpace(id); id != "" {
		return id
	}
	return def
}
