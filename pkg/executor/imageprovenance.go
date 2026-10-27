package executor

// imageprovenance.go is the hub-wide setting that decides what a dispatch does
// with one of cloop's own images that could not be verified (Task 20453):
// executors.image_provenance.
//
// The check itself is pkg/imagepolicy's OwnImageCheck, run by each driver that
// dispatches an image — the container and Kubernetes drivers, and the remote
// executor for a device or a virtual executor. A signature present and wrong
// refuses whatever this says. An image with no signature, or one nothing could
// check, is admitted with a warning on the run under "warn", the default, and
// refused under "required".
//
// Applied as a ratchet, like executors.isolation_evidence: a hub reads many
// projects' config.yaml, and one of them must not relax a hub that requires
// verified images.

import (
	"strings"
	"sync/atomic"
)

// Image provenance policies: executors.image_provenance.
const (
	// ImageProvenancePolicyWarn runs an unsigned or unverifiable image of
	// cloop's own with a warning on the run. The default.
	ImageProvenancePolicyWarn = "warn"
	// ImageProvenancePolicyRequired refuses it.
	ImageProvenancePolicyRequired = "required"
)

// ValidImageProvenancePolicy reports whether v is a policy this build knows;
// empty is the default.
func ValidImageProvenancePolicy(v string) bool {
	switch strings.TrimSpace(v) {
	case "", ImageProvenancePolicyWarn, ImageProvenancePolicyRequired:
		return true
	}
	return false
}

var imageProvenanceRequired atomic.Bool

// SetImageProvenanceRequired is the raw switch, returning the previous value.
// Bootstrap paths call ApplyImageProvenancePolicy instead.
func SetImageProvenanceRequired(v bool) bool { return imageProvenanceRequired.Swap(v) }

// ImageProvenanceRequired reports whether one of cloop's own images is refused
// unless its digest was verified.
func ImageProvenanceRequired() bool { return imageProvenanceRequired.Load() }

// ApplyImageProvenancePolicy installs a configured policy as a ratchet: it can
// make the hub stricter and never looser.
func ApplyImageProvenancePolicy(v string) {
	if strings.TrimSpace(v) == ImageProvenancePolicyRequired {
		imageProvenanceRequired.Store(true)
	}
}
