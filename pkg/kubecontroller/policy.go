package kubecontroller

// policy.go holds the refusals that depend on how this controller was started
// rather than on the spec alone (Task 20485), so neither the CRD nor
// ExecutorPoolSpec.Validate can state them: a runner image named by tag when
// the controller requires digests, and a runner that would run as the
// controller's own ServiceAccount. Either makes the pool Invalid, with the
// spec's own problems, and the controller starts nothing for it.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

// ServiceAccountRef names a ServiceAccount.
type ServiceAccountRef struct {
	Namespace string
	Name      string
}

// String is namespace/name.
func (r ServiceAccountRef) String() string { return r.Namespace + "/" + r.Name }

// serviceAccountSubject is the prefix of a ServiceAccount token's subject.
const serviceAccountSubject = "system:serviceaccount:"

// ServiceAccountFromToken reads which ServiceAccount a Kubernetes service
// account token was issued to, from its subject claim
// (system:serviceaccount:<namespace>:<name>). It verifies nothing: the
// controller reads its own token to learn which account no runner may run as,
// and a token it cannot read leaves that check off rather than guessing.
func ServiceAccountFromToken(token string) (ServiceAccountRef, bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 || len(parts[1]) > 64<<10 {
		return ServiceAccountRef{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return ServiceAccountRef{}, false
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ServiceAccountRef{}, false
	}
	rest, ok := strings.CutPrefix(claims.Sub, serviceAccountSubject)
	if !ok {
		return ServiceAccountRef{}, false
	}
	ns, name, ok := strings.Cut(rest, ":")
	if !ok || !dnsSubdomain.MatchString(ns) || !dnsSubdomain.MatchString(name) {
		return ServiceAccountRef{}, false
	}
	return ServiceAccountRef{Namespace: ns, Name: name}, true
}

// problems is everything that makes a (normalized) pool Invalid: its spec's
// own problems and this controller's refusals, sorted.
func (c *Controller) problems(pool *ExecutorPool) []string {
	out := append(pool.Spec.Validate(), c.policyProblems(pool)...)
	sort.Strings(out)
	return out
}

// policyProblems returns what this controller's own settings refuse in a
// pool, "field: what is wrong", in the form Validate uses.
func (c *Controller) policyProblems(pool *ExecutorPool) []string {
	var v validator
	t := pool.Spec.Template
	if c.opts.RequireImageDigest {
		// An empty image is cloop's harness image, and a named one of cloop's
		// own images is treated like it: the controller runs either by the
		// digest it resolved at the registry and verified against the
		// publishing workflow (image.go), never by the tag. Any other image
		// runs as written, so it must name its digest itself.
		if img := strings.TrimSpace(t.Image); img != "" && !imagepolicy.IsOwnImage(img) {
			if ref, err := imagepolicy.ParseReference(img); err == nil && !ref.Pinned() {
				v.add("spec.template.image", fmt.Sprintf("%q is not pinned by digest, and this controller "+
					"starts runners only from images that are (--require-image-digest): name it as "+
					"repository@sha256:…, or leave it empty for cloop's harness image, which the controller "+
					"resolves to a digest and verifies", img))
			}
		}
	}
	if own := c.opts.ServiceAccount; own != nil && own.Name != "" {
		// A Pod that names no account runs as the namespace's default.
		name := strings.TrimSpace(t.ServiceAccountName)
		if name == "" {
			name = "default"
		}
		if name == own.Name && pool.Metadata.Namespace == own.Namespace {
			v.add("spec.template.serviceAccountName", fmt.Sprintf("%q is the controller's own ServiceAccount, "+
				"whose authority reads the pool's credential; runners run model-authored code and never run "+
				"as it — name an account made for them", name))
		}
	}
	return v.problems
}
