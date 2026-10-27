package imagepolicy

// registrylabels.go reads an image's labels at its registry (Task 20450), for
// the hub that resolves a project's image there anyway: under
// require_signature it asks the registry which digest a tag names before it
// verifies the signature on it (registry.go). The labels are one step further
// along the same path — the manifest names a configuration blob, and the blob
// holds them — so the hub can tell whether the image carries the project's
// harness before anything is leased for a run that would fail inside it.
//
// Everything is fetched by digest once the first manifest is in hand, and
// every byte is checked against the digest it was fetched by: a label read
// from a blob that is not the one the manifest names would be a statement
// about some other image.

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// LabelResolver reads the labels of the image a reference names.
type LabelResolver interface {
	// Labels returns the image's labels: nil and no error for an image that
	// has none.
	Labels(ctx context.Context, ref string) (map[string]string, error)
}

// maxConfigBytes bounds an image configuration blob. A real one is a few
// kilobytes — its history and its labels; this is a ceiling against a
// registry streaming without end.
const maxConfigBytes = 4 << 20

// ociDescriptor is the part of an OCI or Docker descriptor this file reads.
type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform,omitempty"`
}

// ociManifest is an image index (a manifest list) or an image manifest: the
// first has Manifests, the second a Config.
type ociManifest struct {
	MediaType string          `json:"mediaType"`
	Manifests []ociDescriptor `json:"manifests"`
	Config    ociDescriptor   `json:"config"`
}

// Labels implements LabelResolver: the labels in the configuration of the
// image ref names. For a multi-platform index it reads the linux/amd64 image,
// or else the first Linux one: a multi-platform build labels every platform
// alike, and the hub has no platform of its own to prefer.
func (r *RegistryResolver) Labels(ctx context.Context, ref string) (map[string]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	parsed, err := ParseReference(ref)
	if err != nil {
		return nil, err
	}
	if parsed.Registry == "" {
		return nil, fmt.Errorf("%w: %q names no registry to ask", ErrRegistry, ref)
	}
	target := parsed.Digest
	if target == "" {
		target = parsed.Tag
		if target == "" {
			target = "latest"
		}
	}
	fetch := &registryFetch{r: r, ref: parsed}
	body, err := fetch.get(ctx, "/manifests/"+target, manifestAccept, maxManifestBytes, parsed.Digest)
	if err != nil {
		return nil, err
	}
	man, err := decodeManifest(parsed, body)
	if err != nil {
		return nil, err
	}
	if len(man.Manifests) > 0 {
		child := pickPlatform(man.Manifests)
		if child == "" {
			return nil, fmt.Errorf("%w: the index of %s lists no Linux image", ErrRegistry, ref)
		}
		if body, err = fetch.get(ctx, "/manifests/"+child, manifestAccept, maxManifestBytes, child); err != nil {
			return nil, err
		}
		if man, err = decodeManifest(parsed, body); err != nil {
			return nil, err
		}
	}
	if err := validateDigest(man.Config.Digest); err != nil {
		return nil, fmt.Errorf("%w: the manifest of %s names no usable configuration: %v", ErrRegistry, ref, err)
	}
	blob, err := fetch.get(ctx, "/blobs/"+man.Config.Digest, "*/*", maxConfigBytes, man.Config.Digest)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(blob, &cfg); err != nil {
		return nil, fmt.Errorf("%w: the configuration of %s is not JSON: %v", ErrRegistry, ref, err)
	}
	return cfg.Config.Labels, nil
}

// decodeManifest reads an index or an image manifest.
func decodeManifest(ref Reference, body []byte) (ociManifest, error) {
	var man ociManifest
	if err := json.Unmarshal(body, &man); err != nil {
		return ociManifest{}, fmt.Errorf("%w: %s served a manifest for %s that is not JSON: %v",
			ErrRegistry, ref.Registry, ref.String(), err)
	}
	return man, nil
}

// pickPlatform chooses the image of an index whose labels stand for all of
// them: linux/amd64, else the first Linux image. Attestations, which BuildKit
// lists with platform unknown/unknown, are never chosen.
func pickPlatform(entries []ociDescriptor) string {
	first := ""
	for _, d := range entries {
		if d.Platform == nil || !strings.EqualFold(d.Platform.OS, "linux") || validateDigest(d.Digest) != nil {
			continue
		}
		if strings.EqualFold(d.Platform.Architecture, "amd64") {
			return d.Digest
		}
		if first == "" {
			first = d.Digest
		}
	}
	return first
}

// contentDigest is the digest of body in the algorithm want names.
func contentDigest(body []byte, want string) string {
	if strings.HasPrefix(strings.ToLower(want), "sha512:") {
		sum := sha512.Sum512(body)
		return "sha512:" + hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// registryFetch is one conversation with a registry about one repository: it
// authenticates on the first 401 and spends the result on every request after.
type registryFetch struct {
	r    *RegistryResolver
	ref  Reference
	auth string
	// authorized reports that a 401 has been answered once already, so a
	// second one is a refusal rather than a prompt to log in.
	authorized bool
}

// get fetches path below the repository and checks it against digest, when it
// names one. limit bounds the body.
func (f *registryFetch) get(ctx context.Context, path, accept string, limit int64, digest string) ([]byte, error) {
	target := f.r.endpoint(f.ref.Registry) + "/v2/" + f.ref.Repository + path
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRegistry, err)
		}
		req.Header.Set("Accept", accept)
		if f.auth != "" {
			req.Header.Set("Authorization", f.auth)
		}
		// A blob is commonly answered with a redirect to a storage host. The
		// client follows it and, the host being another, sends no
		// Authorization there: the redirect itself is the grant.
		resp, err := f.r.client().Do(req)
		if err != nil {
			return nil, fmt.Errorf("%w: %s is unreachable from this host: %v", ErrRegistry, f.ref.Registry, err)
		}
		switch {
		case resp.StatusCode == http.StatusUnauthorized && !f.authorized:
			challenges := resp.Header.Values("Www-Authenticate")
			drain(resp)
			if f.auth, err = f.r.authorize(ctx, f.ref, target, challenges); err != nil {
				return nil, err
			}
			f.authorized = true
			continue
		case resp.StatusCode != http.StatusOK:
			drain(resp)
			return nil, fmt.Errorf("%w: %s answered HTTP %d for %s of %s", ErrRegistry, f.ref.Registry,
				resp.StatusCode, path, f.ref.Name())
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("%w: reading %s of %s: %v", ErrRegistry, path, f.ref.Name(), err)
		}
		if int64(len(body)) > limit {
			return nil, fmt.Errorf("%w: %s served more than %d bytes for %s of %s", ErrRegistry,
				f.ref.Registry, limit, path, f.ref.Name())
		}
		if digest != "" {
			if got := contentDigest(body, digest); !strings.EqualFold(got, digest) {
				return nil, fmt.Errorf("%w: %s served %s for %s of %s, whose digest is %s", ErrRegistry,
					f.ref.Registry, got, path, f.ref.Name(), digest)
			}
		}
		return body, nil
	}
	return nil, fmt.Errorf("%w: %s refused this host access to %s%s", ErrRegistry, f.ref.Registry,
		f.ref.Name(), f.r.loginHint(f.ref.Registry))
}
