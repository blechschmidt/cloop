package container

// build.go implements the two image operations a per-project sandbox needs:
// pinning a reference to a digest, and baking a project's `setup:` commands
// into a derived image.
//
// # Why pin
//
// `image: python:3.12` names a moving target. The tag is repointed on every
// patch release, so the same task, the same commit and the same sandbox.yaml
// produce a different environment depending on when they ran — and the run that
// worked in March is not reproducible in June. Resolving the tag once and
// running the digest makes the task artifact a record of what actually
// executed rather than of what was asked for.
//
// # Why build here rather than expect a pre-built image
//
// The alternative to `setup:` is telling every project to publish its own image
// to a registry the hub can pull from, which means a registry, credentials, and
// a CI pipeline before a repo can pin `pip install -r requirements.txt`. The
// build is content-addressed and therefore happens once per unique (base,
// setup) pair; steady state is an `image inspect` that hits the local store.
//
// The build inherits the run's network posture rather than the daemon's
// default. That is load-bearing: `setup:` is repo-controlled, and a build with
// unconditional egress would be a way for a pull request to reach the network
// from inside a deployment whose whole configuration says it may not.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

// DerivedImagePrefix is the repository derived sandbox images are tagged under.
// "localhost/" keeps podman from treating the name as a Docker Hub reference
// and trying to pull it.
const DerivedImagePrefix = "localhost/cloop-sandbox"

// LabelDerivedFrom and LabelSetupHash are stamped onto derived images so an
// operator running `podman images --filter label=...` can tell what a
// cloop-sandbox tag was built from, and `podman image prune` decisions are
// informed rather than guessed.
const (
	LabelDerivedFrom = "io.cloop.sandbox.base"
	LabelSetupHash   = "io.cloop.sandbox.setup"
)

// buildTimeout bounds a derived-image build. Dependency installs are genuinely
// slow — a cold `pip install` on a large requirements file is minutes — so the
// bound is generous, but it must exist: a `setup:` command that reads stdin or
// waits on a lock would otherwise hang the build forever, and with it whichever
// caller triggered the first run of that sandbox.
const buildTimeout = 30 * time.Minute

// imageInspectTimeout bounds the digest lookups, which are local store reads.
const imageInspectTimeout = 30 * time.Second

// ImageIdentity is what a reference resolved to locally.
type ImageIdentity struct {
	// Ref is the reference as requested.
	Ref string
	// RepoDigest is the registry-reproducible "repo@sha256:..." form, empty
	// when the image has none — true for locally-built images, and for images
	// loaded from a tarball.
	RepoDigest string
	// ID is the local content ID ("sha256:..."), always present for an image
	// that exists locally.
	ID string
}

// Pinned returns the strongest reference that still resolves to this exact
// image: the repo digest when there is one, otherwise the reference as given.
//
// It deliberately does not fall back to the bare image ID. Running by ID works,
// but it produces a container whose image field is a hash with no repository,
// which makes every downstream artifact — logs, `podman ps`, the run record —
// unable to say what was executed. A tag that could move is a worse pin but a
// better record, and the artifact stores the ID alongside it either way.
func (i ImageIdentity) Pinned() string {
	if i.RepoDigest != "" {
		return i.RepoDigest
	}
	return i.Ref
}

// InspectImage resolves ref against the local image store.
//
// A missing image is an error naming the pull command, because the driver never
// pulls implicitly: an implicit pull turns a cold start into an unbounded
// network wait inside an HTTP handler, and turns a typo'd sandbox.yaml into a
// registry request from the hub.
func InspectImage(ctx context.Context, rt Runtime, ref string) (ImageIdentity, error) {
	if err := ValidateImageRef(ref); err != nil {
		return ImageIdentity{}, err
	}
	// Both runtimes expose .RepoDigests and .Id on `image inspect`; unlike the
	// `info` schema, this part of the API is common to them. The separator
	// keeps the two values apart without needing a JSON decode.
	const format = "{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}\x1f{{.Id}}"
	res, err := runCLITimeout(ctx, rt, imageInspectTimeout, "image", "inspect", "--format", format, "--", ref)
	if err != nil {
		return ImageIdentity{}, fmt.Errorf("container: inspect image %s: %w", ref, err)
	}
	if res.ExitCode != 0 {
		return ImageIdentity{}, fmt.Errorf(
			"container: image %s is not present locally (fix: %s pull %s): %s",
			ref, rt.Name, ref, firstLine(res.Stderr))
	}
	parts := strings.SplitN(strings.TrimSpace(res.Stdout), "\x1f", 2)
	id := ImageIdentity{Ref: ref, RepoDigest: strings.TrimSpace(parts[0])}
	if len(parts) == 2 {
		id.ID = normalizeImageID(strings.TrimSpace(parts[1]))
	}
	return id, nil
}

// normalizeImageID puts a content ID in the algorithm-prefixed form.
//
// The two runtimes disagree: `docker image inspect --format {{.Id}}` yields
// "sha256:bf85…" and podman yields a bare "bf85…". Both are accepted as
// references by their own runtime, so the difference is invisible until
// something downstream tries to *read* the value — SandboxRecord.Pinned()
// looking for a digest, an operator diffing two artifacts — and then the same
// image looks like two different ones depending on which runtime ran it.
func normalizeImageID(id string) string {
	if id == "" || strings.Contains(id, ":") {
		return id
	}
	return "sha256:" + id
}

// ResolveImage implements executor.ImageResolver: it returns ref pinned to a
// digest where one is available.
func (e *Executor) ResolveImage(ctx context.Context, ref string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(ref) == "" {
		ref = e.opts.Image
	}
	id, err := InspectImage(ctx, e.rt, ref)
	if err != nil {
		return "", err
	}
	return id.Pinned(), nil
}

// ResolveDigest implements imagepolicy.Resolver against the local image store.
//
// It reports imagepolicy.ErrNoDigest rather than an error when the image is
// present but carries no repo digest, which is the case for anything built
// locally or loaded from a tarball. The two outcomes need opposite handling —
// one means "nothing to pin to", the other means "the image is not here" — and
// collapsing them would make a missing image look like an unsigned one.
func (e *Executor) ResolveDigest(ctx context.Context, ref string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	id, err := InspectImage(ctx, e.rt, ref)
	if err != nil {
		return "", err
	}
	_, digest, ok := strings.Cut(id.RepoDigest, "@")
	if !ok || digest == "" {
		return "", fmt.Errorf("%w: %s has no repo digest in the local store", imagepolicy.ErrNoDigest, ref)
	}
	return digest, nil
}

// authorizeImage applies the hub's image trust policy to a project-supplied
// image reference, returning the reference the workload must actually run.
//
// It is called before the image is inspected, built from, or run — "before
// pull/run" in the literal sense that nothing has touched the reference yet.
// The returned string is digest-pinned whenever the store can resolve one, and
// everything downstream uses that rather than the project's original text: the
// tag stops existing at this line, so nothing later can accidentally use it.
func (e *Executor) authorizeImage(ctx context.Context, ref string) (string, error) {
	enforcer := imagepolicy.Enforcer{
		Policy:   e.opts.ImagePolicy,
		Resolver: e,
		Verifier: e.verifier,
	}
	res, err := enforcer.Authorize(ctx, ref)
	if err != nil {
		// A reference that is not a reference is a broken file: it carries
		// ErrInvalidSpec so the API renders it as 400 and the author fixes the
		// repo. Every other rule is a well-formed request the operator's
		// configuration forbids, and stays a *imagepolicy.DenyError so the UI
		// renders the rule and its remediation as a conflict.
		var denied *imagepolicy.DenyError
		if errors.As(err, &denied) && denied.Malformed() {
			return "", fmt.Errorf("%w: sandbox image: %w", executor.ErrInvalidSpec, err)
		}
		return "", err
	}
	for _, w := range res.Warnings {
		fmt.Fprintf(os.Stderr, "[container] %s: %s\n", FileNameHint, w)
	}
	return res.Ref, nil
}

// sandboxImage returns the image a Spec should actually run, resolving the
// per-project override and building a derived image when the spec carries
// setup commands.
//
// The returned identity is what gets recorded in the handle and the task
// artifact, so it describes the image the workload really ran — after the
// override, after the build, after the digest resolution.
func (e *Executor) sandboxImage(ctx context.Context, spec executor.Spec) (ImageIdentity, error) {
	base := strings.TrimSpace(spec.Image)
	if base == "" {
		base = e.opts.Image
	} else {
		// A project-supplied override. This is the untrusted one — it came out
		// of a repo — so it goes through the trust policy before it is
		// inspected, built from, or run, and what comes back is what the rest
		// of this function uses. The original tag is not carried forward.
		authorized, err := e.authorizeImage(ctx, base)
		if err != nil {
			return ImageIdentity{}, err
		}
		base = authorized
	}
	baseID, err := InspectImage(ctx, e.rt, base)
	if err != nil {
		return ImageIdentity{}, err
	}
	if len(spec.SetupCommands) == 0 {
		return baseID, nil
	}
	return e.ensureDerivedImage(ctx, baseID, spec)
}

// ensureDerivedImage returns a derived image built from base plus the spec's
// setup commands, building it if it is not already present.
//
// The tag is a hash of exactly the inputs that affect the result — the base's
// content identity and the command list — so the cache cannot serve a stale
// image after a `setup:` edit, and editing an unrelated part of sandbox.yaml
// cannot force a rebuild.
func (e *Executor) ensureDerivedImage(ctx context.Context, base ImageIdentity, spec executor.Spec) (ImageIdentity, error) {
	from := base.Pinned()
	if base.ID != "" {
		// Prefer the local content ID for the FROM: it is exact, it cannot be
		// repointed between the inspect above and the build below, and unlike
		// a repo digest it never sends the builder to a registry.
		from = base.ID
	}
	key := derivedKey(base, spec.SetupCommands)
	tag := DerivedImagePrefix + ":" + key

	// Cache hit: the image exists, so the setup already ran.
	if id, err := InspectImage(ctx, e.rt, tag); err == nil {
		return id, nil
	}

	dockerfile, err := renderDockerfile(from, base, key, spec.SetupCommands)
	if err != nil {
		return ImageIdentity{}, err
	}

	// An empty build context. The Dockerfile has no COPY and must not: the
	// context would be the project tree, which would let a repo bake its own
	// files — and anything it had fetched — into a cached image that later
	// tasks inherit.
	contextDir, err := os.MkdirTemp("", "cloop-sandbox-ctx-")
	if err != nil {
		return ImageIdentity{}, fmt.Errorf("container: build context: %w", err)
	}
	defer func() { _ = os.RemoveAll(contextDir) }()

	args := []string{
		"build",
		"--file", "-",
		"--tag", tag,
		// Never reach a registry for the base: it is already resolved above.
		"--pull=false",
		// The build inherits the workload's network posture. See the file
		// header — this is the boundary that keeps `setup:` from being an
		// egress channel a no-network deployment did not sign up for.
		"--network", e.buildNetwork(spec),
		contextDir,
	}

	buildCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), buildTimeout)
	defer cancel()

	res, err := runCLIStdin(buildCtx, e.rt, dockerfile, args...)
	if err != nil {
		if errors.Is(buildCtx.Err(), context.DeadlineExceeded) {
			return ImageIdentity{}, fmt.Errorf(
				"container: building the sandbox image for %s timed out after %s — "+
					"a setup: command is probably waiting on input or a lock", FileNameHint, buildTimeout)
		}
		return ImageIdentity{}, fmt.Errorf("container: build sandbox image: %w", err)
	}
	if res.ExitCode != 0 {
		// Untag a half-built image so the next attempt is a clean build rather
		// than a cache hit on a broken layer.
		e.removeImage(context.WithoutCancel(ctx), tag)
		return ImageIdentity{}, fmt.Errorf(
			"container: %s setup failed (exit %d): %s", FileNameHint, res.ExitCode,
			lastLines(res.Stderr+res.Stdout, 12))
	}
	return InspectImage(ctx, e.rt, tag)
}

// FileNameHint names the file a build failure came from. It is a string here
// rather than an import of pkg/sandbox because that package imports pkg/config,
// which imports this one.
const FileNameHint = ".cloop/sandbox.yaml"

// buildNetwork returns the network the derived-image build runs with.
func (e *Executor) buildNetwork(spec executor.Spec) string {
	if spec.DisableNetwork || e.opts.Network == "" || e.opts.Network == NetworkNone {
		return NetworkNone
	}
	return e.opts.Network
}

// derivedKey is the content-addressed tag suffix for a derived image.
func derivedKey(base ImageIdentity, setup []string) string {
	var b strings.Builder
	// The base's content identity, not its tag: rebuilding when the base tag
	// moves is the entire reason the digest is resolved first.
	b.WriteString(base.ID)
	b.WriteString("\x00")
	b.WriteString(base.RepoDigest)
	for _, cmd := range setup {
		b.WriteString("\x00")
		b.WriteString(cmd)
	}
	return shortHash(b.String())
}

// renderDockerfile builds the Dockerfile for a derived image.
//
// It emits nothing but FROM, LABEL and RUN. No COPY (see the build context
// note), no USER (the run decides that, and changing it here would silently
// re-privilege every task in the project), no ENV (values belong in the run's
// environment, not baked into a layer any later task can read).
func renderDockerfile(from string, base ImageIdentity, key string, setup []string) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "FROM %s\n", from)
	fmt.Fprintf(&b, "LABEL %s=%q\n", LabelDerivedFrom, base.Ref)
	fmt.Fprintf(&b, "LABEL %s=%q\n", LabelSetupHash, key)
	for i, cmd := range setup {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			return "", fmt.Errorf("%w: setup_commands[%d] is blank", executor.ErrInvalidSpec, i)
		}
		// Re-checked rather than assumed: this is the last point before a
		// repo-supplied string becomes a Dockerfile instruction, and the cost
		// of being wrong is an attacker-chosen FROM or COPY.
		if strings.ContainsAny(cmd, "\n\r") {
			return "", fmt.Errorf("%w: setup_commands[%d] spans multiple lines", executor.ErrInvalidSpec, i)
		}
		fmt.Fprintf(&b, "RUN %s\n", cmd)
	}
	return b.String(), nil
}

// removeImage untags an image, ignoring failures — it is cleanup, and a
// failure to untag is never worth surfacing over whatever went wrong first.
func (e *Executor) removeImage(ctx context.Context, ref string) {
	rmCtx, cancel := context.WithTimeout(ctx, imageInspectTimeout)
	defer cancel()
	_, _ = runCLITimeout(rmCtx, e.rt, imageInspectTimeout, "image", "rm", "--force", "--", ref)
}

// lastLines returns the final n lines of s, which is where a build failure's
// actual error lives — the preceding hundreds of lines are layer chatter.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
