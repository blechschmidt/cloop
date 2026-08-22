# cloop hub — multi-stage build onto a distroless, non-root, read-only runtime.
#
# The runtime stage is distroless on purpose, and it costs something: there is
# no shell, no package manager, no curl and no git in the final image. That is
# the point. A hub configured with executors.allow_host_process=false has
# already promised never to run a harness on its own host; an image that
# contains no way to execute anything makes that promise structural instead of
# a config value. It also means `docker exec -it … sh` does not work, which is
# a real operational cost and the reason `cloop hub healthcheck` exists — the
# HEALTHCHECK below is the binary probing itself, because there is nothing
# else in the image that speaks HTTP.
#
# Build:
#   docker build -t cloop-hub:dev .
# Run (read-only rootfs, one writable volume, unprivileged):
#   docker run --rm -p 8080:8080 \
#     --read-only --cap-drop ALL --security-opt no-new-privileges \
#     -v cloop-state:/var/lib/cloop --tmpfs /tmp:rw,noexec,nosuid,size=64m \
#     -e CLOOP_UI_TOKEN=… -e CLOOP_SECRET_KEY=… cloop-hub:dev

# ── Stage 1: build ──────────────────────────────────────────────────────────
# --platform=$BUILDPLATFORM pins the toolchain to the *builder's* architecture
# and cross-compiles from there. Without it, `buildx --platform linux/arm64`
# runs the entire Go build under emulation, which is roughly an order of
# magnitude slower for no benefit — the compiler is a cross-compiler already.
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS build

WORKDIR /src

# Dependencies first: this layer is invalidated only by go.mod/go.sum, so
# editing source does not re-download the module graph.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev

# Declared WITHOUT defaults, deliberately. TARGETOS/TARGETARCH/BUILDARCH are
# predefined BuildKit args, and giving one a default stops BuildKit injecting
# the real value — so `buildx --platform linux/arm64` would quietly compile
# GOARCH=amd64 and produce an image that cannot exec. Empty is the right
# fallback for a plain `docker build`: the Go toolchain then uses the host's
# own GOOS/GOARCH, which is what that invocation means.
ARG TARGETOS
ARG TARGETARCH
ARG BUILDARCH

# CGO_ENABLED=0 is what makes the binary runnable on a distroless *static*
# base with no libc at all. cloop's only C-adjacent dependency is SQLite, and
# it uses modernc.org/sqlite (pure Go) precisely so this is possible — swapping
# in a cgo SQLite driver would silently break this image.
#
# -trimpath keeps build-host paths out of the binary so the same source
# produces the same bytes on a developer laptop and in CI.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags="-s -w -X github.com/blechschmidt/cloop/cmd.Version=${VERSION}" \
      -o /out/cloop .

# Fail the build rather than the deployment if the binary turns out to be
# dynamically linked: a cgo-linked binary starts fine here and dies with
# "no such file or directory" on the distroless stage, which is one of the
# least informative errors in containers.
#
# Skipped when cross-compiling, where the binary is for another architecture
# and running it would fail for a reason that has nothing to do with linking.
RUN if [ -z "$TARGETARCH" ] || [ "$TARGETARCH" = "$BUILDARCH" ]; then \
      /out/cloop version; \
    else \
      echo "cross-compiling $BUILDARCH -> $TARGETARCH; skipping the run check"; \
    fi

# The state directory, pre-created here so it can be COPY --chown'd into a
# distroless stage that has no mkdir and no chown. Getting the ownership right
# in the image is what makes an *empty named volume* usable: Docker seeds a
# fresh volume from the image path including its ownership, so a directory
# left owned by root produces a volume the non-root hub cannot write to — and
# the symptom is a permission error from SQLite, several layers away from the
# cause.
RUN mkdir -p /skel/.cloop
# A drop directory for `cloop executor enroll --bundle-file`, owned by the
# unprivileged user the runtime stage runs as.
#
# It is here rather than in the compose file because of how Docker seeds a
# named volume: a fresh volume mounted at a path that exists in the image
# inherits that path's ownership, and one mounted at a path that does not is
# created owned by root — which the non-root hub then cannot write to. Handing
# a bundle from the container that mints it to the container that redeems it is
# the ordinary shape of automated enrollment (compose, cloud-init, Ansible), so
# the image provides somewhere for it to land.
RUN mkdir -p /skel-run/enroll

# ── Stage 2: executor agent ─────────────────────────────────────────────────
# A *different* base from the hub, and deliberately so.
#
# The hub image is distroless because a control plane that promises never to
# run a harness on its own host should contain no way to execute one. An
# executor agent's entire job is the opposite: it materialises a source tree
# with git and runs a harness in it. It needs git on PATH, and the write-back
# path needs it again to commit and bundle what the harness produced — so the
# distroless image is not merely inconvenient here, it cannot do the work.
#
# Keeping them as two images is what makes that difference visible in the
# artifact rather than in a comment. The hub cannot exec anything; the agent
# can, on a machine that is not the hub. That is the whole architecture.
#
# It is declared BEFORE the runtime stage so `runtime` remains the last one and
# therefore the default target: a plain `docker build .` must keep producing
# the hub, not this.
FROM alpine:3.20 AS executor

RUN apk add --no-cache git ca-certificates openssh-client tini \
 && adduser -D -u 65532 -h /var/lib/cloop-agent cloop \
 && mkdir -p /var/lib/cloop-agent/work /srv/git \
 && chown -R 65532:65532 /var/lib/cloop-agent /srv/git

COPY --from=build /out/cloop /usr/local/bin/cloop

# The agent persists its long-lived credential under $HOME after redeeming the
# single-use enrollment token, so HOME must be on a writable volume or every
# restart re-enrolls (and burns a token that is, by design, single-use).
WORKDIR /var/lib/cloop-agent
ENV HOME=/var/lib/cloop-agent
USER 65532:65532

# /srv/git exists and is owned by the agent user so that a named volume
# mounted there is seeded with that ownership. It is what lets `make e2e-stack`
# build a git origin from this image without running as root — which matters
# because the service drops every capability, so a root process could not write
# into a directory it does not own anyway.

# tini reaps the harness processes the agent forks. Without a reaper at PID 1
# a long-running agent accumulates zombies until it hits the container's PID
# limit, which presents as workloads that will not start for no visible reason.
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/cloop"]
CMD ["executor", "agent"]

# ── Stage 3: runtime ────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="cloop hub" \
      org.opencontainers.image.description="cloop control plane: dashboard, REST API and remote executor endpoint" \
      org.opencontainers.image.source="https://github.com/blechschmidt/cloop" \
      org.opencontainers.image.documentation="https://github.com/blechschmidt/cloop/blob/main/deploy/README.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="blechschmidt" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian12:nonroot"

COPY --from=build /out/cloop /usr/local/bin/cloop

# `cloop ui` resolves .cloop relative to the process working directory — there
# is no --workdir flag — so WORKDIR *is* the state-directory selector. The
# volume must be mounted here or the hub will create its database inside the
# read-only layer and fail.
#
# HOME points at the same directory deliberately. The multi-project registry
# lives at $HOME/.cloop/projects.json, and pointing HOME anywhere else on a
# read-only rootfs means either a second writable mount or a hub that cannot
# register a project. One volume holds all persistent state, which is also
# what makes "back up the hub" a single instruction.
COPY --from=build --chown=65532:65532 /skel /var/lib/cloop
COPY --from=build --chown=65532:65532 /skel-run /run

WORKDIR /var/lib/cloop
ENV HOME=/var/lib/cloop
VOLUME ["/var/lib/cloop"]

# The base image's nonroot user. Named numerically so a Kubernetes
# runAsNonRoot check can verify it without resolving /etc/passwd.
USER 65532:65532

EXPOSE 8080

# There is no curl in this image; the binary probes itself. Liveness, not
# readiness: a hub whose database is briefly locked should not be restarted,
# it should be taken out of rotation, and that decision belongs to /readyz in
# an orchestrator probe rather than to Docker's restart policy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/cloop", "hub", "healthcheck", "--url", "http://127.0.0.1:8080"]

ENTRYPOINT ["/usr/local/bin/cloop"]
CMD ["ui", "--port", "8080", "--no-browser"]
