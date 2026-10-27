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
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build

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
      -ldflags="-s -w -X github.com/blechschmidt/cloop/pkg/version.Version=${VERSION}" \
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
# The projects root: projects/ in the hub's home, where a project created by
# name goes (ui.projects_root, Task 20418). Present in the image for the same
# reason as .cloop — a volume seeded here, or a mount point the Helm chart puts
# its state volume's projects/ on, must belong to the hub's user.
RUN mkdir -p /skel/projects
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

# ── Stage 3: harness sandbox ────────────────────────────────────────────────
# The image a container or Kubernetes executor actually runs a task *in*, and
# the default for both (pkg/executor/container.DefaultImage and
# pkg/executor/kubernetes.DefaultImage). The contract it satisfies is documented
# on those constants; this stage is the reference implementation of it.
#
# Four properties are load-bearing, and each one is a bug that costs a debugging
# cycle if it is missing:
#
#   1. NO ENTRYPOINT. The driver denylists --entrypoint (see the entry in
#      argv.go's denied map) precisely so that the image cannot change what argv
#      runs — which means the image has to exec the argv it is handed. An
#      ENTRYPOINT here would swallow the hub's `cloop run` and the task would
#      silently do nothing.
#   2. cloop at /usr/local/bin/cloop, because the harness re-invokes cloop
#      subcommands from inside the sandbox.
#   3. The `claude` CLI on PATH, because claudecode is the default provider and
#      pkg/provider/claudecode resolves the binary by name.
#   4. It must work under an ARBITRARY uid. The driver derives --user from the
#      project directory's owner, so there is no uid this image can bake in and
#      rely on. That is what HOME=/tmp below is for.
#
# Debian rather than the alpine the executor stage uses: the claude CLI ships
# prebuilt native helpers (ripgrep among them) linked against glibc, and on musl
# they fail at exec time — inside a sandbox, where the error is hardest to see.
# A harness image is the wrong place to spend a boundary on image size.
#
# Two images are built here, and they differ by one program (Task 20450):
#
#   harness          claude, cloop and git — the default image, published as
#                    ghcr.io/blechschmidt/cloop-harness;
#   harness-copilot  the same plus the GitHub Copilot CLI, for the copilot
#                    provider, published as
#                    ghcr.io/blechschmidt/cloop-harness-copilot.
#
# A variant rather than one image because of what the Copilot CLI weighs: a
# 199 MB native binary that, on its first start, unpacks a 247 MB runtime beside
# it. Measured on amd64 (CLI 1.0.104), the harness image is 685 MB unpacked and
# 268 MB compressed, and the copilot CLI adds 445 MB and 217 MB to it — +65%
# and +81%, a pull that nearly doubles, paid by every node for every claude
# project, which is most of them. The numbers are kept in
# docs/reference/sandbox.md.
#
# Each image states what it carries in a label, org.cloop.harnesses, which a hub
# reads wherever it inspects an image anyway, and a project whose harness the
# list lacks is refused before it starts. An image without the label is not
# refused: unknown is not no.
#
# They are declared BEFORE the runtime stage so `runtime` remains the last one
# and therefore the default target: a plain `docker build .` must keep producing
# the hub, not these. Build them explicitly:
#   docker build --target harness -t cloop-harness:dev .
#   docker build --target harness-copilot -t cloop-harness-copilot:dev .

# What both images share. cloop comes last in each of them, because it changes
# with every build and everything below it is then reused from build to build —
# the copilot layer included, which is why that is a stage of its own on this
# one rather than a layer added on top of the finished harness image.
FROM node:22-bookworm-slim AS harness-base

# git and a CA bundle because almost every task shells out to one or the other;
# ca-certificates additionally backs the provider's own TLS calls. procps
# supplies the ps(1) that background-activity detection shells out to.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git ca-certificates openssh-client procps \
 && rm -rf /var/lib/apt/lists/*

# The agent harness for the default provider. Pinned by the ARG so a rebuild of
# an old tag is reproducible rather than silently newer; override to move it.
ARG CLAUDE_CODE_VERSION=latest
RUN npm install -g --no-fund --no-audit "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
 && npm cache clean --force \
 && claude --version

# A non-root user for the documented default and for any runtime that resolves
# the image's own USER. The driver overrides it with --user on every start, so
# this is the floor rather than the decision: an image whose default user is
# root is one --user flag away from a root workload, and ValidateNonRootUser
# exists because most base images make that the easy mistake.
RUN useradd --uid 65532 --create-home --shell /usr/sbin/nologin cloop

# The GitHub Copilot CLI, for the copilot variant: the npm package
# @github/copilot, a small loader that execs the native build published beside
# it for each platform (@github/copilot-linux-x64, -linux-arm64), plus the
# loader's one dependency.
FROM harness-base AS harness-copilot-base

# Pinned twice, unlike claude: by version, and by the sha512 integrity of every
# tarball the install unpacks, as `npm view <name>@<version> dist.integrity`
# prints them. Each tarball is fetched into npm's cache, copied back out and
# hashed against its pin; the install then runs --offline, so it can unpack
# nothing but what was checked — the other platforms' builds, which the loader
# lists as optional, are simply absent. A rebuild of an old tag installs the
# same bytes or fails here, whatever the registry serves by then. To move the
# version, `scripts/copilot-cli-pins.sh <version>` prints the ARG lines below;
# every one of them moves with it.
ARG COPILOT_CLI_VERSION=1.0.104
ARG COPILOT_CLI_INTEGRITY=sha512-C2fPHjSM8HanINktDaqaalPzNSsth9H3zj9V4+ier8ziOIqi+U6OiLXwH44e+QR1vIEaRLKnX40tXUS8SeJDVw==
ARG COPILOT_CLI_LINUX_X64_INTEGRITY=sha512-HGxTAkwrlzIAoQRQ25uWoKToujHzmO1sKC0qGP/yQTv8UhWufHYGHKkHj4sjEbHhRqwXfZvcUzKL9t/vUtklFg==
ARG COPILOT_CLI_LINUX_ARM64_INTEGRITY=sha512-rJ4f2Dgi+jbs4Jf/t/9ommYKhS1e78zxMx7NKuOYkLubnjwzqL/cWeG+UZV4sxl8uTaG1B6pnc1Hr5OuecQ8zA==
ARG COPILOT_CLI_DETECT_LIBC_VERSION=2.1.2
ARG COPILOT_CLI_DETECT_LIBC_INTEGRITY=sha512-Btj2BOOO83o3WyH59e8MgXsxEQVcarkUOpEYrubB0urwnN10yQ364rsiByU11nZlqWYZm05i/of7io4mzihBtQ==

# Where the CLI unpacks its runtime, in the image and read-only, rather than
# under $HOME. The native binary carries its runtime packed and unpacks it, 247
# MB, the first time it starts — into the cache under $HOME unless this says
# otherwise, and $HOME is the sandbox's /tmp: a tmpfs in RAM, capped at 512 MB
# by the container driver and gone with the container. So every task would
# unpack it again into memory, half the scratch space gone before the agent did
# anything. Unpacked here once, at the `copilot --version` below, a start finds
# it complete and reads it, which any uid can; nothing is written.
ENV COPILOT_PKG_CACHE_HOME=/usr/local/lib/copilot

RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) native=linux-x64;   native_integrity="$COPILOT_CLI_LINUX_X64_INTEGRITY" ;; \
      arm64) native=linux-arm64; native_integrity="$COPILOT_CLI_LINUX_ARM64_INTEGRITY" ;; \
      *) echo "the Copilot CLI publishes no build for $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    pinned() { \
      npm cache add --no-update-notifier "$1"; \
      tarball=$(npm pack --offline --silent --no-update-notifier --pack-destination /tmp "$1"); \
      got=$(node -e 'const fs = require("fs"), crypto = require("crypto"); process.stdout.write("sha512-" + crypto.createHash("sha512").update(fs.readFileSync(process.argv[1])).digest("base64"))' "/tmp/$tarball"); \
      rm -f "/tmp/$tarball"; \
      if [ "$got" != "$2" ]; then echo "$1 is $got, not the pinned $2" >&2; exit 1; fi; \
      echo "$1 matches its pin"; \
    }; \
    pinned "@github/copilot@${COPILOT_CLI_VERSION}" "$COPILOT_CLI_INTEGRITY"; \
    pinned "@github/copilot-${native}@${COPILOT_CLI_VERSION}" "$native_integrity"; \
    pinned "detect-libc@${COPILOT_CLI_DETECT_LIBC_VERSION}" "$COPILOT_CLI_DETECT_LIBC_INTEGRITY"; \
    npm install -g --offline --no-fund --no-audit --no-update-notifier "@github/copilot@${COPILOT_CLI_VERSION}"; \
    npm cache clean --force; \
    COPILOT_HOME=/tmp/copilot-build-home copilot --version; \
    rm -rf /tmp/copilot-build-home /root/.cache /root/.npm; \
    test -f "$COPILOT_PKG_CACHE_HOME/pkg/${native}/${COPILOT_CLI_VERSION}/cli-main.js"

# The default image.
FROM harness-base AS harness

COPY --from=build /out/cloop /usr/local/bin/cloop

# HOME on the tmpfs the driver mounts at /tmp, NOT on /home/cloop.
#
# This is the arbitrary-uid property made concrete. git writes ~/.gitconfig, npm
# and claude write dotfiles, and a uid that is not 65532 cannot write to
# /home/cloop — so a HOME pointing there produces "could not lock config file"
# from git on a task that looked like it should work. /tmp is mounted
# rw,nosuid,nodev,exec by the driver for every workload regardless of uid, which
# makes it the only path guaranteed writable by whoever we turn out to be.
ENV HOME=/tmp

# Credentials are deliberately absent: provider API keys and brokered secrets
# are injected as environment at start (buildRunArgs' `--env NAME` passthrough),
# which is what makes one image safe to share across tenants and safe to publish.

# org.cloop.harnesses lists the programs the image carries, comma-separated.
# pkg/imagepolicy reads it (HarnessesLabel), and tests/docs holds each image's
# list equal to remote.PublishedHarnessImages, which the hub's refusals name
# these images from.
LABEL org.opencontainers.image.title="cloop harness" \
      org.opencontainers.image.description="cloop sandbox image: the default workload image for container and Kubernetes executors" \
      org.opencontainers.image.source="https://github.com/blechschmidt/cloop" \
      org.opencontainers.image.documentation="https://github.com/blechschmidt/cloop/blob/main/docs/architecture/executors.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="blechschmidt" \
      org.opencontainers.image.base.name="node:22-bookworm-slim" \
      org.cloop.harnesses="claude,cloop,git"

USER 65532:65532

# Explicit and empty, so that the no-ENTRYPOINT contract is stated in the image
# rather than merely inherited from whatever the base image happens to do.
ENTRYPOINT []
CMD ["/usr/local/bin/cloop", "--help"]

# The copilot variant: the default image's tail, on the stage that carries the
# Copilot CLI. Every line means what it means in the harness stage above.
FROM harness-copilot-base AS harness-copilot

COPY --from=build /out/cloop /usr/local/bin/cloop

ENV HOME=/tmp

# The CLI keeps its state — sessions, logs, its configuration — in
# COPILOT_HOME, named outright on the tmpfs for the reason HOME is there: any
# uid can create it. Its updater is off, so the CLI that runs is the one this
# image was built with rather than whatever it would download at a start.
ENV COPILOT_HOME=/tmp/.copilot \
    COPILOT_AUTO_UPDATE=false

LABEL org.opencontainers.image.title="cloop harness with GitHub Copilot" \
      org.opencontainers.image.description="cloop sandbox image with the GitHub Copilot CLI, for the copilot provider" \
      org.opencontainers.image.source="https://github.com/blechschmidt/cloop" \
      org.opencontainers.image.documentation="https://github.com/blechschmidt/cloop/blob/main/docs/reference/sandbox.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="blechschmidt" \
      org.opencontainers.image.base.name="node:22-bookworm-slim" \
      org.cloop.harnesses="claude,copilot,cloop,git"

USER 65532:65532
ENTRYPOINT []
CMD ["/usr/local/bin/cloop", "--help"]

# ── Stage 4: runtime ────────────────────────────────────────────────────────
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
# Every interface, explicitly (Task 20393). A container's loopback is its own,
# so a published port reaches only what listens on the container's interfaces —
# and without --listen a hub with no sign-in would bind 127.0.0.1 and be
# unreachable while its HEALTHCHECK, which probes from inside, reported it
# healthy. Naming the address instead makes an open hub refuse to start, with
# the reason: give it CLOOP_UI_TOKEN or ui.oidc, or set
# ui.allow_unauthenticated_network: true in a mounted config and publish it on
# the host's loopback only (-p 127.0.0.1:8080:8080).
CMD ["ui", "--listen", "0.0.0.0", "--port", "8080", "--no-browser"]
