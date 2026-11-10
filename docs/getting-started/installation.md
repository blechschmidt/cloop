# Installation

cloop is a single static Go binary. You don't have to set up a daemon, a
database or any configuration before the first run. The first time you run
`cloop init` in a project, cloop creates the state it needs inside that project.

Before you install, decide which AI provider you want to use. Two of the five
need a second program on the machine that you sign in to, two need a
credential, and Ollama needs a local server.

- [Prerequisites](#prerequisites)
- [Download a release binary](#download-a-release-binary)
- [Install with `go install`](#install-with-go-install)
- [Build from source](#build-from-source)
- [The container image](#the-container-image)
- [Verifying the install](#verifying-the-install)
- [Shell completion](#shell-completion)

---

## Prerequisites

**Go 1.26 or newer.** `go.mod` declares `go 1.26.0` and pins
`toolchain go1.26.10`. Go 1.21 and later read that line and download the pinned
toolchain automatically, so any recent Go works. Older versions refuse to build
the module.

**One provider.** cloop has five backends. The default one and `copilot` use a
program you sign in to, and the others use an API key or a local server:

| Provider | What it talks to | What it needs |
| --- | --- | --- |
| `claudecode` (default) | the local `claude` CLI, over a pipe | the `claude` binary on `PATH` (`~/.local/bin` and `~/.npm-global/bin` are also searched), already signed in |
| `copilot` | the local `copilot` CLI (GitHub Copilot) | the `copilot` binary on `PATH`, signed in with `copilot login` or given `COPILOT_GITHUB_TOKEN` |
| `anthropic` | `https://api.anthropic.com/v1` | `ANTHROPIC_API_KEY`, or `cloop config set anthropic.api_key …` |
| `openai` | `https://api.openai.com/v1` | `OPENAI_API_KEY`, or `cloop config set openai.api_key …`. `openai.base_url` points it at any OpenAI-compatible server |
| `ollama` | `http://localhost:11434` | nothing but a local Ollama server with a pulled model |

`cloop providers` prints this table for your machine and marks each provider as
configured or not. `cloop providers --test` also makes one live call to each.
[Providers](providers.md) helps you choose between them.

---

## Download a release binary

This is the only way to install cloop without a Go toolchain. Each release
publishes a static binary for each platform, a `checksums.txt` that covers all
of them, and a Sigstore signature bundle (`<asset>.sigstore.json`) for each of
those files:

| Platform | Asset |
| --- | --- |
| Linux x86-64 | `cloop_linux_amd64.tar.gz` |
| Linux arm64 | `cloop_linux_arm64.tar.gz` |
| Linux armv7 | `cloop_linux_arm.tar.gz` |
| macOS Intel | `cloop_darwin_amd64.tar.gz` |
| macOS Apple silicon | `cloop_darwin_arm64.tar.gz` |

Asset names don't include the version, so `releases/latest/download/<asset>`
always points at the current release. It is the only URL that stays valid from
one release to the next, and the executor bootstrap installer uses it. To see
which version a binary is, run `cloop version`.

These commands download the x86-64 archive for your operating system, verify it
and install it:

```bash
ASSET="cloop_$(uname -s | tr '[:upper:]' '[:lower:]')_amd64.tar.gz"
BASE="https://github.com/blechschmidt/cloop/releases/latest/download"

curl -fsSLO "$BASE/$ASSET"
curl -fsSLO "$BASE/$ASSET.sigstore.json"
curl -fsSLO "$BASE/checksums.txt"

# Provenance: was this built by cloop's release workflow? See below.
cosign verify-blob "$ASSET" \
  --bundle "$ASSET.sigstore.json" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp \
    '^https://github\.com/blechschmidt/cloop/\.github/workflows/release\.yml@refs/tags/v[^/]+$'

# Integrity: did the download arrive intact?
sha256sum --ignore-missing -c checksums.txt   # shasum -a 256 -c on macOS

# Members carry a "./" prefix (the archive is built with `tar -C "$workdir" .`),
# so the member name has to be written as ./cloop — a bare `cloop` is "Not
# found in archive".
tar -xzf "$ASSET" ./cloop
sudo install -m 0755 cloop /usr/local/bin/cloop
```

### Verifying provenance

Of the two checks above, only `cosign verify-blob` tells you who built the
binary. `sha256sum` only shows that the download arrived intact.
`checksums.txt` comes from the same GitHub release as the archive, so anyone who
can replace the archive can also replace the checksum file, and the comparison
then passes against their list.

cloop's releases are signed with [Sigstore][sigstore] keyless signing. The release workflow authenticates to
Fulcio with GitHub's OIDC token and receives a short-lived certificate that
names the workflow, repository and ref that requested it. The project has no
long-lived private key that could leak or would need rotating. To produce a
signature that matches the identity in the command above, someone would have
to run this repository's release workflow on a tag.

You need both flags. If you leave either one off, the check proves nothing:

- `--certificate-oidc-issuer`: without it, cosign accepts a certificate from
  any issuer that Fulcio federates with.
- `--certificate-identity-regexp`: without it, any valid Sigstore signature
  passes, and anyone can make one. The identity is what ties the signature to
  cloop's release workflow.

Install cosign from [its releases page][cosign]. Signatures are also recorded
in the public Rekor transparency log, so anyone can check afterwards which
signatures were issued for cloop releases.

[sigstore]: https://www.sigstore.dev/
[cosign]: https://github.com/sigstore/cosign/releases

### When verification is not possible

An air-gapped site that mirrors releases internally may not be able to reach
Sigstore. Both self-installing commands, and the install script, take
`--insecure-skip-verify`:

```bash
cloop upgrade --insecure-skip-verify
cloop executor agent install --upgrade --from ./cloop --insecure-skip-verify
sh install.sh --insecure-skip-verify        # or CLOOP_INSECURE_SKIP_VERIFY=1
```

The flag turns off the signature check only. The checksum is still verified.
Every command that uses the flag says so in its output, so you can find
unverified installs by searching your provisioning logs.

A fork that builds and signs its own cloop shouldn't turn verification off. Set
`CLOOP_PROVENANCE_ISSUER` and `CLOOP_PROVENANCE_IDENTITY` to the fork's signing
identity instead, so that a signature is still required.

To install a specific release instead of the newest one, replace
`latest/download` with `download/v<version>`, for example
`https://github.com/blechschmidt/cloop/releases/download/v0.0.1`. Releases up to
and including v0.0.1 used versioned asset names
(`cloop_0.0.1_linux_amd64.tar.gz`). `cloop upgrade` still recognises those
names, so an older binary can still upgrade.

Release binaries carry a real version string (a `go install` build doesn't), so
`cloop upgrade` works with them. It queries the releases API, downloads the
asset for the running OS and architecture, checks its SHA-256 against
`checksums.txt` and its signature against the identity above, and only then
replaces the running binary atomically. It needs `cosign` on `PATH`, and it
refuses to upgrade without it instead of skipping the signature check.
`cloop upgrade --check` only reports whether an update exists.

There is no Windows build. cloop stops harnesses by supervising their process
groups, which only works on POSIX systems, so releases include Linux and macOS
binaries only.

Release archives are reproducible. Rebuilding the same tag from the same commit
produces byte-identical tarballs, so you can run
`make release-dist VERSION=v<version>` locally and compare the checksums with
the published ones.

---

## Install with `go install`

```bash
go install github.com/blechschmidt/cloop@latest
```

The binary goes into `$(go env GOPATH)/bin`, which needs to be on your `PATH`.

A binary installed this way reports its version as `dev`, followed by the short
commit it was built from if the toolchain recorded one (for example
`dev+g4f7b5bc`). This is expected. The version string is set at build time by a
linker flag (`-X github.com/blechschmidt/cloop/pkg/version.Version=…`), and
`go install` doesn't set it.

Three things use the version: the version banner, `cloop upgrade --check`, and,
on a device running as an executor agent, the build version the agent reports to
the control plane. The hub's Executors panel uses that to flag version skew
across a fleet. An agent without a version is shown as running an unreleased
build, so the hub never assumes it is current.

---

## Build from source

```bash
git clone https://github.com/blechschmidt/cloop.git
cd cloop
make build            # equivalent to: go build -o cloop .
```

To give the binary a real version, set the same linker flag the container build
uses:

```bash
go build -trimpath \
  -ldflags "-X github.com/blechschmidt/cloop/pkg/version.Version=v1.2.3" \
  -o cloop .
```

A binary with a version can replace itself with `cloop upgrade`. It downloads
the asset for the current OS and architecture from the GitHub releases API,
verifies its SHA-256 and swaps the running binary atomically.
`cloop upgrade --check` only reports whether an update exists.

---

## The container image

The image built from this repository runs the **hub**: the dashboard, the REST
API and the endpoint that remote executor agents connect to. To use cloop on
your own machine, install the binary instead. The
[operator runbook](../operations/runbook.md) and `deploy/README.md` explain how
to run a hub in production.

```bash
docker build -t cloop-hub:dev .
```

The default target is distroless: it has no shell, no package manager, no `curl`
and no `git`. The hub never runs a harness on its own host, so its image
contains nothing that could run one. As a result, `docker exec … sh` doesn't
work, and the container's `HEALTHCHECK` runs the binary itself as
`cloop hub healthcheck`.

The image runs as UID 65532, exposes port 8080, and its default command is
`ui --port 8080 --no-browser`. cloop finds `.cloop` relative to the working
directory, so `WORKDIR` decides where the state is kept. Mount the volume at
`/var/lib/cloop`. Otherwise the hub tries to write its database into the
read-only layer and fails.

```bash
docker run --rm -p 8080:8080 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v cloop-state:/var/lib/cloop --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v /srv/cloop/cloop-secret-key:/run/secrets/cloop-secret-key:ro \
  -e CLOOP_SECRET_KEY_FILE=/run/secrets/cloop-secret-key \
  -e CLOOP_UI_TOKEN=… cloop-hub:dev
```

Pass the root key in as a file, owned by UID 65532 with mode `0400`. Don't pass
it as `-e CLOOP_SECRET_KEY=…`: `docker inspect` shows environment variables to
anyone who can run it (see [the root key](../operations/runbook.md#the-root-key)).

A second target builds the executor agent. It is based on Alpine instead of
distroless, because the agent needs `git` to materialise a project's source tree
and to commit what a task changed:

```bash
docker build --target executor -t cloop-executor:dev .
```

To try SSO, RBAC and TLS together without writing any configuration, start the
evaluation stack. It runs a hub, dex as a mock identity provider, and nginx to
terminate TLS:

```bash
docker compose up --build     # then open https://cloop.localtest.me:8443/
docker compose down -v        # resets everything
```

A third target builds the **harness image**, the sandbox that container and
Kubernetes executors run each task in:

```bash
docker build --target harness -t cloop-harness:dev .
```

You rarely need to build it yourself. It is published, and both kinds of
executor use the published image by default:

```bash
docker pull ghcr.io/blechschmidt/cloop-harness:latest
```

The image includes the `claude` CLI. For projects that use the `copilot`
provider there is a variant that adds the GitHub Copilot CLI
(`--target harness-copilot`, published as
`ghcr.io/blechschmidt/cloop-harness-copilot`). It is a separate image because
the Copilot CLI nearly doubles its size. See [the published
images](../reference/sandbox.md#the-published-images-and-what-an-image-carries).

When a task needs a toolchain this image lacks, build your own and point
`executors.container.image` at it. Any base OS works, as long as the image has:

- `cloop` at `/usr/local/bin/cloop`
- the `claude` CLI on `PATH`, for the default provider
- `git` and a CA bundle
- no `ENTRYPOINT`. The driver denylists `--entrypoint`, so the image has to run
  the argv it is given.
- a `HOME` that any UID can write to. The driver sets `--user` from the owner of
  the project directory, so the user can't be baked into the image.

Credentials never go into the image. Provider keys and brokered secrets are
passed in as environment variables when the sandbox starts, which is why one
image can be shared safely between tenants.

For Kubernetes there is a Helm chart at `deploy/helm/cloop-hub`. Its default
`image.repository` is `ghcr.io/blechschmidt/cloop`, and `image.tag` defaults to
the chart's `appVersion`. A second chart, `deploy/helm/cloop-executor-controller`,
runs the executor controller that keeps an executor pool's runners as Pods,
from the same image. `.github/workflows/publish-images.yml` publishes both
images to GHCR for every release tag, with `:edge` following `main`, and signs
every digest it pushes with keyless signing. To check an image yourself, run
`cloop hub verify-image ghcr.io/blechschmidt/cloop:<tag>`. A hub also checks
cloop's images before a sandbox runs one. In production, pin images by digest. A
tag can move, so the image that runs your agents could change without a deploy.

---

## Verifying the install

To check which version you installed, run `cloop version`. There is no
`--version` flag.

```console
$ cloop version
cloop dev
Go go1.26.3 linux/amd64
```

The second line shows the Go toolchain that built the binary, which helps when
a bug has to be reproduced.

`cloop doctor` checks more. Outside a project it checks your environment. Inside
a project it also checks the integrity of the state database, the config file,
and whether the YAML config still matches its SQLite mirror.

```console
$ cloop doctor
cloop doctor — environment health check

  [WARN] .cloop/ directory                    .cloop/ directory not found — project may not be initialized
         fix: Run: cloop init "<your goal>"
  [PASS] Go binary                            go version go1.26.3 linux/amd64
  [PASS] claude binary (claudecode provider)  claude CLI binary found in PATH
  [WARN] config validate: config.yaml         config file not found — using defaults
  [PASS] .cloop/ disk usage                   .cloop/ uses 0 B

Result: 3 passed, 2 warnings, 0 failed

Tip: run 'cloop doctor --providers' to also test live provider connectivity.
```

In an empty directory these warnings are expected: there is no project here yet.
The exit status is 1 only if a check fails. Warnings exit with 0, so you can use
`cloop doctor` as a CI gate without configuring it first.
`--providers` adds a live connectivity test for each configured provider, which
is slower and uses a token or two.

`cloop hub doctor` is a separate command. It audits the configuration of a
hosted hub (issuer discovery, TLS material, RBAC, sealing key) and is documented
in the [runbook](../operations/runbook.md).

---

## Shell completion

cloop generates shell completions for bash, zsh, fish and PowerShell. They
complete subcommands and flags, and also values such as provider names, template
names and the IDs of the tasks in the project you are in.

To turn them on for the current session:

```bash
source <(cloop completion bash)     # bash
source <(cloop completion zsh)      # zsh
cloop completion fish | source      # fish
```

```powershell
cloop completion powershell | Out-String | Invoke-Expression
```

To make them permanent:

```bash
# bash, Linux
cloop completion bash > /etc/bash_completion.d/cloop
# bash, macOS (needs bash-completion@2)
cloop completion bash > $(brew --prefix)/etc/bash_completion.d/cloop

# zsh
cloop completion zsh > "${fpath[1]}/_cloop"

# fish
cloop completion fish > ~/.config/fish/completions/cloop.fish
```

`cloop completion <shell> --help` prints the same instructions for that shell.
If they ever differ from this page, the command's output is the up-to-date one.

---

**Next:** [Your first project](first-project.md) takes you from an empty
directory to a plan the agent has worked through.
