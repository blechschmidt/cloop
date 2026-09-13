# Installation

cloop is a single static Go binary. There is no daemon to register, no database
to provision and nothing to configure before the first run — the state a project
needs is created inside that project, the first time you run `cloop init` in it.

What you do have to decide before installing is **which AI provider you intend
to use**, because one of the four needs a second program on the machine and the
other three need a credential. That is the only prerequisite that is not "a Go
toolchain".

- [Prerequisites](#prerequisites)
- [Download a release binary](#download-a-release-binary)
- [Install with `go install`](#install-with-go-install)
- [Build from source](#build-from-source)
- [The container image](#the-container-image)
- [Verifying the install](#verifying-the-install)
- [Shell completion](#shell-completion)

---

## Prerequisites

**Go 1.25 or newer.** `go.mod` declares `go 1.25.0` and pins
`toolchain go1.25.14`. Any Go 1.21 or later toolchain honours that line and
downloads the pinned one on its own, so in practice "a recent Go" is enough;
anything older refuses the module outright.

**One provider.** cloop registers four backends, and the default is the one that
is *not* an API key:

| Provider | What it talks to | What it needs |
| --- | --- | --- |
| `claudecode` (default) | the local `claude` CLI, over a pipe | the `claude` binary on `PATH` (`~/.local/bin` and `~/.npm-global/bin` are also searched), already signed in |
| `anthropic` | `https://api.anthropic.com/v1` | `ANTHROPIC_API_KEY`, or `cloop config set anthropic.api_key …` |
| `openai` | `https://api.openai.com/v1` | `OPENAI_API_KEY`, or `cloop config set openai.api_key …`. `openai.base_url` points it at any OpenAI-compatible server |
| `ollama` | `http://localhost:11434` | nothing — a local Ollama server with a pulled model |

`cloop providers` prints that table for your machine, with each provider marked
configured or not, and `cloop providers --test` additionally makes one live call
to each. See [Providers](providers.md) for choosing between them.

---

## Download a release binary

The only install path that needs no Go toolchain at all. Each release publishes
a static binary per platform, plus a `checksums.txt` covering all of them:

| Platform | Asset |
| --- | --- |
| Linux x86-64 | `cloop_<version>_linux_amd64.tar.gz` |
| Linux arm64 | `cloop_<version>_linux_arm64.tar.gz` |
| macOS Intel | `cloop_<version>_darwin_amd64.tar.gz` |
| macOS Apple silicon | `cloop_<version>_darwin_arm64.tar.gz` |

```bash
VERSION=0.0.1   # no leading "v" in the asset name; the git tag has one
ASSET="cloop_${VERSION}_$(uname -s | tr '[:upper:]' '[:lower:]')_amd64.tar.gz"
BASE="https://github.com/blechschmidt/cloop/releases/download/v${VERSION}"

curl -fsSLO "$BASE/$ASSET"
curl -fsSLO "$BASE/checksums.txt"
sha256sum --ignore-missing -c checksums.txt   # shasum -a 256 -c on macOS

# Members carry a "./" prefix (the archive is built with `tar -C "$workdir" .`),
# so the member name has to be written as ./cloop — a bare `cloop` is "Not
# found in archive".
tar -xzf "$ASSET" ./cloop
sudo install -m 0755 cloop /usr/local/bin/cloop
```

Unlike `go install`, these binaries carry a real version string, so
`cloop upgrade` works from here: it queries the releases API, downloads the
asset for the running OS and architecture, verifies its SHA-256 against the
same `checksums.txt`, and swaps the running binary atomically.
`cloop upgrade --check` reports whether an update exists and does nothing else.

**There is no Windows build.** The process-group supervision cloop stops
harnesses with is POSIX-only, so releases carry Linux and macOS binaries only.

Release archives are reproducible: the same tag rebuilt from the same commit
produces byte-identical tarballs, so the checksums above can be regenerated
locally with `make release-dist VERSION=v<version>` and compared against the
published ones.

---

## Install with `go install`

```bash
go install github.com/blechschmidt/cloop@latest
```

The binary lands in `$(go env GOPATH)/bin`, which must be on your `PATH`.

A binary installed this way reports its version as `dev` (plus the short commit
it was built from, when the toolchain recorded one — `dev+g4f7b5bc`). That is not
a bug: the version string is a build-time linker flag
(`-X github.com/blechschmidt/cloop/pkg/version.Version=…`) and `go install` does
not set it.

Three things read the value: the version banner, `cloop upgrade --check`, and —
on a device running as an executor agent — the build version reported to the
control plane, which the hub's Executors panel uses to flag version skew across
a fleet. An unstamped agent is reported as running an unreleased build rather
than being silently assumed current.

---

## Build from source

```bash
git clone https://github.com/blechschmidt/cloop.git
cd cloop
make build            # equivalent to: go build -o cloop .
```

To stamp a real version into the binary, set the same linker flag the container
build uses:

```bash
go build -trimpath \
  -ldflags "-X github.com/blechschmidt/cloop/pkg/version.Version=v1.2.3" \
  -o cloop .
```

Once a versioned binary is installed, `cloop upgrade` replaces it in place: it
queries the GitHub releases API, downloads the asset for the current OS and
architecture, verifies its SHA-256 and swaps the running binary atomically.
`cloop upgrade --check` reports whether an update exists and does nothing else.

---

## The container image

The image in this repository runs the **hub** — the dashboard, the REST API and
the endpoint remote executor agents dial into. It is not a packaged CLI for
local use; for that, install the binary. The [operator
runbook](../operations/runbook.md) and `deploy/README.md` cover running one for
real.

```bash
docker build -t cloop-hub:dev .
```

The default target is distroless: no shell, no package manager, no `curl` and no
`git`. That is deliberate — a hub that promises never to execute a harness on
its own host should contain no way to execute one — and it has a practical
consequence, which is that `docker exec … sh` does not work and the container's
`HEALTHCHECK` is the binary probing itself with `cloop hub healthcheck`.

The image runs as UID 65532, exposes 8080, and its default command is
`ui --port 8080 --no-browser`. `.cloop` is resolved relative to the working
directory, so `WORKDIR` *is* the state-directory selector: the volume has to be
mounted at `/var/lib/cloop` or the hub writes its database into the read-only
layer and fails.

```bash
docker run --rm -p 8080:8080 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v cloop-state:/var/lib/cloop --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -e CLOOP_UI_TOKEN=… -e CLOOP_SECRET_KEY=… cloop-hub:dev
```

A second target builds the executor agent, which is Alpine rather than
distroless because materialising a source tree and committing what a task
changed both need `git`:

```bash
docker build --target executor -t cloop-executor:dev .
```

To see SSO, RBAC and TLS working together without writing any configuration,
bring up the evaluation stack — a hub, dex as a mock identity provider, and
nginx terminating TLS:

```bash
docker compose up --build     # then open https://cloop.localtest.me:8443/
docker compose down -v        # resets everything
```

A third target builds the **harness image** — the sandbox a container or
Kubernetes executor actually runs a task inside, and the default for both:

```bash
docker build --target harness -t cloop-harness:dev .
```

You rarely need to build it yourself. It is published, and the executor defaults
already point at it:

```bash
docker pull ghcr.io/blechschmidt/cloop-harness:latest
```

What makes an image usable as a harness is a contract, not just a base OS: it
carries `cloop` at `/usr/local/bin/cloop`, the `claude` CLI on `PATH` for the
default provider, `git` and a CA bundle, **no `ENTRYPOINT`** (the driver
denylists `--entrypoint`, so the image must exec the argv it is handed), and a
`HOME` that is writable by any UID — the driver derives `--user` from the
project directory's owner, so nothing can be baked in. Build your own when a
task needs a toolchain this one lacks, and point `executors.container.image` at
it. Credentials are never baked in: provider keys and brokered secrets are
injected as environment at start, which is what makes one image safe to share
across tenants.

For Kubernetes there is a chart at `deploy/helm/cloop-hub`. Its default
`image.repository` is `ghcr.io/blechschmidt/cloop` and `image.tag` defaults to
the chart's `appVersion`. Both images are published to GHCR by
`.github/workflows/publish-images.yml` on every release tag, with `:edge`
tracking `main`. For production, pin by digest rather than by tag — a floating
tag means the thing that runs your agents can change without a deploy.

---

## Verifying the install

There is no `--version` flag; the version is a subcommand.

```console
$ cloop version
cloop dev
Go go1.26.3 linux/amd64
```

The second line reports the Go toolchain the binary was built with, which is
what you want when a bug report has to be reproduced.

`cloop doctor` is the broader check. Run outside a project it verifies the
environment; run inside one it also checks the state database's integrity, the
config file, and whether the YAML config and its SQLite mirror still agree.

```console
$ cloop doctor
cloop doctor — environment health check

  [WARN] .cloop/ directory                    .cloop/ directory not found — project may not be initialized
         fix: Run: cloop init "<your goal>"
  [WARN] .cloop/state.json                    state.json not found — no session has been run yet
         fix: Run: cloop run to start a session
  [PASS] Go binary                            go version go1.26.3 linux/amd64
  [PASS] claude binary (claudecode provider)  claude CLI binary found in PATH
  [WARN] config validate: config.yaml         config file not found — using defaults
  [PASS] .cloop/ disk usage                   .cloop/ directory uses 0.0 MB

Result: 3 passed, 3 warnings, 0 failed

Tip: run 'cloop doctor --providers' to also test live provider connectivity.
```

Those warnings are the expected result in an empty directory — they are telling
you there is no project here yet, which is true. Exit status is 1 only if
something **fails**; warnings exit 0, so `cloop doctor` is usable as a CI gate
without tuning it first. `--providers` adds a live connectivity test per
configured provider, which is slower and costs a token or two.

`cloop hub doctor` is a different command with a different question — it audits
a *hosted* hub's configuration (issuer discovery, TLS material, RBAC, sealing
key) and is documented in the [runbook](../operations/runbook.md).

---

## Shell completion

Completions are generated by the binary for **bash**, **zsh**, **fish** and
**PowerShell**. They cover subcommands and flags, and dynamic values such as
provider names, template names and the task IDs that currently exist in the
project you are standing in.

For the current session:

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

`cloop completion <shell> --help` prints the same instructions for that shell,
which is the copy that stays correct if these ever diverge.

---

**Next:** [Your first project](first-project.md) — from an empty directory to a
task plan the AI has executed.
