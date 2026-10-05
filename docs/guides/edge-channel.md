# Following the hub's build: the edge channel

A hub that deploys `main` speaks a newer executor protocol than any published
release. Devices can only be moved onto a **signed** build — the hub names a
version, the device fetches and verifies it, and the hub never supplies bytes —
so until the edge channel existed every protocol bump stranded the fleet until
someone hand-built a static binary, copied it to each device and installed it
with `--insecure-skip-verify`.

The **edge channel** is the signed artifact for `main`. After CI passes on a
commit, the [`edge.yml`](https://github.com/blechschmidt/cloop/blob/main/.github/workflows/edge.yml)
workflow builds that commit for every release platform, signs it, and
publishes it. A device whose operator puts it on the edge channel can then be
upgraded to **this hub's build** from the Executors panel, or by the fleet
auto-update policy, with the same verification a release gets.

This page covers what CI publishes and how it is trusted, how a device opts
in, upgrading from the dashboard, and the channel's limits.

---

## What CI publishes

`edge.yml` runs after every completed run of the **CI** workflow and does
nothing unless that run **passed**, was a **push to `main`** of this
repository, and the commit is an ancestor of `main`. Pull requests — including
a fork's branch that happens to be called `main` — are never built.

For a commit that qualifies it runs [`scripts/build-edge.sh`](https://github.com/blechschmidt/cloop/blob/main/scripts/build-edge.sh),
which builds exactly what [`scripts/build-release.sh`](https://github.com/blechschmidt/cloop/blob/main/scripts/build-release.sh)
builds, stamped `dev+g<first seven digits>` — the version the hub's own
deploy gives the same commit — and with the commit's **sequence**, its place on
`main` ([rollback protection](#rollback-protection)), and writes:

| Asset | What it is |
| --- | --- |
| `cloop_<commit>_<os>_<arch>.tar.gz` | one per release platform (linux amd64/arm64/arm, darwin amd64/arm64) |
| `cloop_<commit>_manifest.v2.json` | schema 2: `{schema, commit, version, protocol, sequence, archives: {name: sha256}, built_at, run}` |
| `cloop_<commit>_manifest.json` | schema 1: the same without `sequence`, for devices whose cloop predates it |
| `<asset>.sigstore.json` | a Sigstore bundle for every archive and for both manifests |

The manifest's `protocol` is read from the built binary (`cloop version
--json`), not from the source, so it is what the binary will negotiate; so are
its `commit` and `sequence`, which the script requires the binary to report
exactly as it counted them.

The schema-1 manifest is kept for one reason: a device running a build from
before sequences reads exactly schema 1 at exactly that name, and refuses
anything else. It installs the new build from it — its first sequenced build —
and reads the schema-2 manifest from then on. Without it, every such device
would have been stranded off the channel by the change that added the sequence.
A current build reads the schema-2 manifest, and the schema-1 one only for a
build that predates it; each name must carry its own schema.

Everything is attached to **one prerelease tagged `edge`**:

- It is **never marked latest.** `cloop upgrade`, the bootstrap installer and
  the hub's "latest" lookup only ever ask for `/releases/latest`, so none of them
  can see it; the workflow checks after every publish that latest is still a
  `v*` release.
- Its **tag is never moved.** The first publish creates it at whatever commit
  that was, and nothing touches it again: every asset carries its commit in its
  name, so where the tag points is immaterial, and a moved tag rewrites history
  for everyone who fetched it.
- It keeps the builds of the **newest 30 commits** on `main`
  ([`scripts/edge-prune.py`](https://github.com/blechschmidt/cloop/blob/main/scripts/edge-prune.py)),
  ranked by their place in `main`'s history rather than by upload time. A build
  from months ago is not something "follow the hub" should reach; that is what
  releases are for.

---

## The trust root

Builds are signed with Sigstore keyless signing, like releases, and
verification pins the signer. There are **two pins, kept apart**:

| Channel | Signed by | Pinned identity (`pkg/provenance`) |
| --- | --- | --- |
| stable (releases) | `release.yml` on a tag | `DefaultIdentityRegexp`: `^https://github\.com/blechschmidt/cloop/\.github/workflows/release\.yml@refs/tags/v[^/]+$` |
| edge | `edge.yml` on `main` | `EdgeIdentityRegexp`: `^https://github\.com/blechschmidt/cloop/\.github/workflows/edge\.yml@refs/heads/main$` |

Both require the issuer `https://token.actions.githubusercontent.com`.

- A **release target** (`v0.0.4`, `latest`) is verified against the release
  identity only. An edge signature does not make anything a release.
- An **edge target** (`edge:<commit>`) is verified against the edge identity
  only. A release signature does not satisfy it, and neither does `edge.yml` run
  from any other branch, from a tag or from a pull request's merge ref, any other
  workflow on `main`, or a fork.
- Which pin applies is decided **by the device**, from the kind of target it
  resolved. Nothing the hub sends selects an identity.

A signature proves that `edge.yml` built *a* commit. Three more checks bind the
bytes to *the* commit that was asked for, so an attacker who can replace release
assets but cannot make `edge.yml` on `main` sign for them can, at most, make an
upgrade fail:

1. The manifest is verified first and must name exactly the requested commit.
   A genuine manifest of another commit, uploaded under this one's name, is
   refused.
2. Each archive must hash to what the verified manifest lists for it, and
   carry its own valid signature. An older genuine archive swapped in under a
   newer commit's name fails the hash.
3. The installer runs the extracted binary and requires it to report the
   manifest's version, commit and sequence before it replaces anything — a
   validly signed manifest for one commit paired with a binary of another is
   refused, and nothing overrides that.

A signature cannot say whether a build is *newer* than the one a device runs:
every retained edge build is genuinely signed. That is the sequence's job.

A fork that publishes its own edge channel repoints the pin with
`CLOOP_PROVENANCE_EDGE_IDENTITY` — a separate variable from
`CLOOP_PROVENANCE_IDENTITY`, so repointing one never moves the other.

---

## Rollback protection

Every release and edge build is stamped with its **sequence**: its commit's
first-parent position on `main`,

```bash
git rev-list --count --first-parent <commit>
```

counted on a full-depth checkout (`build-release.sh` and `build-edge.sh` refuse a
shallow one, and `edge.yml` builds only commits on `main`'s first-parent
history, where the count is a position). `cloop version` prints it
(`built from <commit>, sequence N on main`) and `cloop version --json` reports
`commit` and `sequence`. A release is stamped with its tagged commit's sequence,
so a move from a release to an edge build, or back, is ordered too.

The device's installer refuses a staged build whose sequence is lower than the
installed binary's — reading both from the binaries themselves, never from the
upgrade request or the agent:

| Installed build | Staged build | Outcome |
| --- | --- | --- |
| sequence 4150 | sequence 4160 | installed, logged as a move forward |
| sequence 4150 | sequence 4150 | the same commit: allowed (a reinstall, or a release of that commit) |
| sequence 4150 | sequence 4100 | **refused** — `install: refusing to install an older build` |
| sequence 4150 | no sequence (any build from before the stamp, e.g. v0.0.4) | **refused** — every signed build since carries one |
| no sequence (the bootstrap) | anything | allowed, with a journal line; the device enforces the order from then on |

**Who can override it:** only root on the device, with `--force` on an
operator's own `cloop executor agent install --upgrade --to <target>` (or
`--from <binary>`). The request the agent files for the root helper carries a
`force` flag, and so does the hub's upgrade frame; neither reaches this refusal,
and `--apply-request --force` is refused outright. So a compromised agent, a
workload running as the agent's user, or a compromised hub can still ask for an
older signed build — and the helper refuses it, logging

```text
refused: … would move this device back on main from dev+g4453c68 (sequence 4150 on main)
to dev+ga0f3870 (sequence 4100 on main); only root on the device can do that
(install --upgrade --force), not the hub or the agent
```

in `journalctl -u cloop-executor-upgrade.service`.

The hub follows the same order: each device reports its build's sequence in its
hello (`build_sequence`, shown as a **seq N** chip in the Executors panel and by
`cloop executor list --inventory`), and
the Upgrade dialog, `POST /api/executors/{id}/upgrade` and the auto-update
policy never offer or send a build earlier than it — 409, whatever `force` says.
`cloop hub doctor` warns (`executors.edge_lag`) about a device on the edge
channel more than 20 sequences behind the hub's own build, and about one whose
build carries no sequence yet, which rollback protection does not cover until it
has been upgraded once.

---

## Putting a device on the edge channel

The choice is made **on the device, by root**. The hub can read a device's
channel; it has no way to set or clear it.

```bash
# On the device — cosign first: every build is verified with it.
sudo install -m 0755 cosign-linux-amd64 /usr/local/bin/cosign

sudo cloop executor agent install --upgrade --channel edge
```

`--channel edge` writes one drop-in beside the agent's unit and restarts the
agent so it starts with it:

```ini
# /etc/systemd/system/cloop-executor.service.d/20-update-channel.conf
[Service]
Environment=CLOOP_UPDATE_CHANNEL=edge
```

Like the packet-filter grant (`10-packet-filter.conf`), it is a drop-in so
that an upgrade keeps it: an upgrade replaces the binary and never re-renders
the unit. `--channel stable` removes it. The agent reports its channel in its
hello, and its banner says which it follows:

```text
  firewall: nft(8) — CAP_NET_ADMIN held by the agent, never by its workloads
  updates: edge channel — releases, and signed builds of main
```

### The remote-upgrade helper

`--channel edge` also installs the **remote-upgrade helper**, unless told
`--remote-upgrade=false`; a fresh install gets it by default, and
`sudo cloop executor agent install --upgrade --remote-upgrade` adds it to any
device. It is what lets the Upgrade button work at all on a hardened device.

The agent runs as an unprivileged system user with a read-only filesystem and
no way to gain privilege. It cannot replace `/usr/local/bin/cloop`, which is
root's, and cannot restart its own unit. So when the hub asks it to upgrade,
it writes the version it was asked for to
`/var/lib/cloop-executor/upgrade-request.json`, and two root units do the rest:

| Unit | Does |
| --- | --- |
| `cloop-executor-upgrade.path` | starts the service when a request appears |
| `cloop-executor-upgrade.service` | root, oneshot: takes and deletes the request, checks the target against the device's channel, fetches it from the pinned repository, verifies it, installs it with `cloop executor agent install --upgrade` semantics |

The request names a version, a force flag, a settle time and a reason — what
the hub's upgrade frame names, and nothing more. It cannot name a URL, a file
or a signing identity, so whatever can write it (the agent, or a workload
running as its user) can ask for exactly what the hub can. The helper decides
the channel from systemd's view of the agent's unit (`systemctl show
--property=Environment`), never from the request, and ignores a request older
than 15 minutes. Its unit runs as root but confined: it may write only the
binary's directory, the request's, and its own state directory (cosign's cache).

A device without the helper, whose agent is not root, now **refuses** an
upgrade and says why, where it used to accept and then fail where nobody
looked. The same goes for a device with no cosign, and for one whose helper is
installed but not armed — `cloop-executor-upgrade.path` is not active, so a
request would sit in the state directory unread; the refusal names
`sudo systemctl enable --now cloop-executor-upgrade.path`. The device says
which when it connects, and the dialog shows that as a warning beside the
target rather than in its place: what the device said is as old as its
connection, so Upgrade asks again and the device answers from a check it runs
then. Fixing the cause on the device is enough; the agent need not restart.

The request's settle time is at most 600 seconds — the helper's unit gives
itself 15 minutes in all — and the agent refuses a longer one before it
acknowledges anything. `<name>-upgrade` is the helper of the agent `<name>`, so
a new agent may not be installed under a service name ending in `-upgrade`.

### A device whose cloop predates the channel

`--channel` is new. A device running an older cloop cannot run that command
until it has a build that knows it, and the first such build has to be
installed by hand — once. Do it with a verified edge build rather than a
hand-built binary:

```bash
# On the device. <commit> is the full commit id of a build CI has published;
# the Executors panel's Upgrade dialog names the hub's.
c=<commit>
base=https://github.com/blechschmidt/cloop/releases/download/edge
curl -fsSLO "$base/cloop_${c}_linux_amd64.tar.gz"
curl -fsSLO "$base/cloop_${c}_linux_amd64.tar.gz.sigstore.json"
cosign verify-blob "cloop_${c}_linux_amd64.tar.gz" \
  --bundle "cloop_${c}_linux_amd64.tar.gz.sigstore.json" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/blechschmidt/cloop/\.github/workflows/edge\.yml@refs/heads/main$'
tar -xzf "cloop_${c}_linux_amd64.tar.gz" ./cloop

# The verified binary fetches and verifies the same build itself, installs it,
# and puts the device on the edge channel — with backup, restart and rollback.
sudo ./cloop executor agent install --upgrade --channel edge --to "edge:$c"
```

`--to` fetches a published build — a release tag, `latest`, or on an
edge-channel device `edge:<commit>` — instead of installing the binary that
runs the command. From then on the dashboard moves the device.

---

## Upgrading from the dashboard

On a device that follows the edge channel, the Executors panel's **Upgrade**
dialog offers **this hub's build (`<short commit>`)** — target
`edge:<full commit>` — once CI has published it. The device fetches and
verifies the build itself, files the request for the helper, and reconnects on
the new build; that reconnection is the confirmation, as for any upgrade.

The hub never offers a build that would lower the device's protocol, or one
earlier on `main` than the device's build: it reads both from the build's
manifest. (It reads the manifest without verifying it, because what it decides
is only what to offer; the device verifies everything, and its installer
independently refuses a binary that speaks less than the one it replaces or sits
earlier on `main`.)

When the hub's build is not offered, the dialog says why, in place of the
offer:

| The dialog says | Because | Remedy |
| --- | --- | --- |
| the deploy built commit … which is not on GitHub | the hub runs a commit nobody pushed | push it to `main` |
| no CI run on main exists for commit … | it is not on `main`, or was pushed together with newer commits (CI runs only for the newest commit of a push) | push again, or wait for the next deploy |
| CI has not published commit … yet: CI is still running on it | CI is in progress | wait |
| CI passed … the edge workflow is building and signing it | `edge.yml` is running | wait |
| CI failed on commit … | CI failed, so nothing was published | fix `main` |
| … the edge workflow that publishes it failed | `edge.yml` failed | re-run it from the Actions tab |
| … has since been pruned | the hub is older than the newest 30 commits | upgrade the hub |
| it speaks v16, below the device's v17 | the build would lower the device's protocol | upgrade the hub |
| … runs a build at sequence 4200 on main, and this hub's build … is sequence 4150 on main | the device is later on `main` than the hub; it would refuse the hub's build | upgrade the hub |
| this build … was made from a tree with uncommitted changes | a dirty hub build | build the hub from a commit |

The hub resolves this through GitHub and caches the answer like "latest": a
published build for 10 minutes, any other answer for 5, a failure to ask not at
all. GitHub's unauthenticated API allows 60 requests an hour, and a published
build costs none of them after the first commit lookup — the manifest is a
plain download.

`POST /api/executors/{id}/upgrade` accepts `edge:<commit>` (7 to 40 hex
digits), and on an edge-channel device the hub's own version string
(`dev+ga0f3870`) means its edge build. A device on the stable channel is
refused with **409** and the command that would change that; so is a build
that would lower the device's protocol, unless the request sets `force`; and so
is a build — edge or release — earlier on `main` than the device's, **whatever**
`force` says, because the device would refuse it anyway.

### Auto-update

With the fleet auto-update policy's target left empty — "match the hub" — a
device on the edge channel converges on the hub's edge build, under the same
rules as releases: never while it runs work, never more than `max_in_flight`
at once, never a cordoned device, never lower protocol, never earlier on
`main`. A device on the stable
channel is left alone with the reason. A pinned release reaches devices on
either channel; a pinned `edge:<commit>` other than the hub's own is refused,
because the hub can judge the protocol of its own build and not of an
arbitrary commit.

---

## Rolling back

Every upgrade keeps the binary it replaced at `/usr/local/bin/cloop.prev`, and
restores it by itself if the agent does not come back within the settle window
(30 s by default). By hand:

```bash
# Back to the previous binary.
sudo install -m 0755 /usr/local/bin/cloop.prev /usr/local/bin/cloop
sudo systemctl restart cloop-executor

# Or to an earlier edge build or a release, verified, staying on the channel.
sudo cloop executor agent install --upgrade --to edge:<commit> --force
sudo cloop executor agent install --upgrade --to v0.0.4 --force

# Or off the channel: releases only from now on.
sudo cloop executor agent install --upgrade --channel stable
```

`--force` is needed to move to an older build or a lower protocol, here as
anywhere — and moving back on `main` takes *this* `--force`, run as root on the
device: the dashboard's Upgrade and the auto-update policy cannot do it, with or
without `force` ([rollback protection](#rollback-protection)).

A release older than the channel — v0.0.4 is one — knows neither the channel
nor the helper. Its agent does not file requests, so on a device rolled back
to it the Upgrade button is accepted and then fails in the device's journal,
as it did before the helper existed, and the helper units left behind would
start a binary without `--apply-request`. Upgrade such a device on the device
until it runs a build that knows the channel again; to leave nothing behind,
take the device off the channel and remove the helper before rolling back
(`sudo cloop executor agent install --upgrade --channel stable
--remote-upgrade=false`).

---

## Limits

The edge channel is a convenience with a weaker promise than a release, and
the difference is worth stating plainly:

- **"Passed CI on `main`", not "shipped".** Nobody decided to release an edge
  build; there are no release notes, and a regression CI does not catch is in
  it.
- **Anyone who can push to `main` can change what `edge.yml` builds.** The
  identity cannot protect against them — it protects against everyone who
  cannot: someone who can replace release assets, push a branch, open a pull
  request, or run another workflow.
- **The hub's own build, by default.** The dialog and the auto-update policy
  offer the commit the hub runs. An operator can type another published
  commit's `edge:<commit>` into the dialog, and the hub checks its manifest the
  same way; the policy follows only the hub's. Builds older than the newest 30
  commits are gone.
- **systemd devices only.** The channel and the helper are drop-ins and units;
  an `--output shell` install has neither. An agent running as root can still
  upgrade itself in place.
- **A device needs cosign**, on the default `PATH`, and network access to
  GitHub and Sigstore. A device that has neither says so in the dialog.
- **The hub's version must name a clean commit.** A hub built from a dirty tree
  or without VCS data (`dev`) has no edge build.
- **The short commit is matched by prefix.** The deploy stamps
  `git log --format=%h` and CI stamps seven digits; both name one commit, and
  the hub treats them as one build.
- **The order is `main`'s first-parent history.** A release tagged off `main`
  carries its own branch's count (the release workflow warns), and a history
  rewritten on `main` would renumber it — `main` is never force-pushed, and
  neither is any tag.

---

## See also

- [Executor architecture: upgrading a device](../architecture/executors.md#upgrading-a-device)
- [Security model: release provenance and the trust root](../security/model.md#release-provenance-and-the-trust-root)
- [Operator runbook: moving a device onto the edge channel](../operations/runbook.md#moving-a-device-onto-the-edge-channel)
