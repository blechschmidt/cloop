# Following the hub's build: the edge channel

A hub that deploys `main` speaks a newer executor protocol than any published
release. Devices only install **signed** builds: the hub names a version, and
the device fetches and verifies it. The hub never sends the binary. Before the
edge channel, every protocol bump left the fleet behind until someone
hand-built a static binary, copied it to each device and installed it with
`--insecure-skip-verify`.

The **edge channel** provides signed builds of `main`. After CI passes on a
commit, the [`edge.yml`](https://github.com/blechschmidt/cloop/blob/main/.github/workflows/edge.yml)
workflow builds that commit for every release platform, signs it and publishes
it. A device whose operator has put it on the edge channel can then be
upgraded to **this hub's build** from the Executors panel or by the fleet
auto-update policy, verified the same way as a release.

---

## What CI publishes

`edge.yml` runs after every completed run of the **CI** workflow. It builds
only if that run passed, was triggered by a push to `main` of this repository,
and the commit is an ancestor of `main`. It never builds pull requests,
including one from a fork's branch that happens to be called `main`.

For a commit that qualifies, it runs [`scripts/build-edge.sh`](https://github.com/blechschmidt/cloop/blob/main/scripts/build-edge.sh).
The script builds the same binaries as [`scripts/build-release.sh`](https://github.com/blechschmidt/cloop/blob/main/scripts/build-release.sh)
and stamps them with two values: the version `dev+g<first seven digits>`
(the version the hub's own deploy gives the same commit) and the commit's
**sequence**, its place on `main` (see [rollback protection](#rollback-protection)).
It writes these assets:

| Asset | What it is |
| --- | --- |
| `cloop_<commit>_<os>_<arch>.tar.gz` | one per release platform (linux amd64/arm64/arm, darwin amd64/arm64) |
| `cloop_<commit>_manifest.v2.json` | schema 2: `{schema, commit, version, protocol, sequence, archives: {name: sha256}, built_at, run}` |
| `cloop_<commit>_manifest.json` | schema 1: the same without `sequence`, for devices whose cloop predates it |
| `<asset>.sigstore.json` | a Sigstore bundle for every archive and for both manifests |

The manifest's `protocol` comes from the built binary (`cloop version --json`),
not from the source, so it is the protocol the binary will negotiate. The same
goes for `commit` and `sequence`: the script checks that the binary reports the
values it counted.

The schema-1 manifest is for devices running a build from before sequences,
which read only schema 1, only under that file name. Such a device installs its
first sequenced build from it and reads the schema-2 manifest from then on. A
current build reads the schema-2 manifest, and the schema-1 manifest only for a
build that predates schema 2. Each file name must carry its own schema.

Everything is attached to one prerelease tagged `edge`:

- **It is never marked latest.** `cloop upgrade`, the bootstrap installer and
  the hub's "latest" lookup only ask for `/releases/latest`, so none of them
  sees it. After every publish, the workflow checks that latest is still a
  `v*` release.
- **Its tag is never moved.** The first publish created the tag at that run's
  commit, and nothing moves it afterwards. Every asset has its commit in its
  name, so where the tag points doesn't matter, and moving a tag would
  rewrite history for everyone who fetched it.
- **It keeps the builds of the newest 30 commits** on `main`
  ([`scripts/edge-prune.py`](https://github.com/blechschmidt/cloop/blob/main/scripts/edge-prune.py)),
  ranked by their place in `main`'s history, not by upload time. For older
  builds, use a release.

---

## The trust root

Edge builds are signed with Sigstore keyless signing, like releases, and
verification pins the signer's identity. Releases and edge builds have separate
pins:

| Channel | Signed by | Pinned identity (`pkg/provenance`) |
| --- | --- | --- |
| stable (releases) | `release.yml` on a tag | `DefaultIdentityRegexp`: `^https://github\.com/blechschmidt/cloop/\.github/workflows/release\.yml@refs/tags/v[^/]+$` |
| edge | `edge.yml` on `main` | `EdgeIdentityRegexp`: `^https://github\.com/blechschmidt/cloop/\.github/workflows/edge\.yml@refs/heads/main$` |

Both require the issuer `https://token.actions.githubusercontent.com`.

- A **release target** (`v0.0.4`, `latest`) is verified against the release
  identity only. An edge signature never passes for a release.
- An **edge target** (`edge:<commit>`) is verified against the edge identity
  only. None of these satisfy it: a release signature, `edge.yml` run from any
  other branch, a tag or a pull request's merge ref, any other workflow on
  `main`, or a fork.
- The device decides which pin applies, based on the kind of target it
  resolved. Nothing the hub sends selects an identity.

A signature proves that `edge.yml` built some commit. Three more checks tie the
bytes to the commit that was requested. An attacker who can replace release
assets, but cannot get `edge.yml` on `main` to sign them, can at most make an
upgrade fail:

1. The manifest is verified first and must name the requested commit. A
   genuine manifest for another commit, uploaded under this commit's name, is
   refused.
2. Each archive must hash to the value the verified manifest lists for it, and
   must carry its own valid signature. An older genuine archive swapped in
   under a newer commit's name fails the hash check.
3. Before it replaces anything, the installer runs the extracted binary and
   requires it to report the manifest's version, commit and sequence. A validly
   signed manifest for one commit paired with a binary of another is refused,
   and there is no override.

A signature can't tell whether a build is newer than the one a device runs,
because every retained edge build is validly signed. The sequence covers that.

A fork that publishes its own edge channel sets the pin with
`CLOOP_PROVENANCE_EDGE_IDENTITY`. It is separate from
`CLOOP_PROVENANCE_IDENTITY`, so changing one never changes the other.

---

## Rollback protection

Every release and edge build is stamped with its **sequence**, the
first-parent position of its commit on `main`:

```bash
git rev-list --count --first-parent <commit>
```

The count is taken on a full-depth checkout: `build-release.sh` and
`build-edge.sh` refuse a shallow one. `edge.yml` builds only commits on
`main`'s first-parent history, where the count is a position. `cloop version`
prints the sequence (`built from <commit>, sequence N on main`), and
`cloop version --json` reports `commit` and `sequence`. A release is stamped
with its tagged commit's sequence, so moving from a release to an edge build,
or back, is ordered too.

The installer on the device refuses a staged build whose sequence is lower
than the installed binary's. It reads both sequences from the binaries
themselves, never from the upgrade request or the agent:

| Installed build | Staged build | Outcome |
| --- | --- | --- |
| sequence 4150 | sequence 4160 | installed, logged as a move forward |
| sequence 4150 | sequence 4150 | the same commit: allowed (a reinstall, or a release of that commit) |
| sequence 4150 | sequence 4100 | **refused** with `install: refusing to install an older build` |
| sequence 4150 | no sequence (any build from before the stamp, e.g. v0.0.4) | **refused**, because every signed build since then carries one |
| no sequence (the bootstrap) | anything | allowed, with a journal line; the device enforces the order from then on |

**Who can override it:** only root on the device, by passing `--force` to
`cloop executor agent install --upgrade --to <target>` (or `--from <binary>`).
The request the agent files for the root helper has a `force` flag, and so
does the hub's upgrade frame, but neither one gets past this check, and
`--apply-request --force` is refused outright. A compromised agent, a workload
running as the agent's user, or a compromised hub can still ask for an older
signed build. The helper refuses it and logs this in
`journalctl -u cloop-executor-upgrade.service`:

```text
refused: … would move this device back on main from dev+g4453c68 (sequence 4150 on main)
to dev+ga0f3870 (sequence 4100 on main); only root on the device can do that
(install --upgrade --force), not the hub or the agent
```

The hub applies the same order. Each device reports its build's sequence in its
hello (`build_sequence`). The Executors panel shows it as a **seq N** chip, and
`cloop executor list --inventory` lists it. The Upgrade dialog,
`POST /api/executors/{id}/upgrade` and the auto-update policy never offer or
send an earlier build, and the API answers 409 whatever `force` says.

`cloop hub doctor` warns (`executors.edge_lag`) about an edge-channel device
more than 20 sequences behind the hub's own build, and about one whose build
has no sequence yet, which rollback protection doesn't cover until its first
upgrade. Its `executors.rollback_protection` check warns about a device whose
build has no sequence (every release before v0.0.5 and any binary built by
hand) and that follows releases: one on the stable channel, or too old to
report a channel. The device's card in the Executors panel shows the same
warning with the fix: the Upgrade button if the agent can carry out an
upgrade. Otherwise, run `cloop upgrade` once on the device as root (it fetches
the latest release and verifies its signature), then
`cloop executor agent install --upgrade --remote-upgrade` (it restarts the
agent on the new build and installs the helper the button needs).

---

## Putting a device on the edge channel

Root on the device chooses the channel. The hub can read a device's channel,
but it cannot set or clear it.

A new device can join the channel when you enroll it. When the hub runs a build
that CI has published, the Executors panel's one-command installer ends in
`install.sh --channel edge`. The bootstrap script then installs that build,
verified against the edge workflow's identity, with the agent on the edge
channel. You can drop the flag from the command to install the latest release
instead
([installing the agent as a service](../architecture/executors.md#installing-the-agent-as-a-service)).
A device that is already enrolled opts in like this:

```bash
# On the device — cosign first: every build is verified with it.
sudo install -m 0755 cosign-linux-amd64 /usr/local/bin/cosign

sudo cloop executor agent install --upgrade --channel edge
```

`--channel edge` writes a drop-in next to the agent's unit and restarts the
agent so that it picks the setting up:

```ini
# /etc/systemd/system/cloop-executor.service.d/20-update-channel.conf
[Service]
Environment=CLOOP_UPDATE_CHANNEL=edge
```

Like the packet-filter grant (`10-packet-filter.conf`), the setting is a
drop-in so that upgrades keep it: an upgrade replaces the binary and never
rewrites the unit. `--channel stable` removes it. The agent reports its channel
in its hello, and its banner shows which channel it follows:

```text
  firewall: nft(8) — CAP_NET_ADMIN held by the agent, never by its workloads
  updates: edge channel — releases, and signed builds of main
```

### The remote-upgrade helper

`--channel edge` also installs the **remote-upgrade helper**, unless you pass
`--remote-upgrade=false`. A fresh install gets the helper by default, and
`sudo cloop executor agent install --upgrade --remote-upgrade` adds it to any
device. On a hardened device, the Upgrade button doesn't work without it.

The agent runs as an unprivileged system user with a read-only filesystem and
no way to gain privileges. It can't replace `/usr/local/bin/cloop`, which root
owns, and it can't restart its own unit. When the hub asks it to upgrade, it
writes the requested version to `/var/lib/cloop-executor/upgrade-request.json`,
and two root units do the rest:

| Unit | Does |
| --- | --- |
| `cloop-executor-upgrade.path` | starts the service when a request appears |
| `cloop-executor-upgrade.service` | runs as root, oneshot: takes and deletes the request, checks the target against the device's channel, fetches it from the pinned repository, verifies it, and installs it the way `cloop executor agent install --upgrade` does |

The request holds a version, a force flag, a settle time and a reason: the same
fields as the hub's upgrade frame. It can't name a URL, a file or a signing
identity, so anything that can write it (the agent, or a workload running as
the agent's user) can ask for no more than the hub can. The helper reads the
channel from systemd's view of the agent's unit
(`systemctl show --property=Environment`), never from the request, and it
ignores a request older than 15 minutes. Its unit runs as root but confined: it
can write only to the binary's directory, the request's directory and its own
state directory (cosign's cache).

A device refuses an upgrade, and says why, if it has no helper and its agent
doesn't run as root. It also refuses if cosign is missing, or if the helper is
installed but `cloop-executor-upgrade.path` isn't active, because a request
would then sit unread in the state directory. That error names
`sudo systemctl enable --now cloop-executor-upgrade.path`. The device reports
the problem when it connects, and the dialog shows it as a warning next to the
target, not in place of it. Because that report is as old as the connection,
clicking Upgrade asks the device again, and it answers from a fresh check. Fix
the cause on the device; the agent doesn't need a restart.

The request's settle time is at most 600 seconds (the helper's unit allows
itself 15 minutes in total), and the agent refuses a longer one before it
acknowledges anything. The helper of agent `<name>` is `<name>-upgrade`, so you
can't install a new agent under a service name that ends in `-upgrade`.

### A device whose cloop predates the channel

A device running a cloop build from before `--channel` existed can't run that
command until it has a newer build, and you have to install that first build by
hand, once. Use a verified edge build for it, not a hand-built binary:

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

`--to` fetches a published build (a release tag, `latest`, or `edge:<commit>`
on an edge-channel device) instead of installing the binary that runs the
command. After this, you can upgrade the device from the dashboard.

---

## Upgrading from the dashboard

For a device on the edge channel, the **Upgrade** dialog in the Executors panel
offers **this hub's build (`<short commit>`)**, with the target
`edge:<full commit>`, once CI has published it. The device fetches and verifies
the build itself, files the request for the helper, and reconnects on the new
build. As with any upgrade, the reconnection is the confirmation.

The hub never offers a build that would lower the device's protocol or that
is earlier on `main` than the device's build. It reads both from the build's
manifest without verifying it, because it only decides what to offer. The
device verifies everything, and its installer separately refuses a binary that
speaks an older protocol than the one it replaces or comes earlier on `main`.

When the hub's build isn't offered, the dialog shows the reason in its place:

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
| … runs a build at sequence 4200 on main, and this hub's build … is sequence 4150 on main | the device is later on `main` than the hub and would refuse the hub's build | upgrade the hub |
| this build … was made from a tree with uncommitted changes | the hub was built from a dirty tree | build the hub from a commit |

The hub looks this up on GitHub and caches the answer as it does for "latest":
a published build for 10 minutes, any other answer for 5, and a failed lookup
not at all. GitHub's unauthenticated API allows 60 requests an hour, and after
the first commit lookup a published build uses none of them, because the
manifest is a plain download.

`POST /api/executors/{id}/upgrade` accepts `edge:<commit>` (7 to 40 hex
digits). For an edge-channel device, the hub's own version string
(`dev+ga0f3870`) also means its edge build. The endpoint answers **409** when:

- the device is on the stable channel (the error includes the command that
  changes that);
- the build would lower the device's protocol, unless the request sets `force`;
- the build, edge or release, is earlier on `main` than the device's, whatever
  `force` says, because the device would refuse it anyway.

### Auto-update

When the fleet auto-update policy's target is empty ("match the hub"), devices
on the edge channel move to the hub's edge build under the same rules as for
releases: never while a device runs work, never more than `max_in_flight` at
once, never a cordoned device, never to a lower protocol, and never to an
earlier build on `main`. A device on the stable channel is skipped, and the
policy gives the reason. A pinned release reaches devices on either channel. A
pinned `edge:<commit>` other than the hub's own is refused, because the hub can
judge the protocol of its own build but not of an arbitrary commit.

---

## Rolling back

Every upgrade keeps the binary it replaced at `/usr/local/bin/cloop.prev`, and
restores it automatically if the agent doesn't come back within the settle
window (30 s by default). To roll back by hand:

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

Moving to an older build or a lower protocol needs `--force`, here as
everywhere else. Moving back on `main` needs this `--force`, run as root on the
device. The dashboard's Upgrade button and the auto-update policy can't do it,
with or without `force` (see [rollback protection](#rollback-protection)).

A release older than the channel, such as v0.0.4, knows neither the channel nor
the helper, and its agent doesn't file requests. On a device rolled back to it,
an upgrade from the Upgrade button is accepted and then fails in the device's
journal, and the helper units left behind would start a binary that has no
`--apply-request`. Upgrade such a device locally until it runs a build that
knows the channel again. To leave nothing behind, take the device off the
channel and remove the helper before you roll back
(`sudo cloop executor agent install --upgrade --channel stable --remote-upgrade=false`).

---

## Limits

An edge build promises less than a release:

- **An edge build has passed CI on `main`, and that is all.** Nobody decided to
  release it, there are no release notes, and any regression CI doesn't catch
  is in it.
- **Anyone who can push to `main` can change what `edge.yml` builds.** The
  pinned identity doesn't protect against them. It protects against people who
  can't push to `main` but can replace release assets, push a branch, open a
  pull request or run another workflow.
- **The hub's own build, by default.** The dialog and the auto-update policy
  offer the commit the hub runs. You can type another published commit's
  `edge:<commit>` into the dialog, and the hub checks its manifest the same
  way. The policy follows only the hub's build. Builds older than the newest 30
  commits are deleted.
- **systemd devices only.** The channel and the helper are a drop-in and
  units, and an `--output shell` install has neither. An agent running as root
  can still upgrade itself in place.
- **A device needs cosign** on the default `PATH`, and network access to
  GitHub and Sigstore. A device without cosign says so in the dialog.
- **The hub's version must name a clean commit.** A hub built from a dirty tree
  or without VCS data (`dev`) has no edge build.
- **The short commit is matched by prefix.** The deploy stamps
  `git log --format=%h` and CI stamps seven digits. Both name the same commit,
  and the hub treats them as the same build.
- **The order is `main`'s first-parent history.** A release tagged on a commit
  outside `main` carries its own branch's count (the release workflow warns
  about this). Rewriting `main`'s history would renumber it, so `main` is never
  force-pushed, and neither is any tag.

---

## See also

- [Executor architecture: upgrading a device](../architecture/executors.md#upgrading-a-device)
- [Security model: release provenance and the trust root](../security/model.md#release-provenance-and-the-trust-root)
- [Operator runbook: moving a device onto the edge channel](../operations/runbook.md#moving-a-device-onto-the-edge-channel)
