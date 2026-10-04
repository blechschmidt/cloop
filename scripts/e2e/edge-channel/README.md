# Live check: the edge channel on a device

The package suites prove the edge channel against stand-ins: a cosign that
decides by signer (`internal/cosigntest`), a staged device (`internal/edgetest`),
an edge release served by httptest. This kit proves it against the real things:
a build that `.github/workflows/edge.yml` published and Sigstore signed, the
device's real cosign and its network path to GitHub and Sigstore, the hardened
unit, and the root helper (`<service>-upgrade.path`/`.service`) running under
systemd. It was written for, and first run in, Task 20376 against sgx.

## What it checks

| step | expected |
| --- | --- |
| a hub stamped as a commit CI has **not** published yet | the device's card: no target; the note says why ("CI is still running on it", with the run) |
| the same hub once `edge.yml` has published the commit | target `edge:<full sha>`, label `this hub's build (<short>)` |
| `POST /api/executors/<id>/upgrade` with that target | 200, accepted; the agent files `upgrade-request.json`; the helper's journal shows the download, two signature checks against the edge identity, the identify step, the swap and the restart |
| the device reconnects | `agent_version` is `dev+g<short>`; `cloop-<svc>.prev` is the build it replaced; the drop-ins are byte-identical |
| the same target for a device installed `--channel stable` | **409**, naming `--channel edge` and that the hub cannot change it |

## The rig

Never through a production hub: run a hub of its own, stamped as a commit that
CI publishes, with its own `HOME`, `CLOOP_HOME`, workdir, port and a dashboard
token (`cloop ui` binds all interfaces), and reach it from the device over
`ssh -R` so the agent dials loopback. On the device, install the agent as a
**second service** — its own unit, state directory and helper — so the
production agent is never touched; since Task 20376 an agent identifies its own
install from its cgroup, so the two do not answer for each other.

```bash
# on the hub's host: a hub that claims to be <short>, and a device build that
# knows the channel but is not that commit
git archive <commit> | tar -x -C src && cd src
go build -ldflags "-X github.com/blechschmidt/cloop/pkg/version.Version=dev+g<short>" -o ../cloop-hub .
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/blechschmidt/cloop/pkg/version.Version=dev+gdeadbee" -o ../cloop-dev .

env -i PATH=$PATH HOME=$RIG/home CLOOP_HOME=$RIG/cloophome cloop-hub init --provider mock --skip-clarify "edge rig"
env -i PATH=$PATH HOME=$RIG/home CLOOP_HOME=$RIG/cloophome CLOOP_UI_TOKEN=$TOKEN cloop-hub ui --port 18376 --no-browser &
env -i ... cloop-hub executor enroll --name sgx-edge --server ws://127.0.0.1:18376/api/executors/connect --bundle-file bundle
ssh -N -R 18376:127.0.0.1:18376 device &

# on the device: cosign first (every build is verified with it), then the second service
install -m 0755 cosign-linux-amd64 /usr/local/bin/cosign
install -m 0755 cloop-dev /usr/local/bin/cloop-edge
CLOOP_ENROLL_BUNDLE=$(cat bundle) cloop-edge executor agent install --service-name cloop-edge \
  --user cloop-executor --group cloop-executor --binary /usr/local/bin/cloop-edge --channel edge
journalctl -u cloop-edge | grep -E 'updates:|remote upgrade'   # "updates: edge channel", no "unavailable"

# the dashboard's view, and the upgrade
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:18376/api/executors
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"target_version":"edge:<full sha>"}' http://127.0.0.1:18376/api/executors/<id>/upgrade
journalctl -u cloop-edge-upgrade     # on the device
```

`env -i` matters: an agent running here inherits `CLOOP_SECRET_KEY` and the
Claude variables from the hub service it is a child of, and a test hub that
picks them up is not the hub you think it is.

To press the button rather than call the API, `../device-features/drive.js`
has `upgrade-dialog <executor-id>` (report the dialog, cancel) and
`upgrade <executor-id>` (accept what it offers, report the toast).

## The first run (Task 20376, sgx)

- The rig's agent, installed as `cloop-t20376` beside the production
  `cloop-executor`, reported the production unit's helper as missing: an agent
  described the *default* install whoever asked, and would have filed its
  request where the production helper acts on it. Fixed in 9de6d04 — an agent
  is the unit in its cgroup whose ExecStart runs its own binary as an agent.
- With the hub stamped `dev+g9de6d04` before CI had published it, the card said
  "CI has not published commit 9de6d04 yet: CI is still running on it" with the
  run. Once `edge.yml` had, the dialog read *Upgrade sgx-t20376 to this hub's
  build (9de6d04)?* with `edge:9de6d04…` prefilled.
- Accepting it: the agent filed the request at 21:46:29; the helper had
  downloaded the manifest and the archive, verified both, identified the binary
  (`dev+g9de6d04`, protocol v17), swapped it, restarted the agent and seen it
  come back by 21:46:35; the hub showed `dev+g9de6d04`, skew none.
  `cloop-t20376.prev` held the replaced build, both drop-ins were
  byte-identical, CapEff stayed `0x1000`.
- `--channel stable` on the device, then the same target: **409**, force or
  not. The same target written straight into `upgrade-request.json` as the
  agent's user: the helper refused it from `systemctl show`, deleted the
  request and left the binary alone.
- A real `edge.yml` signature: the certificate's SAN is exactly
  `https://github.com/blechschmidt/cloop/.github/workflows/edge.yml@refs/heads/main`;
  `cosign verify-blob` accepts it under `EdgeIdentityRegexp` and refuses it
  under the release identity.
- `workflow_run` runs are filed under main's head when they start, so the run
  that built 9de6d04 was listed under the next commit; the hub now finds it by
  its title, `Edge build of <commit>`.

Tear down with `cloop-edge executor agent install --uninstall --purge
--service-name cloop-edge` on the device (it disarms the helper first and
removes both of its units), `rm /usr/local/bin/cloop-edge*`, then stop the
tunnel and the hub.
