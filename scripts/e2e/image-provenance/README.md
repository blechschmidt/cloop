# Live check: a device sandbox runs the digest the hub verified

`pkg/executor/remote`'s tests prove the hub resolves cloop's own image at the
registry, verifies the digest and names it in the start frame, against a
stand-in registry and a stand-in cosign; `tests/security`'s
`TestNoSandboxRunsACloopImageByTag` holds every executor to it. This kit proves
it on a real device with the real ones (Task 20453): a test hub with cosign on
its `PATH`, an agent on the device in container mode, and images of cloop's
signed by `.github/workflows/publish-images.yml` — or published before it signed
anything.

The project is a `mock` provider's, so the run needs no model and no
credential: the workload is the published image's own `cloop run`.

## The checks

[`run.sh`](run.sh) prints one `PASS` or `FAIL` line per row and exits non-zero
on any failure.

| step | expected |
| --- | --- |
| `cloop hub verify-image` on the signed tag and on the unsigned one | `verified`, and `unsigned` |
| `image_provenance: required`, the device's image unsigned (`cloop-harness:latest`) | **409** under the `image-provenance` rule naming the setting, and no container created on the device |
| `required`, the device's image signed (`cloop-harness:edge`) | the device creates its sandbox from `repo@<digest>` — the digest the registry serves, asked independently — and from no tag; the run's `.cloop/sandbox-run.json` records `image_provenance: verified` and that digest; the task is **done** |
| `warn`, the hub's pin repointed at the edge identity (`CLOOP_PROVENANCE_IMAGES_IDENTITY`) | the same signed image is wrongly signed: **409**, "not from the workflow that publishes them", nothing created |
| `warn`, the device's image unsigned | runs the device's own copy of the tag; the journal carries `image_provenance` "ran without a signature … from the device's own copy of the tag", and the run's record names no digest — the registry's, which the hub checked, need not be the device's copy |

## Running it

From the hub's host, with `ssh <device>` working as root and docker on both:

```bash
COSIGN=/path/to/cosign scripts/e2e/image-provenance/run.sh     # DEVICE=sgx
DEVICE=edge-2 PORT=18471 COSIGN=… scripts/e2e/image-provenance/run.sh
KEEP=1 COSIGN=… scripts/e2e/image-provenance/run.sh            # leave both trees
```

`SIGNED` must name an image of cloop's that the publishing workflow signed —
`:edge` once a commit with Task 20453 has reached `main`, a release tag after
v0.0.7 — and `UNSIGNED` one it did not: `:latest` until the next release, as the
device already holds it. The rig pulls the signed digest on the device, as a
refusal's remedy tells an operator to; the device's engine never pulls by
itself.

Everything it starts is its own and goes on exit: the hub (`cloop ui` bound to
`127.0.0.1:$PORT`, its own `HOME`, workdir, `CLOOP_SECRET_KEY` and API token, an
environment built from nothing), the `ssh -R` tunnel, and on the device a second
agent under `/tmp/cloop-image-provenance-$PORT`, run as the production agent's
user and stopped by the PID it recorded. The production agent is not touched.
The pulled digest stays in the device's image store.
