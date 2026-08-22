# Deploying the cloop hub

A **hub** is a cloop control plane: the dashboard, the REST API, and the
endpoint remote executor agents dial into. This directory holds everything
needed to run one — container image, evaluation stack, Helm chart, and the
bootstrap command that generates a hardened configuration.

| Artifact | Path | Use it for |
| --- | --- | --- |
| Container image | [`../Dockerfile`](../Dockerfile) | Any container runtime |
| Evaluation stack | [`../docker-compose.yml`](../docker-compose.yml) | Trying SSO + RBAC + TLS in one command |
| Helm chart | [`helm/cloop-hub/`](helm/cloop-hub/) | Kubernetes, including in-cluster execution |
| Bootstrap command | `cloop hub bootstrap` | Bare metal, systemd, or generating any of the above |

---

## The thing to understand first

cloop's built-in defaults are the ones a single developer in a git checkout
wants: host execution allowed, no TLS, no authentication, no RBAC. Every
security control in the codebase is opt-in.

That matters because **a hub that works tells you nothing about whether it is
open.** An operator who starts from the defaults and adds what they notice
missing gets a functioning dashboard with an executor policy that will happily
fork a harness — running model-authored code — in the same process tree as the
control plane, next to its secret store.

So the artifacts here invert those defaults for a hosted deployment
specifically. Where they differ from cloop's defaults, they are stricter, and
the difference is deliberate:

| Setting | cloop default | Here |
| --- | --- | --- |
| `executors.allow_host_process` | unset (permissive) | `false` |
| `ui.oidc.default_role` | — | `none` (deny-by-default) |
| `ui.allowed_ws_origins` | unset (any origin) | pinned to the external URL |
| Dashboard auth | none | token, then SSO |
| `CLOOP_SECRET_KEY` | unset | generated, 256 bits, mode 0600 |
| Container user | — | 65532, read-only rootfs, no capabilities |

---

## Quick evaluation: `docker compose up`

```bash
docker compose up --build
```

Then open **<https://cloop.localtest.me:8443/>** and accept the self-signed
certificate warning. Sign in with any of:

| User | Password | Ends up as | Why |
| --- | --- | --- | --- |
| `admin@example.com` | `password` | **admin** | listed in `ui.oidc.admin_emails` |
| `operator@example.com` | `password` | **operator** | matched by a `role_mappings` entry |
| `nobody@example.com` | `password` | **none** | matched by nothing |

The third one is the one worth trying. It authenticates successfully — dex
issues a valid ID token, cloop creates a session — and the user still sees
nothing. That is deny-by-default, and it is invisible unless you look at it.

`docker compose down -v` resets everything.

### What the stack contains

```
browser ──TLS──> nginx :8443 ──┬── /dex/*  ──> dex        (mock IdP, 3 static users)
                               └── /*      ──> cloop hub  (plain HTTP, not published)
```

Four services: a one-shot `certs` job that generates the TLS pair with
`cloop hub tls-init`, `dex` as the identity provider, `nginx` terminating TLS,
and the hub itself.

### Why the hostname is `cloop.localtest.me` and not `localhost`

OIDC requires that the issuer URL resolve to the same provider from two
different vantage points: the **browser**, which follows the authorization
redirect, and the **hub**, which fetches the discovery document and exchanges
the code server-side. `localhost` cannot satisfy both — inside the hub's
container it means the hub.

`*.localtest.me` resolves to `127.0.0.1` in public DNS, which handles the
browser. Inside the compose network, a network alias on the proxy makes
Docker's embedded DNS answer with the proxy's address instead, which handles
the hub. One issuer URL, correct from both sides.

If you delete that alias, the login fails at discovery with a connection
error — a symptom that looks nothing like its cause, which is why it is
called out here and in the compose file.

### Things you will notice

- **`config.yaml has permissions 644`** on startup. Expected. The warning
  exists because a config *may* contain API keys; the mounted one contains no
  secrets at all (they arrive as environment variables), so it is world-readable
  on purpose.
- **`register local executor: host execution is disabled by policy`**. Also
  expected — that is strict mode refusing to register the host executor. The
  stack's `executor` service enrolls itself moments later and becomes the thing
  runs are dispatched to; until it connects, `/readyz` answers 503 and names
  executors as the reason. That sequence is deliberate and is what
  `make e2e-stack` asserts.

### Checking the configuration

```bash
docker compose run --rm --no-deps --entrypoint /usr/local/bin/cloop cloop hub doctor
```

`cloop hub doctor` diagnoses the things that only exist once cloop is hosted —
issuer discovery, the redirect URI against the external URL, TLS material, the
sealing key, whether anybody maps to admin, image trust, executor reachability,
storage integrity and quotas. On this stack it should report two failures on
purpose: the `CLOOP_SECRET_KEY` here is the placeholder from this file, and
`--offline` aside, a hub with no enrolled executor has nothing to dispatch to.
`--json` emits the same report with stable check ids for CI.

### The executor

```
enroll (one-shot) ──mints a token──> enroll volume ──> executor ──dials out──> hub
```

The `enroll` service runs `cloop executor enroll --bundle-file` in the hub's
state volume and exits; the `executor` service redeems that single-use bundle on
boot, deletes it, and connects *outward* over `wss://`. Nothing in the stack
dials the executor, and the executor has no access to the hub's database or
filesystem — which is the whole point, and is asserted by `make e2e-stack`.

It runs a different image from the hub (`--target executor`): Alpine with git,
because materialising a source tree and committing what a task changed both need
it. The hub image is distroless and has neither, deliberately.

## `make e2e-stack`

```bash
make e2e-stack          # brings the stack up, runs one task, tears it down
KEEP=1 make e2e-stack    # leave it running afterwards
```

Boots the stack, asserts `/readyz` is red with nothing to dispatch to, enrolls
the executor and waits for it to go green, seeds a project with an https git
origin served by the same proxy, dispatches a real `cloop run` to the device
with a scoped API token, and asserts that the executor fetched the tree and that
the harness's output came back to the hub. The task is driven by the mock
provider, so it needs no API key and no network beyond the image pulls.

What it does not assert: that the *files* the task changed came back. That is a
separate mechanism (a git bundle produced on the device and applied by
`pkg/writeback`), and a run dispatched from `POST /api/run` does not currently
request one.

### Not a production template

Static passwords, a committed client secret, a fixed `CLOOP_SECRET_KEY`, and a
self-signed certificate are all in the compose file in plaintext, so that
`docker compose up` needs no arguments. For anything real, start from
`cloop hub bootstrap` or the Helm chart.

---

## Bare metal: `cloop hub bootstrap`

```bash
mkdir -p /srv/cloop && cd /srv/cloop
cloop hub bootstrap --external-url https://cloop.example.com
cloop hub tls-init                # development certificate; skip for a real one
```

This writes two files:

- **`.cloop/config.yaml`** (mode 0600) — the hosted profile, as commented YAML.
  It is generated from a template rather than marshalled from a struct
  precisely so you can read what was decided for you. Safe to commit.
- **`.cloop/hub.env`** (mode 0600) — `CLOOP_SECRET_KEY` and `CLOOP_UI_TOKEN`,
  32 bytes of `crypto/rand` each. **Never commit this.** Directly consumable by
  systemd's `EnvironmentFile=`, `docker compose --env-file`, or
  `set -a; . .cloop/hub.env; set +a`.

It then prints a systemd unit configured for that directory. It is printed and
not installed because writing to `/etc/systemd/system` needs root, and a
bootstrap command that silently acquired a system service would be a poor
trade for saving one copy-paste.

The unit applies the systemd equivalents of what the container image gets
structurally: `ProtectSystem=strict`, `NoNewPrivileges`, an empty
`CapabilityBoundingSet`, `MemoryDenyWriteExecute`, and a single
`ReadWritePaths` for the state directory.

### Useful flags

| Flag | Effect |
| --- | --- |
| `--behind-proxy` | Leave `ui.tls` empty; a proxy or Ingress terminates TLS. **The proxy must set `X-Forwarded-Proto: https`** — that header is what marks the session cookie `Secure`. |
| `--oidc-issuer`, `--oidc-client-id` | Enable SSO. The client *secret* is never written to the config; it comes from `CLOOP_OIDC_CLIENT_SECRET`. |
| `--admin-email` | Break-glass admin, matched on the email claim. Repeatable. |
| `--force` | Overwrite an existing deployment. Read the warning first: it mints a new master key, and a new key cannot open payloads sealed with the old one. |

### About `CLOOP_SECRET_KEY`

It is the passphrase protecting every payload in the secret broker — brokered
kubeconfigs, GitHub PATs, egress credentials. Losing it makes them permanently
unopenable; there is no escrow and no recovery path. Changing it has the same
effect. Back it up wherever you keep root credentials.

---

## Container image

```bash
docker build -t cloop-hub:dev .

docker run --rm -p 8080:8080 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v cloop-state:/var/lib/cloop \
  -e CLOOP_UI_TOKEN=... -e CLOOP_SECRET_KEY=... \
  cloop-hub:dev
```

Multi-stage build: `golang:1.25` compiles a static `CGO_ENABLED=0` binary onto
`gcr.io/distroless/static-debian12:nonroot`. About 31 MB, runs as UID 65532,
works with a read-only root filesystem and all capabilities dropped.

`CGO_ENABLED=0` is what makes the distroless *static* base possible at all.
cloop's only C-adjacent dependency is SQLite, and it uses `modernc.org/sqlite`
(pure Go) specifically so this works — swapping in a cgo driver would break
the image silently.

### Consequences of distroless

There is no shell, no package manager, no curl, and no git in the runtime
image. That is the point: a hub that has already promised never to fork a
harness on its own host should not carry the tools to do so. It also means:

- **`docker exec … sh` does not work.** Use `docker exec … cloop <subcommand>`.
- **The HEALTHCHECK is the binary probing itself** — `cloop hub healthcheck`
  exists because there is nothing else in the image that speaks HTTP.

```bash
cloop hub healthcheck                     # liveness  (/healthz), exit 0 or 1
cloop hub healthcheck --endpoint readyz   # readiness (/readyz)
```

The distinction matters. `/healthz` answers "is this process alive" and
nothing else, so a slow database never triggers a restart. `/readyz` pings
SQLite, so it fails during startup and while storage is unavailable — the
right signal for pulling a replica out of a load balancer and the wrong one
for killing it.

### State layout

| Path | Contents |
| --- | --- |
| `/var/lib/cloop` | `WORKDIR` and `HOME`. One writable volume holds everything. |
| `/var/lib/cloop/.cloop` | `state.db`, artifacts, `config.yaml`, `projects.json` |
| `/tmp` | tmpfs, needed because the rootfs is read-only |

`cloop ui` resolves `.cloop` against the process working directory — there is
no `--workdir` flag — so `WORKDIR` *is* the state-directory selector. `HOME`
points at the same place because the multi-project registry lives at
`$HOME/.cloop/projects.json`, and one volume for all state is also what makes
"back up the hub" a single instruction.

The image ships `/var/lib/cloop` owned by 65532 so a fresh named volume seeds
with the right ownership. Mount the volume anywhere else and the hub gets a
root-owned directory it cannot write a database into — which surfaces as a
SQLite permission error several layers from the cause.

---

## Kubernetes: the Helm chart

```bash
kubectl create namespace cloop
kubectl create namespace cloop-workloads

kubectl -n cloop create secret generic cloop-hub-secrets \
  --from-literal=CLOOP_SECRET_KEY="$(head -c32 /dev/urandom | base64 | tr -d =)" \
  --from-literal=CLOOP_UI_TOKEN="$(head -c32 /dev/urandom | base64 | tr -d =)" \
  --from-literal=CLOOP_OIDC_CLIENT_SECRET=...

helm install cloop deploy/helm/cloop-hub -n cloop \
  --set secrets.existingSecret=cloop-hub-secrets \
  --set config.externalURL=https://cloop.example.com \
  --set ingress.enabled=true --set ingress.host=cloop.example.com \
  --set oidc.enabled=true --set oidc.issuer=https://idp.example.com/realms/main \
  --set executor.kubernetes.enabled=true
```

`helm install --wait` returns only once the readiness probe passes, which
means the PVC mounted, the ConfigMap landed inside it, `fsGroup` made it
writable, and SQLite opened — under `readOnlyRootFilesystem`, `runAsNonRoot`
and capabilities dropped.

### One replica, `Recreate`

Not a placeholder to raise later. Hub state is SQLite on a ReadWriteOnce
volume; a second replica corrupts it rather than sharing the load, and a
rolling update would schedule the new Pod before the old one released the
volume. Scaling out is a change to the storage layer, not to `replicaCount`.

The PVC carries `helm.sh/resource-policy: keep`, so `helm uninstall` does not
delete your database.

### In-cluster execution

With `executor.kubernetes.enabled=true`, the hub schedules each run as an
ephemeral Pod and authenticates as **its own ServiceAccount** rather than a
brokered kubeconfig.

Everywhere else, cloop insists on a brokered kubeconfig, because a control
plane reaching for ambient cluster credentials is one where every tenant
shares one authority. In-cluster mode inverts that reasoning: the authority is
not ambient, it is a Role the operator installed next to the Deployment,
enforced by the API server rather than by cloop. The alternative — minting a
kubeconfig, sealing it into cloop's secret store, and granting it back to an
executor already running inside the cluster the kubeconfig points at — is not
more secure, only longer, and long loops get shortcut with cluster-admin
kubeconfigs.

The chart installs a Role scoped to exactly the calls the driver makes:

| Resource | Verbs | Used by |
| --- | --- | --- |
| `pods` | `create`, `get`, `list`, `watch`, `delete` | start, poll, reconcile orphans, stream, stop |
| `pods/log` | `get` | stream task output |

Two absences are deliberate. There is **no `update` or `patch`** — the driver
never mutates a Pod after creating it, so a compromised hub cannot rewrite a
running workload's spec. And there is **no `secrets` rule at all** — an
executor that could read Secrets in its namespace would make the secret broker
decorative. CI asserts both directions, so a copy-pasted `"*"` fails the build.

The Role lives in `executor.kubernetes.namespace` (default `cloop-workloads`),
not in the hub's namespace. **Do not point it at the hub's own namespace**: a
workload Pod there can reach the hub's Secrets and its ServiceAccount token,
which is most of what executor isolation exists to prevent. The chart warns
about this in `NOTES.txt` and cloop warns about it at startup.

Verify from inside the Pod:

```bash
kubectl -n cloop exec deploy/cloop-cloop-hub -- cloop executor test kubernetes
```

That runs the full preflight — credentials, TLS, API reachability, RBAC,
confinement, limits — and then actually creates a Pod, runs `cloop version` in
it, and deletes it.

### Notable values

| Value | Default | Notes |
| --- | --- | --- |
| `config.allowHostProcess` | `false` | Leave it. |
| `config.fromConfigMap` | `true` | Renders `config.yaml` into a ConfigMap mounted read-only, so the hub cannot rewrite its own execution policy. Setting it `false` does **not** mean "same hub, editable config" — it means no config reaches the hub at all, so cloop's permissive defaults apply and **host execution is allowed**. Only use it if you will write a config into the volume yourself. |
| `executor.kubernetes.image` | `""` | Falls back to the hub image, which is distroless: enough for `cloop executor test` to pass, not enough to run a real task. Point it at an image with your toolchain and cloop on `PATH`. |
| `oidc.defaultRole` | `none` | If everyone lands on an empty dashboard, that is this working. Add a `roleMappings` entry; do not lower the default. |
| `secrets.existingSecret` | — | The production path. |
| `secrets.create` | `false` | Evaluation only — values land in the release manifest and in `helm get manifest`. |
| `persistence.enabled` | `true` | `false` means an emptyDir: every restart discards all projects, tasks and sealed secrets. |

### Refusals

The chart fails the render rather than installing something broken. All the
guards live in [`templates/_validate.tpl`](helm/cloop-hub/templates/_validate.tpl),
included unconditionally — a guard inside a conditionally-rendered file
disappears exactly when someone turns that file off.

| Refused | Because |
| --- | --- |
| No secret source, or both | `CLOOP_SECRET_KEY` has to come from somewhere, and exactly one somewhere. |
| `secrets.create` with no `secretKey` | That is the broker master key. |
| `secrets.create`, no OIDC, no `uiToken` | Installs a hub with **no authentication at all** — cloop treats an empty token as "auth not required". |
| `oidc.enabled` with no `issuer` | Discovery has nowhere to go. |
| `oidc.enabled` with `config.fromConfigMap=false` | No OIDC settings would reach the hub; the release would report SSO and serve token auth. |
| `executor.kubernetes` RBAC with no named ServiceAccount | The RoleBinding would target `default`, granting Pod create/delete to every Pod in the namespace that does not name an account. |
| `persistence.existingClaim` with `enabled=false` | The claim would be ignored and the hub would run on an emptyDir while appearing to use your volume. |
| `ingress.host` ≠ the host in `config.externalURL` | Produces a login that silently loops back to the sign-in page. |

### TLS

The Ingress terminates TLS and the hub speaks plain HTTP inside the cluster.
Your Ingress controller **must** set `X-Forwarded-Proto: https`. Most do by
default; nginx-ingress and Traefik both do. Without it, cloop cannot tell that
the browser's connection was encrypted and issues session cookies without the
`Secure` attribute.

The chart's default annotations also raise the proxy read timeout to an hour
and the body-size limit to 10 MiB. Both are ingress-nginx-specific; on another
controller, translate them. cloop's dashboard is WebSocket-first, so with the
usual 60-second read timeout the UI loads and then silently stops updating —
which reads as a cloop bug. And with ingress-nginx's 1 MiB default body size,
requests between 1 and 10 MiB are rejected by the proxy with a 413 the hub
never sees and never records.

`ingress.className` defaults to empty, meaning "use the cluster's default
IngressClass". Check one exists (`kubectl get ingressclass`): ingress-nginx
v1+ ignores class-less Ingresses unless started with
`--watch-ingress-without-class`, and the failure is silent — the object is
created, `helm install --wait` succeeds, and the hub is unreachable.

---

## What CI checks

The `deploy-artifacts` job in [`../.github/workflows/ci.yml`](../.github/workflows/ci.yml)
exists because none of this is checked by `go build`. A Dockerfile producing
an image that cannot start, a chart rendering manifests the API server
rejects, or a `securityContext` the container cannot run under are all
invisible to every other job — and all of them surface for the first time in
front of an operator.

So it boots the things:

1. Builds the image; asserts UID 65532 and the OCI labels.
2. Runs the container with `--read-only --cap-drop ALL --security-opt
   no-new-privileges`; asserts `/healthz` and `/readyz` return 200, that
   unauthenticated `/api/state` returns 401, and that the in-image
   `cloop hub healthcheck` works.
3. Runs `cloop hub bootstrap` and asserts the generated config still contains
   `allow_host_process: false`, `default_role: none`, and a 0600 `hub.env`.
4. `helm lint` across three value sets, and asserts the chart's guard rails
   still refuse every configuration in the table above.
5. Spins up kind, runs `helm template | kubectl apply --dry-run` both
   client- and server-side, installs the chart, and waits for readiness.
6. Asserts the executor Role grants exactly the six Pod verbs and nothing
   else, in the workload namespace only.
7. Runs a real workload through the in-cluster executor.

---

## Troubleshooting

**Login redirects back to the sign-in page with no error.** The redirect URL
registered at your IdP does not match `config.externalURL` + `/auth/callback`.
The chart catches the Ingress-host case at render time; a mismatch at the IdP
it cannot see.

**Dashboard loads but never updates.** The WebSocket is being cut. Raise the
proxy read timeout and make sure `Upgrade`/`Connection` headers are forwarded.

**`no executor available … no default executor configured`.** Strict mode
working as intended: nothing may run on the hub host and no isolated executor
is configured yet. Enable `executor.kubernetes`, enable the container
executor, or enroll a remote agent with `cloop executor enroll`.

**SQLite permission errors on startup.** The state volume is not writable by
UID 65532. In Kubernetes check `podSecurityContext.fsGroup`; in Docker check
that the volume is mounted at `/var/lib/cloop` and not somewhere the image did
not pre-create.

**`in_cluster is set but the ServiceAccount is unusable`.** The Pod has no
projected token. Set `serviceAccount.automountServiceAccountToken=true` —
the chart only mounts it when the Kubernetes executor is enabled, since a hub
that cannot use a cluster credential should not be carrying one.
