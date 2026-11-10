# Deploying the cloop hub

A **hub** is a cloop control plane: the dashboard, the REST API, and the
endpoint that remote executor agents connect to. You can run one with:

| Artifact | Path | Use it for |
| --- | --- | --- |
| Container image | [`../Dockerfile`](../Dockerfile) | Any container runtime |
| Evaluation stack | [`../docker-compose.yml`](../docker-compose.yml) | Trying SSO + RBAC + TLS in one command |
| Helm chart | [`helm/cloop-hub/`](helm/cloop-hub/) | Kubernetes, including in-cluster execution |
| Executor controller chart | [`helm/cloop-executor-controller/`](helm/cloop-executor-controller/) | Executor pools whose runners are Pods in a cluster |
| Bootstrap command | `cloop hub bootstrap` | Bare metal, systemd, or generating any of the above |
| Entra ID SSO module | [`terraform/azure-entra-id/`](terraform/azure-entra-id/README.md) | Provisioning the identity side on Microsoft Entra ID |

The Entra ID module doesn't run cloop. It sets up the identity provider that
gives the hub named users and roles, and its README covers the
provider-specific details behind sign-in failures the Azure portal doesn't
explain.

---

## The thing to understand first

cloop's built-in defaults suit a single developer in a git checkout: host
execution allowed, no TLS, no authentication, no RBAC. Every security control
in the codebase is opt-in.

So a hub can work and still be open. One built up from the defaults can start
a harness, which runs model-written code, in the same process tree as the
control plane and next to its secret store.

Where the artifacts here differ from cloop's defaults, they are stricter:

| Setting | cloop default | Here |
| --- | --- | --- |
| `executors.allow_host_process` | unset (permissive) | `false` |
| `ui.oidc.default_role` | — | `none` (deny-by-default) |
| `ui.allowed_ws_origins` | unset (any origin) | pinned to the external URL |
| Dashboard auth | none | token, then SSO |
| `CLOOP_SECRET_KEY` | unset | generated, 256 bits, in a credential file (never the environment) |
| Container user | — | 65532, read-only rootfs, no capabilities |
| Listen address | `127.0.0.1` without sign-in, every interface with it | `0.0.0.0`, set explicitly, refused without sign-in |

One control is not opt-in: a hub without sign-in listens only on `127.0.0.1`
and refuses an address beyond loopback unless you explicitly allow it (see
[Listening on the network](#listening-on-the-network)).

---

## Quick evaluation: `docker compose up`

```bash
docker compose up --build
```

Then open **<https://cloop.localtest.me:8443/>**, accept the self-signed
certificate warning, and sign in as one of these users:

| User | Password | Ends up as | Why |
| --- | --- | --- | --- |
| `admin@example.com` | `password` | **admin** | listed in `ui.oidc.admin_emails` |
| `operator@example.com` | `password` | **operator** | matched by a `role_mappings` entry |
| `nobody@example.com` | `password` | **none** | matched by nothing |

Try the third one. The sign-in succeeds (dex issues a valid ID token and cloop
creates a session), but the user sees nothing. That is deny-by-default.

`docker compose down -v` resets everything.

### What the stack contains

```
browser ──TLS──> nginx :8443 ──┬── /dex/*  ──> dex        (mock IdP, 3 static users)
                               └── /*      ──> cloop hub  (plain HTTP, not published)
```

The stack has six services:

- `certs`, a one-shot job that generates the TLS certificate and key with
  `cloop hub tls-init`
- `dex`, the identity provider
- `nginx`, which terminates TLS
- the hub itself
- `enroll`, a one-shot job that mints a join bundle once the hub is healthy
- `executor`, the agent that redeems the bundle

The last two give the stack an isolating executor. A hub in strict mode isn't
ready without one, so `/readyz` is red until they have run.

### Why the hostname is `cloop.localtest.me` and not `localhost`

OIDC needs the issuer URL to reach the same provider from the browser, which
follows the authorization redirect, and from the hub, which fetches the
discovery document and exchanges the code. Inside the hub's container,
`localhost` means the hub.

`*.localtest.me` resolves to `127.0.0.1` in public DNS, which works for the
browser. Inside the compose network, a network alias on the proxy makes
Docker's embedded DNS return the proxy's address, which works for the hub. If
you delete that alias, the login fails at discovery with a connection error
that gives no hint of the cause.

### Things you will notice

- **`config.yaml has permissions 644`** at startup. Expected: a config can
  contain API keys, but this one holds none (secrets arrive as environment
  variables), so it is world-readable.
- **`register local executor: host execution is disabled by policy`**. Also
  expected: strict mode refuses to register the host executor. The stack's
  `executor` service enrolls moments later and takes the runs. Until it
  connects, `/readyz` answers 503 and names executors as the reason, which
  `make e2e-stack` checks.

### Checking the configuration

```bash
docker compose run --rm --no-deps --entrypoint /usr/local/bin/cloop cloop hub doctor
```

`cloop hub doctor` checks what only exists once cloop is hosted: issuer
discovery, the redirect URI against the external URL, TLS material, the
sealing key, whether anyone maps to admin, image trust, executor reachability,
storage integrity and quotas. On this stack it should report two expected
failures: `CLOOP_SECRET_KEY` is the compose file's placeholder, and (unless you
pass `--offline`) a hub with no enrolled executor has nothing to dispatch to.
`--json` prints the same report with stable check IDs for CI.

### The executor

```
enroll (one-shot) ──mints a token──> enroll volume ──> executor ──dials out──> hub
```

The `enroll` service runs `cloop executor enroll --bundle-file` in the hub's
state volume and exits. The `executor` service redeems the single-use bundle at
boot, deletes it, and connects out to the hub over `wss://`. Nothing dials the
executor, and it has no access to the hub's database or filesystem, which
`make e2e-stack` checks.

Its image (`--target executor`) is Alpine with git, which it needs to
materialise a source tree and commit what a task changed. The distroless hub
image has no git.

## `make e2e-stack`

```bash
make e2e-stack          # brings the stack up, runs one task, tears it down
KEEP=1 make e2e-stack    # leave it running afterwards
```

The target:

1. Starts the stack and asserts `/readyz` is red with nothing to dispatch to.
2. Signs in through dex as the three users.
3. Enrolls the executor and waits for it to turn green.
4. Seeds a project with an https git origin served by the same proxy.
5. Dispatches a real `cloop run` to the device with a scoped API token.
6. Asserts that the executor fetched the tree and the harness's output came
   back to the hub.

The task uses the mock provider, so it needs no API key and no network beyond
the image pulls.

The sign-in is a real browser flow driven by curl (`deploy/eval/oidc-login.sh`):
a PAT would bypass discovery, PKCE, the code exchange, ID-token verification
and claim-to-role mapping. It asserts all three RBAC outcomes:
`admin@example.com` resolves to admin, `operator@example.com` is mapped to
operator by a claim, and `nobody@example.com` signs in but gets a 403 on a
gated route. To run it on its own against a live stack:

```bash
CA_FILE=$(mktemp) && docker run --rm -v cloop-eval_certs:/c alpine:3.20 \
  cat /c/cert.pem > "$CA_FILE"
CA_FILE=$CA_FILE deploy/eval/oidc-login.sh nobody@example.com
```

On teardown it fails if any container stopped with a non-zero exit code,
printing that container's log first. A container still running passes even if
it restarted: nginx resolves its upstream when it parses its config, so a proxy
that starts before the hub exits once, then restarts and works.

If port 8443 is taken, publish the stack on another port. The port in the URL
can't change (the certificate, the issuer and every OIDC redirect contain it),
so change the host port and the client's connection mapping together:

```bash
CLOOP_EVAL_PORT=18443 \
CLOOP_EVAL_CURL_CONNECT='--connect-to cloop.localtest.me:8443:127.0.0.1:18443' \
  make e2e-stack
```

The target doesn't check that the files the task changed came back. That is a
separate mechanism (a git bundle produced on the device and applied by
`pkg/writeback`), and a run dispatched from `POST /api/run` doesn't currently
request one.

CI runs all of this on every push and pull request in the gating **Eval stack
(SSO + remote executor)** job.

### Not a production template

Static passwords, a committed client secret, a fixed `CLOOP_SECRET_KEY` and a
self-signed certificate are all in the compose file in plaintext, so that
`docker compose up` needs no arguments. For a real deployment, start from
`cloop hub bootstrap` or the Helm chart.

---

## Bare metal: `cloop hub bootstrap`

```bash
mkdir -p /srv/cloop && cd /srv/cloop
cloop hub bootstrap --external-url https://cloop.example.com
cloop hub tls-init                # development certificate; skip for a real one
```

This writes three files:

- **`.cloop/config.yaml`** (mode 0600): the hosted profile as commented YAML,
  generated from a template so you can read what was decided for you. Safe to
  commit.
- **`cloop-secret-key`**: the root key, `CLOOP_SECRET_KEY`, 32 bytes from
  `crypto/rand`. It sits next to `.cloop/`, never inside it, so a backup or
  snapshot of the database doesn't include the key that opens it. Where the
  host can, `systemd-creds encrypt` seals it (`cloop-secret-key.cred`) to the
  host's credential secret and its TPM, if there is one, and no plaintext copy
  is written. Otherwise it is a plain file with mode 0600. `--key-file` moves
  it, and `--systemd-creds always|never` decides whether it is sealed.
- **`.cloop/hub.env`** (mode 0600): `CLOOP_UI_TOKEN`, 32 bytes from
  `crypto/rand`. **Never commit this file.** It works as is with systemd's
  `EnvironmentFile=`, `docker compose --env-file`, or
  `set -a; . .cloop/hub.env; set +a`. The root key isn't in it, because
  environment variables are readable in `/proc/<pid>/environ` and
  `systemctl show`, and every child inherits them.

The hosted profile turns on the [git interception proxy](../docs/architecture/git-proxy.md)
and the [Kubernetes access monitor](../docs/architecture/kubernetes-access.md)
with `tls: auto`, so a GitHub token or kubeconfig granted to a project stays on
the hub. The hub issues both monitors' certificates from its own CA, sealed
under `CLOOP_SECRET_KEY`, and sandboxes trust that CA for those two URLs only.
Their advertise URLs, listed in the summary, are `--external-url`'s host on
ports 8443 and 8444, and executors must reach them directly, not through a
TLS-terminating proxy.

Bootstrap then prints a systemd unit for that directory, without installing
it: writing to `/etc/systemd/system` needs root.

The unit applies the systemd equivalents of the container image's
restrictions: `ProtectSystem=strict`, `NoNewPrivileges`, an empty
`CapabilityBoundingSet`, `MemoryDenyWriteExecute`, and a single
`ReadWritePaths` for the state directory. It loads the root key with
`LoadCredentialEncrypted=cloop-secret-key:<file>.cred` (or `LoadCredential=`
for a plain file), so systemd reads it and the hub finds it in
`$CREDENTIALS_DIRECTORY`, readable only by the service. From a shell, name the
plain file instead: `CLOOP_SECRET_KEY_FILE=/srv/cloop/cloop-secret-key cloop ui …`.
A key file must be owned by the hub's user, with mode 0400 or 0600.

### Useful flags

| Flag | Effect |
| --- | --- |
| `--behind-proxy` | Leave `ui.tls` empty for a proxy or Ingress that terminates TLS. The proxy must set `X-Forwarded-Proto: https`, which tells the hub the browser's connection was encrypted; without it, `/install.sh` is refused and enrollment offers no one-line installer. The hub trusts the header only from loopback or an address in `ui.trusted_proxies`, so add the proxy's address there if it runs on another host. |
| `--oidc-issuer`, `--oidc-client-id` | Enable SSO. A client secret is optional: without one, the hub is a public client and PKCE authenticates the code exchange. A secret comes from `CLOOP_OIDC_CLIENT_SECRET` and is never written to the config. |
| `--admin-email` | Break-glass admin, matched on the email claim. Repeatable. |
| `--git-proxy-port`, `--kube-guard-port` | Where the two monitors listen, and the ports in the URLs sandboxes use on `--external-url`'s host. `8443` and `8444` by default; a default that equals `--port` or the external URL's port moves up by 1000 (a dashboard at `https://hub:8443` gets a git proxy on 9443), while a colliding port you set is refused. |
| `--key-file`, `--systemd-creds` | Where the root key is written (outside `.cloop/`; `cloop-secret-key` in `--dir` by default), and whether `systemd-creds` seals it: `auto` when the host can, `always`, or `never`. |
| `--force` | Overwrite an existing deployment. Read the warning first: it mints a new master key, which can't open payloads sealed with the old one. To change the key of a hub you keep, use the online procedure in [changing CLOOP_SECRET_KEY](../docs/operations/runbook.md#changing-cloop_secret_key-itself). |

### About `CLOOP_SECRET_KEY`

It is the passphrase protecting every payload in the secret broker: brokered
kubeconfigs, GitHub PATs and egress credentials. Lose it without an escrow and
they can never be opened again. You can change it online: a rolling restart
with the new key as `CLOOP_SECRET_KEY` and the old as
`CLOOP_SECRET_KEY_PREVIOUS`, then `cloop hub key rotate --retire-previous`
([runbook](../docs/operations/runbook.md#changing-cloop_secret_key-itself)).
The hub reads it from `CLOOP_SECRET_KEY_FILE`, the systemd credential
`cloop-secret-key`, or the environment, in that order, and refuses to start if
two of them disagree ([the root key](../docs/operations/runbook.md#the-root-key)).
Once the hub has started, seal it under a passphrase into a file you keep off
the host with your root credentials:

```bash
cloop hub key escrow export --output /secure/cloop-hub.escrow
```

`cloop hub doctor` warns until an escrow is recorded, and `cloop hub key escrow
verify` rehearses recovery. See the [runbook](../docs/operations/runbook.md#escrowing-the-sealing-key).

With [`secrets.kms`](../docs/reference/configuration.md#sealing-keys-in-a-kms-secrets),
a key-management service holds the secret store's keys instead, and a copy of
the database plus this key opens nothing. The key still seals audit
checkpoints, backup sidecars and the escrow. See
[keys in a KMS](../docs/operations/runbook.md#keys-in-a-kms).

---

## Container image

```bash
docker build -t cloop-hub:dev .

docker run --rm -p 8080:8080 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v cloop-state:/var/lib/cloop \
  -e CLOOP_UI_TOKEN=... \
  -v /srv/cloop/cloop-secret-key:/run/secrets/cloop-secret-key:ro \
  -e CLOOP_SECRET_KEY_FILE=/run/secrets/cloop-secret-key \
  cloop-hub:dev
```

Pass the root key as a file: `-e CLOOP_SECRET_KEY=…` would show it to anyone
who can run `docker inspect`. The bind-mounted file keeps its owner and mode,
so make it readable by UID 65532:
`chown 65532 /srv/cloop/cloop-secret-key && chmod 0400 /srv/cloop/cloop-secret-key`.

The image starts `cloop ui --listen 0.0.0.0 --port 8080 --no-browser` and
refuses to start without `CLOOP_UI_TOKEN` (or `ui.oidc` in a mounted config).
See [Listening on the network](#listening-on-the-network).

A multi-stage build compiles a static `CGO_ENABLED=0` binary with
`golang:1.26` onto `gcr.io/distroless/static-debian12:nonroot`. The image is
about 31 MB, runs as UID 65532, and works with a read-only root filesystem and
all capabilities dropped.

The distroless static base needs `CGO_ENABLED=0`, which works because cloop's
only C-adjacent dependency, SQLite, comes from the pure-Go
`modernc.org/sqlite`. A cgo driver would break the image without warning.

### Consequences of distroless

The runtime image has no shell, no package manager, no curl and no git. This
means:

- **`docker exec … sh` does not work.** Use `docker exec … cloop <subcommand>`.
- **The HEALTHCHECK is the binary probing itself.** `cloop hub healthcheck`
  exists because nothing else in the image speaks HTTP.

```bash
cloop hub healthcheck                     # liveness  (/healthz), exit 0 or 1
cloop hub healthcheck --endpoint readyz   # readiness (/readyz)
```

`/healthz` only answers "is this process alive", so a slow database never
triggers a restart. `/readyz` pings SQLite, so it fails during startup and
while storage is unavailable: right for taking a replica out of a load
balancer, wrong for killing it.

### State layout

| Path | Contents |
| --- | --- |
| `/var/lib/cloop` | `WORKDIR` and `HOME`. One writable volume holds everything. |
| `/var/lib/cloop/.cloop` | `state.db`, artifacts, `config.yaml`, `projects.json` |
| `/var/lib/cloop/projects` | the projects root (`ui.projects_root`'s default): projects created by name. The Helm chart mounts its state volume's `projects/` here |
| `/tmp` | tmpfs, needed because the rootfs is read-only |

`cloop ui` resolves `.cloop` against its working directory (there is no
`--workdir` flag), so `WORKDIR` selects the state directory. `HOME` points to
the same place because the multi-project registry is at
`$HOME/.cloop/projects.json`, and one volume for all state makes backing up the
hub a single step.

The image ships `/var/lib/cloop` owned by 65532, so a new named volume gets
the right ownership. Mount the volume elsewhere and the hub gets a root-owned
directory it can't write its database into, which surfaces as a SQLite
permission error far from the cause.

### Listening on the network

A hub with no sign-in (neither `ui.oidc` nor `CLOOP_UI_TOKEN`) lets anyone who
reaches it list its projects, queue tasks and start agent runs on its host. So
`cloop ui` keeps such a hub on `127.0.0.1` unless you name an address
(`--listen` or `ui.listen`), and refuses one beyond loopback unless
`ui.allow_unauthenticated_network: true` acknowledges it
([the full rule](../docs/reference/configuration.md#web-ui-cloop-ui)). A hub
with sign-in listens on every interface by default.

A container has its own loopback, so a published port only reaches what
listens on the container's interfaces. A hub that fell back to `127.0.0.1`
there would be unreachable while its HEALTHCHECK, which probes from inside,
reported it healthy. So every artifact here names the address:

| Artifact | Listens | Sign-in | Without sign-in |
| --- | --- | --- | --- |
| Image (`Dockerfile` `CMD`) | `--listen 0.0.0.0` | `CLOOP_UI_TOKEN` or `ui.oidc` you provide | refuses to start, and says why |
| Helm chart | `--listen 0.0.0.0` | `oidc.enabled` or `secrets.uiToken` (with `secrets.create`, the chart won't render without one of them) | the Pod refuses to start; an `existingSecret` must carry `CLOOP_UI_TOKEN` unless SSO is on |
| Evaluation stack | `--listen 0.0.0.0` | SSO through dex | — |
| `cloop hub bootstrap` | default (every interface) | `CLOOP_UI_TOKEN` in `hub.env`, SSO once enabled | — |

To run the image without sign-in (on a laptop or for a demo), acknowledge it in
a mounted config and publish the port only on the host's loopback, so the
network can't reach it:

```bash
printf 'ui:\n  allow_unauthenticated_network: true\n' > open-hub.yaml
docker run --rm -p 127.0.0.1:8080:8080 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m -v cloop-state:/var/lib/cloop \
  -v "$PWD/open-hub.yaml:/var/lib/cloop/.cloop/config.yaml:ro" \
  cloop-hub:dev
```

The hub then prints `WARNING: this hub has no sign-in and listens on *:8080
because ui.allow_unauthenticated_network is set` at every start. Remote
executor agents dial the hub, so a hub serving them over the network needs SSO
or a token, whatever it binds.

**Behind a TLS proxy on the same host** (bare metal with nginx, say), bind a
hub with sign-in to loopback too (`ui.listen: 127.0.0.1`), so the proxy is the
only way in. While `ui.external_url` is https, `cloop hub doctor` warns about
`ui.exposure` until you do. It reports a failure for any hub without sign-in
that it finds reachable beyond loopback, whichever build serves it.

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

`helm install --wait` returns only once the readiness probe passes. By then
the PVC is mounted, the ConfigMap is inside it, `fsGroup` has made it writable
and SQLite has opened, all under `readOnlyRootFilesystem`, `runAsNonRoot` and
dropped capabilities.

The hub gets the Secret's `CLOOP_SECRET_KEY` as a file. The chart mounts it at
`/etc/cloop/root-key/cloop-secret-key`, sets `CLOOP_SECRET_KEY_FILE` and
`CREDENTIALS_DIRECTORY=/etc/cloop/root-key`, and blanks the variable `envFrom`
would otherwise set, so the key is in no `kubectl get pod -o yaml` and no
process environment. To change it, put the new key in the Secret as
`CLOOP_SECRET_KEY` and the old as `CLOOP_SECRET_KEY_PREVIOUS`, roll the
Deployment, escrow the new key and run `cloop hub key rotate --retire-previous`
in a Pod. Then drop `CLOOP_SECRET_KEY_PREVIOUS` and roll again. With
`secrets.create`, the old key is `secrets.previousSecretKey`, and the chart
rolls the Pods itself when either changes.

### Replicas

Every replica is a member of one [hub cluster](../docs/architecture/hub-cluster.md).
The Service may send any request to any replica, and a member forwards to
another the few requests only that member can answer: a Stop for a run it
streams, a login callback for a login it began, anything for an edge agent
connected to it. When a replica goes away, the others take over its runs,
agents and duties. One is elected leader for work that must happen exactly
once: retention, backups, auto-resume, the session janitor and the orphan
sweep.

```bash
helm upgrade cloop deploy/helm/cloop-hub -n cloop --reuse-values --set replicaCount=3
kubectl -n cloop exec deploy/cloop-cloop-hub -- cloop hub cluster status
```

Replicas give you availability (a Pod crash or an upgrade no longer takes the
dashboard down) and spread requests, WebSocket and agent connections over
several processes. They don't give you a second node: the control plane is one
SQLite database, and its write-ahead log needs every process that uses it on
one kernel. So with more than one replica, the chart:

- adds a **required podAffinity** term pinning every replica to the node
  already running one (where the ReadWriteOnce volume is attached), appended to
  any `affinity` you set;
- switches the Deployment to **`RollingUpdate`** with `maxSurge: 1` and
  `maxUnavailable: 0`: a replacement joins before a member leaves, and the
  leaving member hands its runs over on SIGTERM;
- sets **`CLOOP_CLUSTER_ADVERTISE_HOST`** to each Pod's IP, which the other
  replicas use to reach it;
- **refuses to render** without persistence or with a `ReadWriteOncePod`
  volume (see [Refusals](#refusals)).

A single replica keeps `Recreate`: without the co-location term, a surge Pod
could land on a node that can't mount the volume and hang the rollout. Set
`strategy.type=RollingUpdate` to get the term, and upgrades without downtime,
on one replica too.

To run more work, move it to executors (`executor.kubernetes.enabled`), which
scale out across the cluster. Replicas share one node's CPU and memory, so size
the node for all of them.

Upgrading from a chart version before 0.2.0: the old Pod holds the
control-plane lease as a pre-cluster hub, and `Recreate` stops it before the
new Pod starts, so the new Pod leads. Raise `replicaCount` after the upgrade.

The PVC carries `helm.sh/resource-policy: keep`, so `helm uninstall` doesn't
delete your database.

### In-cluster execution

With `executor.kubernetes.enabled=true`, the hub schedules each run as an
ephemeral Pod and authenticates as its own ServiceAccount, not with a brokered
kubeconfig.

Everywhere else cloop requires a brokered kubeconfig, so that tenants don't
share the control plane's ambient cluster credentials. Here the authority is a
Role the operator installed next to the Deployment, enforced by the API server.
Brokering a kubeconfig back into the same cluster would be no more secure,
only longer.

The chart installs a Role that allows only the calls the driver makes:

| Resource | Verbs | Used by |
| --- | --- | --- |
| `pods` | `create`, `get`, `list`, `watch`, `delete` | start, poll, reconcile orphans, stream, stop |
| `pods/log` | `get` | stream task output |
| `secrets` | `create`, `patch`, `delete` | deliver a brokered lease to a workload, replace a GitHub App token in it before the token's hour is up, then destroy it |
| `networkpolicies` | `create`, `delete`, `list` | the per-Pod egress allowlist; `list` is for the orphan sweep. The same three verbs are all `cloop hub doctor --probe-network-policy` needs |

The Role leaves out:

- `update` and `patch` on `pods`: the driver never changes a Pod after
  creating it, so a compromised hub can't rewrite a running workload's spec.
- `get`, `list` and `watch` on `secrets`, making the rule write-only. The
  driver must place a lease and destroy it, but an executor that could read
  Secrets in its namespace would defeat the secret broker.
- `update` on `networkpolicies`, so a running Pod's firewall can't be widened.

CI checks that the Role grants these verbs and no others, so a copy-pasted
`"*"` fails the build.

The Role lives in `executor.kubernetes.namespace` (default `cloop-workloads`),
not the hub's namespace. **Do not point it at the hub's own namespace**: a
workload Pod there can reach the hub's Secrets and its ServiceAccount token,
most of what executor isolation exists to prevent. The chart warns about this
in `NOTES.txt`, and cloop warns at startup.

Verify from inside the Pod:

```bash
kubectl -n cloop exec deploy/cloop-cloop-hub -- cloop executor test kubernetes
```

This runs the full preflight (credentials, TLS, API reachability, RBAC,
confinement, limits), then creates a Pod, runs `cloop version` in it, and
deletes it.

### The git proxy and the Kubernetes access monitor

Two monitors run inside the hub process and keep a credential there so the
sandbox doesn't hold it: the [git interception proxy](../docs/architecture/git-proxy.md)
for GitHub tokens, and the [Kubernetes access monitor](../docs/architecture/kubernetes-access.md)
("kube guard") for kubeconfigs. Each is a TLS listener on its own port, on the
hub Pod and its Service. Both are off by default (turning one on changes the
URL a sandbox's git or kubectl talks to), and both need a certificate. The
simplest is the hub's own (`executor.monitorTLS.auto`):

```bash
helm upgrade cloop deploy/helm/cloop-hub --reuse-values \
  --set executor.gitProxy.enabled=true \
  --set executor.kubeGuard.enabled=true \
  --set executor.monitorTLS.auto=true
```

That is the whole evaluation setup, and CI runs it end to end on kind
([`tests/kube`](../tests/kube/README.md)): a workload Pod clones and pushes
through the proxy, with the grant's branch list and repository allowlist
enforced on its pushes, and its `kubectl` reaches the cluster only through the
monitor, read-only.

| Value | Default | Notes |
| --- | --- | --- |
| `executor.gitProxy.enabled`, `executor.kubeGuard.enabled` | `false` | Each adds a port to the Pod and the Service, and a section to `config.yaml`. |
| `executor.gitProxy.port`, `executor.kubeGuard.port` | `8443`, `8444` | Both the container port and the Service port. Not 8080, the dashboard's. |
| `executor.gitProxy.advertiseURL`, `executor.kubeGuard.advertiseURL` | `""` | What a sandbox dials. Empty derives `https://<fullname>.<namespace>.svc:<port>`, right for the Kubernetes executor. For edge devices outside the cluster, set a name they resolve and a route to this port; the generated certificate adds its host. |
| `executor.gitProxy.allowedRefs` | `[]` | Empty means `refs/heads/cloop/**`. A grant can narrow it, never widen it. |
| `executor.gitProxy.sessionMinutes`, `executor.kubeGuard.sessionMinutes` | `0` (60) | At most 720. The deadline for a sandbox's access. |
| `executor.kubeGuard.verbs`, `.namespaces`, `.resources` | `[]` | A hub-wide ceiling on every grant. Empty lets each grant decide; a grant with no verbs is read-only. |
| `executor.kubeGuard.auditAllowed` | `false` | Audit every forwarded request, not only refusals. |
| `executor.monitorTLS.auto` | `false` | The hub issues both certificates itself (`tls: auto`): a CA minted at first start, its key sealed under `CLOOP_SECRET_KEY` in the hub's database (so every replica serves the same identity, and a volume backup carries it), and a 72-hour leaf per monitor, renewed by the cluster leader. Nothing to create or rotate, no ConfigMap, no `git_ca_bundle`: each workload Pod gets the CA from its run's lease Secret. |
| `executor.monitorTLS.existingSecret` | `""` | A `kubernetes.io/tls` Secret for the Service's names, as cert-manager writes, for a cluster that already runs it. |
| `executor.monitorTLS.selfSigned` | `false` | The chart generates a CA and certificate and keeps them across `helm upgrade` by reading its Secret back. A renderer without cluster access (Argo CD, `helm template`) gets a new CA every render; use `existingSecret` there. |
| `executor.monitorTLS.caBundle` | `""` | With `existingSecret`: the CA as PEM, which the chart delivers to the Pods and the kube guard embeds in the kubeconfigs it issues. |
| `executor.monitorTLS.workloadCAConfigMap`, `.workloadCAKey` | `""`, `ca.crt` | With `existingSecret`: a ConfigMap you maintain in the workload namespace (as trust-manager produces), instead of `caBundle`. |
| `executor.monitorTLS.publiclyTrusted` | `false` | With `existingSecret`: the certificate chains to a CA the workload image already trusts; nothing is delivered. |
| `extraCACerts.configMap` | `""` | CAs the hub trusts for its own outbound TLS, added to the image's bundle, such as a private CA for a forge the proxy forwards to or for an identity provider. |
| `hostAliases` | `[]` | `/etc/hosts` entries for the hub Pod. |

**How the Pods trust the proxy.** A sandbox's git verifies the proxy's
certificate, and no public CA certifies an in-cluster name like
`cloop-hub.cloop.svc`. Under `monitorTLS.auto`, the hub hands each workload Pod
its CA in the run's lease Secret, mounted at `/etc/cloop/hub-ca/ca.crt` and
trusted for the proxy's URL only. The chart renders nothing for it. Otherwise
the chart writes the CA into a ConfigMap in the workload namespace
(`<fullname>-monitor-ca`), and `executors.kubernetes.git_ca_bundle` has the
driver mount it into every workload Pod at `/etc/cloop/git-ca/ca.crt` and point
git at it for the proxy's URL only (`http.<url>.sslCAInfo`). Other hosts keep
the image's trust store, so cloning directly from another forge still works.
The kube guard needs none of this: a kubeconfig carries its own CA, and the
monitor embeds the chart's.

**With the egress filter on**, workloads must still reach the monitors: list
the hub Pods' range (the pod CIDR) in `executor.kubernetes.egressFilter.cidrs`
and the monitors' ports in `.ports`. The chart refuses a filter whose ports
leave out the proxy or the monitor.

**Upgrading from chart 0.2.0** with `--reuse-values` works: the old values lack
`executor.gitProxy`, `executor.kubeGuard` and `executor.monitorTLS`, and the
templates fill in the defaults.

**Rotation.** The monitors read their certificate at start. After cert-manager
renews an `existingSecret`, restart the hub (or let a reloader do it). A
changed `caBundle` rolls the Pods automatically.

### Sealing keys in a KMS

With `kms.enabled=true`, the secret store's key-encryption keys live in an
external key-management service instead of being derived from
`CLOOP_SECRET_KEY`. Each key is random, the database keeps only the KMS's
ciphertext of it, and a copy of the volume and the Secret opens nothing without
the KMS.

**A KMS v2 plugin sidecar** (`kms.provider: kmsv2`, the default) is the plugin
the API server uses for encryption at rest: Azure Key Vault, AWS KMS, Google
Cloud KMS or Vault. The chart runs it as a second container sharing an
in-memory emptyDir with the hub at `kms.kmsv2.socketDir`. Only this Pod's
containers can reach the socket, and the plugin, not the hub, holds the cloud
credential. For Azure:

```yaml
kms:
  enabled: true
  movingFromPassphrase: true        # step 1 of the move; false after the retire step
  plugin:
    image: mcr.microsoft.com/oss/azure/kms/keyvault:v0.8.0@sha256:<digest>
    args:
      - --listen-addr=unix:///var/run/kmsplugin/socket.sock
      - --keyvault-name=<vault>
      - --key-name=<key>
      - --key-version=<version>
      - --config-file-path=/etc/kubernetes/azure.json
      - --healthz-port=8787
    volumeMounts: [{name: azure-config, mountPath: /etc/kubernetes, readOnly: true}]
    volumes: [{name: azure-config, secret: {secretName: kms-azure-json}}]
```

`deploy/terraform/azure-entra-id/modules/key-vault-kms` creates the key, grants
the plugin's identity wrap and unwrap on it, and renders these values
(`helm_values_yaml`). Pin the plugin image yourself, by digest, to the version
you run.

**Vault or OpenBao Transit** (`kms.provider: transit`) takes
`kms.transit.address`, `key`, and either `tokenSecret.name` (a Secret you keep
renewed, mounted as a file) or `kubernetes.role` (Vault's Kubernetes auth
method; the chart projects a service account token with the audience
`kubernetes.audience`, not the API server's). `caConfigMap` adds a private CA.

A hub that can't reach its KMS refuses to start after `kms.startupTimeout`
(default 30s) and never falls back to the passphrase. The
[runbook](../docs/operations/runbook.md#keys-in-a-kms) covers moving onto a
KMS, the `cloop hub key rotate --retire-previous` step and moving back. For
moving off a KMS, `kms.previous` takes a `secrets.kms_previous` block, and
`kms.plugin.extraContainers` a second plugin.

### Notable values

| Value | Default | Notes |
| --- | --- | --- |
| `config.allowHostProcess` | `false` | Leave it. |
| `config.fromConfigMap` | `true` | Renders `config.yaml` into a read-only ConfigMap, so the hub can't rewrite its own execution policy. `false` doesn't mean "same hub, editable config": no config reaches the hub, so cloop's permissive defaults apply and host execution is allowed. Use it only if you write a config into the volume yourself. |
| `executor.kubernetes.image` | `""` | Falls back to the distroless hub image: enough for `cloop executor test` to pass, not to run a real task. Point it at an image with your toolchain and cloop on `PATH`. |
| `oidc.defaultRole` | `none` | If everyone lands on an empty dashboard, this is working. Add a `roleMappings` entry; don't lower the default. |
| `secrets.existingSecret` | — | The production path. |
| `secrets.create` | `false` | Evaluation only: values end up in the release manifest and in `helm get manifest`. |
| `persistence.enabled` | `true` | `false` means an emptyDir: every restart discards all projects, tasks and sealed secrets. |
| `kms.enabled` | `false` | Hold the secret store's keys in a KMS (above). The chart refuses a plugin sidecar with no image, Transit with no way to authenticate, and a KMS whose config can't reach the hub. |

### Refusals

The chart fails the render instead of installing something broken. All the
guards live in [`templates/_validate.tpl`](helm/cloop-hub/templates/_validate.tpl),
which is always included, so turning off an optional template can't remove one.

| Refused | Because |
| --- | --- |
| No secret source, or both | `CLOOP_SECRET_KEY` must come from exactly one source. |
| `secrets.create` with no `secretKey` | That is the broker master key. |
| `secrets.create`, no OIDC, no `uiToken` | A hub with no authentication at all: cloop treats an empty token as "auth not required". |
| `oidc.enabled` with no `issuer` | Discovery has nowhere to go. |
| `oidc.enabled` with `config.fromConfigMap=false` | No OIDC settings would reach the hub, so the release would report SSO and serve token auth. |
| `executor.kubernetes` RBAC with no named ServiceAccount | The RoleBinding would target `default`, granting Pod create/delete to every Pod in the namespace that does not name an account. |
| `persistence.existingClaim` with `enabled=false` | The claim would be ignored, and the hub would run on an emptyDir while appearing to use your volume. |
| More than one replica (or `strategy.type=RollingUpdate`) without persistence | Each Pod would run on its own emptyDir: separate hubs with separate databases behind one Service. |
| More than one replica with `persistence.accessMode=ReadWriteOncePod` | Only one Pod could mount the volume; the others would never start. |
| `ingress.host` ≠ the host in `config.externalURL` | The login would loop back to the sign-in page without an error. |
| A monitor with no certificate, or two certificate sources (`auto`, `existingSecret`, `selfSigned`) | The session token travels with every request, so the hub won't start a monitor without TLS, and exactly one source decides which certificate it serves. |
| `auto` with `caBundle`, `workloadCAConfigMap` or `publiclyTrusted` | The hub issues the certificate and delivers its own CA, so each would describe one that isn't in use. |
| A monitor's `advertiseURL` that is not a bare `https://` URL | http would expose the session token, and a path would be read as part of every repository's path. |
| Both monitors on one port, or either on 8080 | One listener per port; 8080 is the dashboard's. |
| `sessionMinutes` outside 0–720 | A session longer than a working day amounts to handing over the credential itself. |
| `executor.gitProxy` for the Kubernetes executor with an `existingSecret` and no way for Pods to trust it | Every Pod's git would refuse the proxy at its first clone. Set `caBundle`, `workloadCAConfigMap` or `publiclyTrusted`. |
| `selfSigned` with `caBundle`, `workloadCAConfigMap` or `publiclyTrusted` | Each would describe a certificate that isn't the one in use. |
| A `caBundle` that is not PEM | — |
| `executor.kubernetes.egressFilter` whose `ports` leave out a monitor's port | Workloads couldn't reach the monitor their credential is routed through. |
| A monitor with `config.fromConfigMap=false` | Its section would never reach the hub. |

### TLS

The Ingress terminates TLS, and the hub speaks plain HTTP inside the cluster.
Your Ingress controller must set `X-Forwarded-Proto: https` (most do by
default, including nginx-ingress and Traefik), and the hub trusts it only from
an address in `config.trustedProxies` (rendered to `ui.trusted_proxies`). The
default lists the private ranges pod networks use. Narrow it to your
controller's pod CIDR, since any pod in a listed range can claim any scheme,
host and client address. From other peers, the hub ignores
`X-Forwarded-*`: it treats the request as plaintext, refuses `/install.sh`,
offers no one-line installer at enrollment, and keys every client's rate limit
and sign-in lockout on the controller's address. The session cookie is
`Secure` regardless: the chart sets `cookie_secure: always`, and an https
callback URL implies it.

The chart's default annotations also raise the proxy read timeout to an hour
and the body-size limit to 10 MiB. Both are ingress-nginx annotations, so
translate them for other controllers. The dashboard is WebSocket-first, so with
the usual 60-second read timeout it loads and then stops updating without an
error, which looks like a cloop bug. With ingress-nginx's 1 MiB default body
size, the proxy rejects requests between 1 and 10 MiB with a 413 the hub never
sees or records.

`ingress.className` defaults to empty, meaning "use the cluster's default
IngressClass". Check that one exists (`kubectl get ingressclass`):
ingress-nginx v1+ ignores Ingresses without a class unless started with
`--watch-ingress-without-class`, and nothing reports it. The object is created,
`helm install --wait` succeeds, and the hub is unreachable.

---

## Kubernetes: the executor controller chart

An executor pool's runners can be Pods: `cloop executor controller` watches
ExecutorPool objects in its namespace, starts a runner Pod for each queued run
the pool can take, and retires idle runners when the demand falls. The chart
in [`helm/cloop-executor-controller/`](helm/cloop-executor-controller/)
installs it.

The quickest way to install it is to let the hub write the commands. The
Executors tab's **+ Add Kubernetes pool**, or
`cloop executor pool create <name> --max-runners N`, creates the pool, its
access list and its controller credential, and prints the commands below with
the hub's URL, its certificate pin and the credential filled in. They install
the hub's own copy of this chart, which it serves at
`/charts/cloop-executor-controller.tgz`, so the controller is the hub's build
and no checkout is needed. The credential is shown once.

By hand, give it a namespace of its own, separate from the hub's:

```bash
kubectl create namespace cloop-runners
kubectl label namespace cloop-runners pod-security.kubernetes.io/enforce=restricted

# The pool's controller credential, minted on the hub for the pool.
kubectl -n cloop-runners create secret generic cloop-pool-credential \
  --from-literal=credential='cloop_pool1_...'

helm install runners deploy/helm/cloop-executor-controller -n cloop-runners \
  --set pool.create=true \
  --set pool.hubURL=https://cloop.example.com \
  --set pool.credential.existingSecret=cloop-pool-credential
```

What it installs:

- The ExecutorPool CRD, from the chart's `crds/` directory. Helm installs a
  chart's CRDs on the first install and never upgrades them, so apply the new
  one yourself when a release changes it:
  `kubectl apply -f deploy/helm/cloop-executor-controller/crds/`.
- Two controller replicas. A Lease elects the one that scales, and the other
  takes over when it goes. The Pods meet the restricted Pod Security profile
  and are probed on the controller's `/healthz` and `/readyz`; `/readyz`
  answers once the controller's caches have synced.
- One Role in the release namespace, bound to the controller's ServiceAccount.
  It holds the rules `cloop executor controller rbac` prints and no others:
  Pods, Secrets and PersistentVolumeClaims for the runners and their volumes,
  Events, the Lease, and ExecutorPools with their status. Nothing is
  cluster-wide. Kubernetes can't limit a list of Secrets to a label, so the
  Role can read every Secret in its namespace. Keep nothing else there.
- A ServiceAccount for the runners, bound to nothing, whose token is not
  mounted. A pool can ask for the token with
  `template.automountServiceAccountToken`; then bind that account to exactly
  what the runs need, because model-written code will hold it. The controller
  refuses a pool whose runners would run as the controller's own account.
- With `pool.create`, an ExecutorPool built from `pool.*`. The credential comes
  from `pool.credential.existingSecret`, or from `pool.credential.value`, which
  the chart writes to a Secret (for evaluation, since the value then sits in
  your values file and the release manifest).

Two settings tighten it further:

- `requireDigest=true` refuses to render unless the controller's image is
  pinned (`image.digest`) and the pool's runner image is a digest, empty, or
  one of cloop's own images by tag. Empty means cloop's harness image. The
  controller resolves cloop's own images to a digest and verifies them, so
  their runner Pods carry the digest either way. It also starts the controller
  with `--require-image-digest`, so a pool created another way that names any
  other runner image by tag is marked Invalid.
- `networkPolicy.enabled=true` adds a NetworkPolicy that lets runner Pods reach
  the hub (`networkPolicy.hub`: selectors for an in-cluster hub, CIDRs for one
  outside, and its ports) and DNS (`networkPolicy.dns`; set its `ports` to
  5353 on OpenShift), and nothing else. Nothing may connect to a runner. A run
  then gets repositories through the hub's git proxy and anything else through
  its egress proxy. Your CNI enforces the policy: flannel and kindnet don't,
  and some CNIs don't filter traffic to the node's own addresses.

The render refuses values that wouldn't work or would widen the controller's
reach: more than one replica without leader election, the controller running
as the namespace's `default` account, runners running as the controller's
account or as `default`, a resync under the controller's 30-second floor, a
pool with a plaintext hub URL or no credential, a template variable that reads
the credential's Secret, and a NetworkPolicy with no way to the hub, no
resolver, or a `/0`. With leader election off, the Deployment replaces its Pod
by stopping the old one first, since two unelected replicas would both scale.
Install one release per namespace.

---

## What CI checks

The `deploy-artifacts` job in [`../.github/workflows/ci.yml`](../.github/workflows/ci.yml)
catches what `go build` can't, such as an image that won't start, a chart
whose manifests the API server rejects, or a `securityContext` the container
can't run under. It runs the artifacts:

1. Builds the image and asserts UID 65532 and the OCI labels.
2. Runs the container with `--read-only --cap-drop ALL --security-opt
   no-new-privileges`; asserts `/healthz` and `/readyz` return 200, that
   unauthenticated `/api/state` returns 401, and that the in-image
   `cloop hub healthcheck` works. Then runs it without `CLOOP_UI_TOKEN` and
   asserts that it refuses to listen on every interface, saying why.
3. Runs `cloop hub bootstrap` and asserts that the generated config still
   contains `allow_host_process: false` and `default_role: none`, and that
   `hub.env` is 0600 (a golden test in `cmd` pins the whole file, including
   both monitors on with `tls: auto`).
4. Runs `helm lint` across the interesting value sets and asserts that the
   chart's guards still refuse every configuration in the table above, and that
   it renders with the defaults `helm upgrade --reuse-values` sees on a release
   from an older chart, which lacks every key added since.
5. Starts a kind cluster, runs `helm template | kubectl apply --dry-run` client-side and
   server-side, installs the chart, and waits for readiness.
6. Asserts with `kubectl auth can-i` against the installed release that the
   executor Role grants the verbs the driver calls and denies all others:
   `create get list watch delete` on `pods`, `get` on `pods/log`,
   `create patch delete` on `secrets` and `create delete list` on
   `networkpolicies`, in the workload namespace only. A `patch` on
   `networkpolicies`, which would widen a running sandbox's firewall, fails the
   job. The same comparison runs in Go against the rendered chart
   (`pkg/executor/kubernetes/rbac_test.go`), from the table the driver prints
   its RBAC remedies from.
7. Runs a real workload through the in-cluster executor, then the driver's
   opt-in real-cluster tests: a per-run Secret is garbage-collected with its
   Pod, the workload's environment comes from the run's lease Secret and is
   never a value in the Pod object, and a harness whose Secret is gone fails
   with an error naming it.
8. Renders the credential monitors and asserts the hub's config, the Service
   ports, the certificate's names and the workload namespace's CA (under
   `monitorTLS.auto`: `tls: auto` with no certificate Secret, CA ConfigMap or
   `git_ca_bundle`). Then runs [`tests/kube`](../tests/kube/README.md) on a
   `monitorTLS.auto` release: a Pod clones and pushes through the git proxy,
   trusting the hub's CA for its URL only, and runs `kubectl` through the
   Kubernetes access monitor, and the test then checks the forge, the audit
   trail and the cluster.
9. Lints and renders the executor controller chart, installs it on the kind
   cluster in a namespace that enforces the restricted Pod Security profile and
   waits for both replicas. It asserts with `kubectl auth can-i` that the
   controller's account holds exactly the verbs it calls in its namespace and
   nothing anywhere else, that the runners' account holds nothing, and that a
   pool created from values gets its status written. The Go tests in
   `pkg/kubecontroller/helm_test.go` hold the rendered Role to the
   controller's rules and to a fixed ceiling, and check the rest of the chart.

---

## Troubleshooting

**Login redirects back to the sign-in page with no error.** The redirect URL
registered at your IdP doesn't match `config.externalURL` + `/auth/callback`.
The chart catches the Ingress-host case at render time, but not a mismatch at
the IdP.

**Dashboard loads but never updates.** The WebSocket is being cut. Raise the
proxy read timeout and make sure the `Upgrade` and `Connection` headers are
forwarded.

**`no executor available … no default executor configured`.** Strict mode
working as intended: nothing may run on the hub host, and no isolated executor
is configured yet. Enable `executor.kubernetes` or the container executor, or
enroll a remote agent with `cloop executor enroll`.

**SQLite permission errors on startup.** The state volume isn't writable by
UID 65532. In Kubernetes, check `podSecurityContext.fsGroup`. In Docker, check
that the volume is mounted at `/var/lib/cloop`, not somewhere the image didn't
create.

**`in_cluster is set but the ServiceAccount is unusable`.** The Pod has no
projected token. Set `serviceAccount.automountServiceAccountToken=true`. The
chart only mounts it when the Kubernetes executor is enabled, since a hub that
can't use a cluster credential shouldn't carry one.
