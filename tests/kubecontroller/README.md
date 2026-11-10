# Executor pools on a real cluster, end to end

[`pool_test.go`](pool_test.go) runs an executor pool the way an operator runs
one: the executor controller installed by its Helm chart
(`deploy/helm/cloop-executor-controller`), an ExecutorPool created from the
chart's values, ephemeral runner Pods with their volumes, and a real hub. It
then kills the controller's leader and two runners mid-run and revokes the
controller's credential, and checks what is left on every runner volume.

`pkg/kubecontroller/cluster_test.go` checks the controller against a real API
server with a fake hub. This suite checks the whole loop: a hub, a controller
inside the cluster, and runners that enroll, run a task and report back.

## What it builds

| Piece | What it is |
| --- | --- |
| the hub | `cloop ui` on this host, over TLS (`cloop hub tls-init`), with an admin token, listening on the address the cluster's node reaches this host at: the docker bridge a kind or k3s-in-docker node sits on. Three projects, `web`, `api` and `ops`, each bound to one executor pool (`max_runners` 2) and granted a stand-in Claude credential |
| [`runner.Dockerfile`](runner.Dockerfile) | one image for everything in the cluster: the controller, the runners and the volume scans. It holds the cloop under test, git, and the stand-in `claude` from `scripts/e2e/gitproxy`, which runs the probe a task carries |
| [`probe.sh`](probe.sh) | what each task runs in its runner: one `RESULT` line per check |
| the controller | the chart, two leader-elected replicas, in a namespace that enforces the restricted Pod Security Standard. The pool from its values has `minRunners` 0, `maxRunners` 2, runner volumes on (`size` 1Gi, `maxClaims` 2 by default) and the hub's certificate as `hubCABundle` |

## The phases

Each phase is a subtest, run in order; a failed phase stops the rest, which
build on it.

| Phase | Passes when |
| --- | --- |
| `scale-from-zero` | before anything is queued there is no runner and the pool's status says 0. A queued run of `web` starts one runner Pod, whose configuration Secret is owned by the Pod and immutable; the pool's status counts it; the run reports `S1` (a file and a git commit left in the workspace, which is on the runner's volume); the hub's plan shows the task done on the pool, with the run's output; the hub's record of the runner names the controller's credential, an enrollment, `web` as its project, and its retirement once the run settled. The hub minted one runner for one run |
| `scale-to-min` | the runner's Pod and Secret are gone, the pool's status is back at `minRunners` (0) and Ready, the one volume is Bound, released, and records `web`; the pool has a `ScaledUp` Event |
| `persistence` | `web`'s second task runs on a runner that mounts `web`'s volume unwiped, started with `--holds` and `web`'s tenant, and finds the file (`P1`) and the commit (`P2`) the first run left |
| `isolation` | `api`'s task runs on a fresh volume and `ops`'s on a volume wiped before its runner started, since `maxClaims` leaves no room for a third. Neither runner holds a tenant. Each run finds no other project's file (`I1`), tree (`I2`) or git object (`I3`) anywhere on its volume, then leaves its own (`S1`) |
| `reused-token` | the first runner's token, replayed by a runner started on this host, is refused: the runner reports `refused` and exits non-zero, and the hub logs the token as already redeemed |
| `expired-token` | a runner token minted with a one-second life is refused once it has expired, and the hub logs why. The test then gives the runner back, as a controller does |
| `runner-killed` | a runner Pod is deleted mid-run. The hub retires it as lost with its run and does not move the run off the pool. Started again, the same task's next runner is deleted too. After the second loss the task is quarantined as a suspected node killer, naming both runners, and a `task.quarantine` row is in `api`'s audit trail. No runner starts after that |
| `controller-killed` | while a runner holds a run, the controller replica holding the Lease is deleted with no grace period. The other replica takes the Lease. For the next 70 seconds the runner Pod is the same one and still running, the hub still counts it busy, no other runner is started, and the hub mints none. The new leader's status counts the busy runner. Once the run is released it finishes there (`H1`), and the new leader deletes the runner's Pod and Secret |
| `credential-revoked` | revoking the controller's credential takes the runner it minted with it: `lease.revoke_sent` names the runner, the run never finishes, the Pod goes, and the hub retires the runner as revoked. A runner token minted with the credential and never used is refused, and the hub logs it as revoked. The pool's status goes `Degraded` with `HubRefused`, and a run queued afterwards gets no runner |
| `no-credential-on-any-volume` | every volume the pool kept is released, a killed runner's included (the controller holds a claim whose Pod is gone for three minutes, in case the Pod is still being created). Each is then mounted read-only in a Pod of its own and scanned, after the scan has found a pattern it was given in a file of its own. No file is named like a credential, and none holds any credential the test made or saw (the Claude credential, the pool credential, the admin token, the hub's secret key, every runner token) or the prefix of any kind of credential cloop issues |

The checks inside a run:

| id | passes when |
| --- | --- |
| ENV | the run's working directory is on the runner's volume, `/var/lib/cloop-runner/storage/workspace/<project>` |
| S1 | the run wrote its marker file and committed it |
| P1, P2 | the marker file and the commit of the project's previous run are there |
| I1, I2, I3 | no marker file, no workspace tree and no git object of another project is anywhere on the volume |
| H0, H1 | the run started holding, and was released by the test |

## Running it

On kind:

```bash
kind create cluster --name cloop-pool
(umask 077 && kind get kubeconfig --name cloop-pool > /tmp/kubeconfig)
CLOOP_KUBECONTROLLER_E2E_KUBECONFIG=/tmp/kubeconfig CLOOP_KUBECONTROLLER_E2E_KIND_CLUSTER=cloop-pool \
  go test ./tests/kubecontroller/ -run TestExecutorPoolOnARealCluster -count=1 -v -timeout 28m
```

On k3s in docker, which needs much less disk than kind's node image:

```bash
docker run -d --name k3s --privileged --tmpfs /run --tmpfs /var/run \
  -p 127.0.0.1:16443:6443 rancher/k3s:v1.30.4-k3s1 server --disable traefik --disable metrics-server \
  '--kubelet-arg=eviction-hard=nodefs.available<500Mi,imagefs.available<500Mi' --tls-san 127.0.0.1
docker exec k3s cat /etc/rancher/k3s/k3s.yaml | sed 's#127.0.0.1:6443#127.0.0.1:16443#' > /tmp/kubeconfig
CLOOP_KUBECONTROLLER_E2E_KUBECONFIG=/tmp/kubeconfig \
CLOOP_KUBECONTROLLER_E2E_IMAGE_IMPORT='docker exec -i k3s ctr images import -' \
  go test ./tests/kubecontroller/ -run TestExecutorPoolOnARealCluster -count=1 -v -timeout 28m
```

| variable | meaning |
| --- | --- |
| `CLOOP_KUBECONTROLLER_E2E_KUBECONFIG` | required: cluster-admin on a throwaway cluster. Without it the test skips |
| `CLOOP_KUBECONTROLLER_E2E_KIND_CLUSTER` | the kind cluster to load the image into |
| `CLOOP_KUBECONTROLLER_E2E_IMAGE_IMPORT` | for any other cluster: a shell command that reads a `docker save` tarball on stdin and loads it onto the nodes. One of the two is needed |
| `CLOOP_KUBECONTROLLER_E2E_CLOOP_BIN` | a static cloop for the image; unset, one is built |
| `CLOOP_KUBECONTROLLER_E2E_HUB_ADDR` | the address the hub listens on, which the cluster's Pods must reach. Unset, it is this host's address on the network of the cluster's first node |
| `CLOOP_KUBECONTROLLER_E2E_STORAGE_CLASS` | the runner volumes' StorageClass; unset, the cluster's default, which must provision `ReadWriteOnce` volumes |
| `CLOOP_KUBECONTROLLER_E2E_KEEP` | leave the namespace and the hub's directory behind |

It takes about six minutes, most of it the hub noticing that a killed runner
is gone, which it does by probing every 30 seconds. CI runs it in the
`kube-controller` job, on a kind cluster of its own.

The test creates one namespace, `cloop-xctl-<stamp>`, and removes it with
everything in it when it ends. On the cluster's nodes it leaves the image
`cloop-kubecontroller-e2e:<stamp>`, which a kind cluster takes with it when it
is deleted; on k3s, `crictl rmi` it. The image is removed from the local
docker daemon as soon as the nodes have it.
