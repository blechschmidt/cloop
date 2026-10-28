# Git proxy and kube guard on Kubernetes, end to end

Three tests, on a real cluster:

- [`TestGitProxyAndKubeGuardOnKubernetes`](#what-it-builds) runs a workload Pod
  through both monitors on the hub the Helm chart installed — the rest of this
  page;
- [`TestAPodsWorkspaceSurvivesItsHubBeingKilled`](#a-pods-workspace-survives-its-hub-being-killed)
  holds a Pod before its workspace fetch, SIGKILLs the hub and checks the new
  hub process serves the fetch (Task 20455);
- [`TestKubeShareWithAnExecPlugin`](#sharing-a-cluster-whose-kubeconfig-runs-a-plugin)
  shares the cluster with a hub running on the test host, through a kubeconfig
  that signs in only with an exec credential plugin (Task 20416) — the last
  section.

`kube_test.go` runs a workload Pod through the git interception proxy and the
Kubernetes access monitor on a hub that `deploy/helm/cloop-hub` installed, and
checks what the Pod, the forge and the audit trail saw (Task 20385). It is the
Kubernetes counterpart of [the device kit](../../scripts/e2e/gitproxy/README.md),
and it runs in CI on the `deploy-artifacts` job's kind cluster.

It changes the release it is pointed at — both monitors stay on afterwards —
so point it only at a throwaway cluster. CI runs it twice: on the release as
installed, one replica, and again once the job has scaled it to a hub cluster of
three, where a workload's git and kubectl reach members other than the one that
minted their sessions and are forwarded.

## What it builds

| Piece | What it is |
| --- | --- |
| [`forge/`](forge/main.go) | `pkg/secretbroker/secretbrokertest`'s smart-HTTP forge as a server: the stand-in for github.com, honouring one PAT for every repository it serves, so only the proxy can narrow it |
| [`forge.Dockerfile`](forge.Dockerfile) | the forge on alpine with git and git-http-backend |
| [`harness.Dockerfile`](harness.Dockerfile) | the workload image: cloop under test, git, kubectl, and the stand-in `claude` from `scripts/e2e/gitproxy` |
| [`probe.sh`](probe.sh) | the checks, run inside the Pod; one `RESULT` line each |

## What it does

1. Builds both images and loads them into kind.
2. Runs the hub's own NetworkPolicy probe (`cloop hub doctor
   --probe-network-policy`) and logs the verdict. Egress blocking is asserted
   only when the probe proved the CNI enforces policies; otherwise the log says
   it is not asserted.
3. Serves the forge in `cloop-e2e-forge-<stamp>` with a certificate for `github.com`
   from a throwaway CA. `acme/granted` holds one commit and **no `.cloop/`**:
   the project and its task exist only on the hub, so the Pod can only have
   them from the seed the hub sends in the run's lease Secret (Task 20402).
4. Creates `cloop-e2e-target-<stamp>` and `cloop-e2e-second-<stamp>`, and a
   ServiceAccount that may *edit* both, so a refused write — or a refused read
   of the other grant's namespace — can only have been refused by the monitor.
5. `helm upgrade --reuse-values` with `executor.gitProxy`, `executor.kubeGuard`
   (with `auditAllowed`), `executor.monitorTLS.auto` — the hub issues both
   certificates from its own CA, and no `git_ca_bundle` is rendered (checked
   against the release's config) — the harness
   image, a per-Pod egress filter opening only the monitors' ports,
   `hostAliases` pointing github.com at the forge and `extraCACerts` trusting
   its CA.
6. Registers a project whose origin is `https://github.com/acme/granted.git`,
   then over the API: the project's goal and its one task (`POST /api/init`,
   `POST /api/tasks`); a `github_pat` secret granted for `acme/granted` only,
   writes limited to `cloop/e2e-allowed-*`; a kubeconfig grant for
   the target namespace with no verbs (read-only), and the same kubeconfig
   granted again for the second namespace with `create` — one cluster granted
   twice, which the Pod receives as one merged kubeconfig with a context per
   grant (Task 20413); a harness credential; the binding to the `kubernetes`
   executor. Then `POST /api/run`.
7. Reads the run's live log and checks:

| id | passes when |
| --- | --- |
| H1 | the lease's `git-credential-cloop` is mode 0550 in the Pod |
| T1 | no GitHub token is in the environment, the lease directory or the workspace's git config |
| C1 | the hub's CA came from the run's lease Secret to `/etc/cloop/hub-ca/ca.crt` and is trusted for the proxy's URL only — the one `sslCAInfo` in the block, no `GIT_SSL_CAINFO` — and the kube guard, whose leaf the same CA signed, is refused by git |
| WS1, WS2 | the init container provisioned the workspace through the proxy (the `cloop-ws-<handle>` Secret's session username at work), and its `.git/config` holds no credential |
| S1 | the repository tracks no `.cloop/`, the workspace holds the project the hub sent, and git ignores it, so a write-back cannot commit it |
| P1 | `git clone https://github.com/acme/granted` works, through the proxy |
| B1 | a push to `cloop/e2e-allowed-<stamp>` is accepted |
| B2 | a push to `cloop/e2e-other-<stamp>` is refused by the proxy, with a message naming the grant's branches |
| R1 | a push to `acme/other` — which the PAT reaches on the forge — is refused by the proxy |
| K0 | the delivered kubeconfig names the monitor, not the API server |
| K1 | `kubectl get pods` succeeds through the monitor |
| K2 | `kubectl create configmap` is refused by the monitor as read-only — and, checked from outside, no configmap was created |
| K3 | no cluster token (a JWT) is readable in the Pod: not in the environment, the lease directory or the delivered kubeconfig |
| K4 | kubectl sees one context per kubeconfig grant, `current-context` the read-only one and first in `CLOOP_K8S_CONTEXTS`; `kubectl --context` reaches each grant's own namespace through the monitor and is refused, by the monitor, in the other grant's namespace and in `kube-system`; and the second grant's context creates a configmap in its namespace — checked from outside too |
| E1 | (only when the CNI enforces NetworkPolicy) the forge is unreachable from the Pod directly |

   Then: neither the PAT nor the cluster's ServiceAccount token is anywhere in
   the Pod object; the forge holds the allowed
   branch at the probe's commit and not the denied one, and `acme/other` gained
   nothing; the audit trail holds `gitproxy.push_denied` for the denied branch,
   `gitproxy.push_allowed`, a refusal naming `acme/other`,
   `kubeguard.request_denied` for configmaps and `kubeguard.request_allowed` for
   pods, a `kubeguard.request_allowed` for the second grant's configmap and a
   `kubeguard.request_denied` for the first grant's context reading the second
   namespace; and the run's Pod, Secrets and NetworkPolicy are deleted.
8. Checks the round trip (Task 20402): the hub's own plan — the one the
   dashboard renders — shows the task done and attributed to the `kubernetes`
   executor, which can only be true if the run's outcome came back out of the
   Pod's log; the live log says the project state came back, and carries none
   of the frame it came in. Then it presses Start again and checks the second
   run did not execute the task: no probe output in its log, and the task still
   done at the same moment.

## Running it

On a kind cluster with the chart installed the way CI installs it (the
`deploy-artifacts` job in `.github/workflows/ci.yml`):

```bash
kind get kubeconfig --name cloop-ci > /tmp/kubeconfig
CLOOP_KUBE_E2E_KUBECONFIG=/tmp/kubeconfig CLOOP_KUBE_E2E_KIND_CLUSTER=cloop-ci \
  go test ./tests/kube/ -run TestGitProxyAndKubeGuardOnKubernetes -count=1 -v -timeout 28m
```

| variable | meaning |
| --- | --- |
| `CLOOP_KUBE_E2E_KUBECONFIG` | required; without it the test skips |
| `CLOOP_KUBE_E2E_KIND_CLUSTER` | the kind cluster to load the images into |
| `CLOOP_KUBE_E2E_IMAGE_IMPORT` | for any other cluster: a shell command that reads a `docker save` tarball on stdin and loads it onto the nodes, e.g. `docker exec -i k3s ctr images import -`. With neither, the images must already be there |
| `CLOOP_KUBE_E2E_CLOOP_BIN` | a static cloop for the harness image; unset, one is built (CI copies the hub image's) |
| `CLOOP_KUBE_E2E_RELEASE`, `CLOOP_KUBE_E2E_NAMESPACE` | the release, `cloop` in `cloop` by default |
| `CLOOP_KUBE_E2E_KEEP` | leave the forge, the target namespace and the helper Pod behind |
| `CLOOP_KUBE_E2E_NODE_EXEC` | a command prefix that runs a command on the hub's node, for the restart test; `docker exec <node name>` by default |

A kind node image is about 1 GB on disk and the test images another few
hundred MB, loaded twice; check free space before running it on a small host.

## A Pod's workspace survives its hub being killed

[`workspace_restart_test.go`](workspace_restart_test.go) (Task 20455) runs on the
same release, at one replica. A Pod's init container fetches its workspace
through a pinned git proxy session after the dispatch returned; the test makes
the hub die in that window and checks a new hub process serves the fetch.

1. Builds the images (the harness image's `cloop` is
   [`cloop-hold.sh`](cloop-hold.sh), which holds the workspace provisioner of the
   repository `acme/held` until `/tmp/cloop-e2e-release` exists in its container
   and runs everything else at once), serves the forge as github.com with
   `acme/held`, and upgrades the release with the git proxy on.
2. Registers a project whose origin is `https://github.com/acme/held.git`, grants
   it a read-only PAT, a harness credential and the `kubernetes` executor, adds
   one task — a check of the workspace — and presses Start.
3. Waits for the run's Pod to sit in its provisioner, reads the session it holds
   from the `cloop-ws-<handle>` Secret, and SIGKILLs the hub's process from the
   node (`crictl inspect` for its pid, `kill -9`): no shutdown path runs. The
   kubelet starts the container again in the same Pod, on the same database, as
   a new cluster member.
4. Waits for the new process to adopt the run and restore the session — a
   `gitproxy.session_restored` row naming the killed process, and the run's
   owner row naming the new one — then releases the provisioner.
5. Checks that the provisioner exits 0; that the run completes, its check
   finding the forge's commit checked out through the proxy (`HW1`, `HW2`); that
   the hub's plan shows the task done on the `kubernetes` executor, which needs
   the run's outcome to come back out of the Pod; and that the session was
   closed — `gitproxy.session_closed` — once the fetch was confirmed.

It needs to run a command on the hub's node: `docker exec <node>` by default,
which is what a kind node is, or `CLOOP_KUBE_E2E_NODE_EXEC` — `docker exec k3s`
for k3s in docker, whose node name is the container's hostname:

```bash
CLOOP_KUBE_E2E_KUBECONFIG=/tmp/kubeconfig CLOOP_KUBE_E2E_KIND_CLUSTER=cloop-ci \
  go test ./tests/kube/ -run TestAPodsWorkspaceSurvivesItsHubBeingKilled -count=1 -v -timeout 28m
```

About two minutes; most of it is the hub's restart and its adoption of the run.

## Sharing a cluster whose kubeconfig runs a plugin

[`share_test.go`](share_test.go) needs only the cluster, not the chart: the hub
runs on the test host (`cloop ui` with `executors.kube_guard` on, `tls: auto`,
the host executor and the stand-in `claude`), as it would on a developer's
machine. It:

1. creates four namespaces — two to share, one for the ServiceAccount, one for a
   "developer" ServiceAccount holding `admin` in the other three — and a
   kubeconfig whose only credential is a fake exec plugin printing the
   developer's token (`client.authentication.k8s.io/v1`, a relative command
   path, `provideClusterInfo`);
2. runs `cloop remote kube share --access write --sa-namespace … --ttl 10m` and
   checks the plugin was told the cluster, the five objects and their RBAC, and
   that RBAC alone *would* let the ServiceAccount create its own token;
3. grants the share to the hub's project for writes and dispatches a task
   running [`share_probe.sh`](share_probe.sh) — which, besides reading and
   writing, tries every way a write grant could mint a ServiceAccount credential
   of its own (Task 20420); the test then checks from outside that none of those
   objects exists, and that a Deployment the cluster administrator made, running
   as a ServiceAccount of its own, still has its image;
4. waits for the hub to renew the share, then for the first token to expire, and
   has the same run use the cluster again;
5. revokes the share and checks nothing labelled `cloop.dev/kube-share=<id>` is
   left, the secret is gone and the run is cut off;
6. uploads a crafted share: its token is for a ServiceAccount the cluster
   administrator made, an object named like the share's and a decoy labelled
   with its id by another owner sit in its namespace, and its metadata lists
   `cluster-admin`'s binding. Revoked with the administrator's own kubeconfig,
   it deletes nothing and keeps the hub's secret; `--force` deletes the secret
   and still nothing in the cluster. Then the test reads the audit trail,
   including a `kubeguard.request_denied` row for each credential refusal's
   reason.

| id | passes when |
| --- | --- |
| P0 | the run's kubeconfig names the monitor and carries a session token — no JWT there or in the environment |
| P1, P2 | `kubectl get` and `kubectl create configmap` work through the monitor |
| P3 | `kubectl create token <the share's ServiceAccount>` is refused by the monitor, under a write grant whose namespaces include the ServiceAccount's |
| P4 | a raw `POST …/serviceaccounts/default/token` is refused by the monitor |
| P5 | `kube-system` is refused by the monitor |
| P6 | after the token the run's session started with has expired, the run reads and writes again (the hub renewed the share; the session took the new token up) |
| P7 | after `cloop remote kube revoke`, the run can no longer reach the cluster |
| P8 | a `kubernetes.io/service-account-token` Secret is refused by the monitor (`service_account_token_secret`) |
| P9, P10 | a Pod, and a Deployment, naming a ServiceAccount other than the namespace's default are refused (`workload_service_account`) |
| P11 | a Pod mounting the node's `/var/lib/kubelet` through `hostPath` is refused (`host_access`) |
| P12 | `kubectl set image` on a Deployment that already runs as another ServiceAccount is refused — the monitor reads the Deployment before the patch |
| P13 | a RoleBinding is refused (`rbac_binding`) |
| P14 | an ordinary Pod, as the namespace's default ServiceAccount, passes (a server-side dry run, so nothing is scheduled) |

```bash
kind create cluster --name cloop-share
kind get kubeconfig --name cloop-share > /tmp/kubeconfig
CLOOP_KUBE_E2E_KUBECONFIG=/tmp/kubeconfig \
  go test ./tests/kube/ -run TestKubeShareWithAnExecPlugin -count=1 -v -timeout 25m
```

About thirteen minutes, nearly all of it waiting: ten minutes is the shortest
token the TokenRequest API issues, and the API server accepts one for a minute
past its expiry. `CLOOP_KUBE_E2E_CLOOP_BIN` supplies the binary; unset, one is
built. CI runs it in the `kube-share` job on a kind cluster of its own.
