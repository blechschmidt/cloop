# Git proxy and kube guard on Kubernetes, end to end

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
4. Creates `cloop-e2e-target-<stamp>` and a ServiceAccount that may *edit* it, so a
   refused write can only have been refused by the monitor.
5. `helm upgrade --reuse-values` with `executor.gitProxy`, `executor.kubeGuard`
   (with `auditAllowed`), a self-signed `executor.monitorTLS`, the harness
   image, a per-Pod egress filter opening only the monitors' ports,
   `hostAliases` pointing github.com at the forge and `extraCACerts` trusting
   its CA.
6. Registers a project whose origin is `https://github.com/acme/granted.git`,
   then over the API: the project's goal and its one task (`POST /api/init`,
   `POST /api/tasks`); a `github_pat` secret granted for `acme/granted` only,
   writes limited to `cloop/e2e-allowed-*`; a kubeconfig grant for
   the target namespace with no verbs (read-only); a harness credential; the
   binding to the `kubernetes` executor. Then `POST /api/run`.
7. Reads the run's live log and checks:

| id | passes when |
| --- | --- |
| H1 | the lease's `git-credential-cloop` is mode 0550 in the Pod |
| T1 | no GitHub token is in the environment, the lease directory or the workspace's git config |
| C1 | the chart's CA is mounted at `/etc/cloop/git-ca/ca.crt` and trusted for the proxy's URL only — no `GIT_SSL_CAINFO` |
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
| E1 | (only when the CNI enforces NetworkPolicy) the forge is unreachable from the Pod directly |

   Then: neither the PAT nor the cluster's ServiceAccount token is anywhere in
   the Pod object; the forge holds the allowed
   branch at the probe's commit and not the denied one, and `acme/other` gained
   nothing; the audit trail holds `gitproxy.push_denied` for the denied branch,
   `gitproxy.push_allowed`, a refusal naming `acme/other`,
   `kubeguard.request_denied` for configmaps and `kubeguard.request_allowed` for
   pods; and the run's Pod, Secrets and NetworkPolicy are deleted.
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

A kind node image is about 1 GB on disk and the test images another few
hundred MB, loaded twice; check free space before running it on a small host.
