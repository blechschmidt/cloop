# cloop documentation

These pages are written from the code, and CI checks that they keep up with it.
For example, the `docs-drift` check fails the build when a new executor
backend, a new kind of secret or a new role ships without being documented
here (see [`tests/docs/drift_test.go`](../tests/docs/drift_test.go)).

New to cloop? Read [your first project](getting-started/first-project.md), then
[how cloop works](getting-started/concepts.md). The rest of this page assumes
you have run cloop at least once.

This page is also the site's table of contents: the menu on the published site
is generated from the sections and links below, so a new page appears in the
menu as soon as it is listed here.

## Getting started

Seven pages, best read in order. They are also listed on the
**[getting started](getting-started/README.md)** page.

- **[Installation](getting-started/installation.md)**: what you need,
  `go install`, building from source, the container image and shell
  completion.
- **[Your first project](getting-started/first-project.md)**: a complete first
  run. You set a goal, cloop turns it into a plan and works through it, and you
  watch it, change it and stop it.
- **[How cloop works](getting-started/concepts.md)**: what a task is, how cloop
  picks the next one, how it knows a task is finished, what happens when one
  fails, and what auto-evolve does when the plan runs out.
- **[Providers](getting-started/providers.md)**: the model backends cloop can
  use, how it decides which provider and model to use, and the environment
  variables that override that choice.
- **[Web dashboard](getting-started/web-ui.md)**: `cloop ui`, what each screen
  shows, and what to set up before anyone else can reach it.
- **[Dashboard walkthrough](getting-started/walkthrough.md)**: the dashboard in
  screenshots. Choose where work may run, create a project that runs there, add
  tasks and start it. Includes enrolling a remote machine.
- **[Working from a terminal](getting-started/terminal.md)**: signing your
  terminal in to a hub with `cloop login` (you approve a code in your browser),
  then using `cloop remote` for projects, tasks, runs and live logs,
  `cloop task attach`, `cloop whoami` and `cloop logout`. Also covers where the
  credential is stored and
  [what the approval page tells you](getting-started/terminal.md#what-the-approval-page-is-telling-you).

## Architecture

- **[Component and security architecture](architecture/README.md)**: an
  overview of the whole system. It covers the processes cloop runs as, what
  each package does, what the hub stores, how a run gets from **Start** to a
  commit, and how the security pieces fit together: trust boundaries, keys,
  sandboxes, and the proxies that keep credentials on the hub. Start here; the
  other pages in this section and under Security each go into one part in
  depth.
- **[Executors](architecture/executors.md)**: how a task gets from the hub to a
  sandbox and back. The `Executor` interface, the four backends (`localprocess`,
  `container`, `remote`, `kubernetes`), how a backend is chosen for a task,
  how the project's code gets into the sandbox, health checks and failover. It
  also explains
  [sandbox network isolation](architecture/executors.md#sandbox-network-isolation)
  (the `--internal` network, the host's nftables rules and the per-Pod
  `NetworkPolicy`) and how machines behind NAT enroll as executors.
- **[Git proxy architecture](architecture/git-proxy.md)**: how the git
  interception proxy (see Security, below) is built into the hub and how each
  kind of sandbox reaches it. Covers the two ways git traffic goes through it,
  what each executor backend does, which files and variables a sandbox gets,
  how long a session lasts, and the
  [limits that remain](architecture/git-proxy.md#limits-that-remain).
- **[Kubernetes access monitor](architecture/kubernetes-access.md)**: how a
  sandbox can be allowed to read one namespace of a cluster, and nothing else,
  without ever holding a credential for the cluster. A proxy on the hub checks
  every API request before adding the real credential. Also covers
  [turning it on](architecture/kubernetes-access.md#turning-it-on) with
  `executors.kube_guard` and the grant's `--verbs`. Off by default.
- **[Hub cluster](architecture/hub-cluster.md)**: running several `cloop ui`
  processes as one hub behind a load balancer. What a cluster needs (one
  database, one kernel), what the members share, which requests are forwarded
  to which member, what happens to a run when its member dies or is upgraded,
  and the [limits](architecture/hub-cluster.md#limits).

## Reference

- **[Per-project sandbox](reference/sandbox.md)**: `.cloop/sandbox.yaml`, a
  file committed to the repository that sets the image, setup steps, allowed
  environment variables, resource limits, capabilities and mounts for one
  project's tasks. What a project can tighten but never loosen, which executor
  supports which field, and how pinning an image digest keeps runs
  reproducible.
- **[Configuration](reference/configuration.md)**: executors, sandbox images,
  transport security, single sign-on and TLS, including
  [IP-layer egress filtering](reference/configuration.md#ip-layer-egress-filtering)
  with the `egress_filter` keys for the container and Kubernetes backends.
- **[Decision records](reference/adr.md)**: `cloop adr`, for recording why the
  system is built the way it is. A decision moves from Proposed to Accepted to
  Superseded; reversing one means writing a new record that replaces it.
- **[Commands](reference/commands.md)**: every CLI command, including
  [`cloop egress firewall`](reference/commands.md#cloop-egress-firewall), which
  shows the packet filter a grant turns into and tells you whether a given
  address would be let out.
- **[HTTP API](reference/http-api.md)**: every endpoint of both HTTP servers,
  with the permission each one requires. Generated from the route tables, so a
  new route cannot ship undocumented. The hub also serves it as OpenAPI at
  `GET /api/openapi.json`.
- **[Audit events](reference/audit-events.md)**: every action the hub can write
  to the `event_type` column of `audit_events`: what triggers it, what it
  records, who may read it, and how stable its name is. Read this before you
  write detection rules for a SIEM. Generated from the code, like the HTTP API
  page.
- **[Credential patterns](reference/credential-patterns.md)**: every kind of
  credential that `cloop audit`, the provider-call audit, the secret broker and
  browser telemetry recognise and redact: GitHub tokens, cloop's own tokens,
  cloud and model provider keys, JWTs, private keys and kubeconfig credentials.
  Generated from the code.

## Security

- **[Security model](security/model.md)**: the trust boundaries and how each
  one is authenticated, why nothing runs on the hub's host, how revoking access
  works, how a credential reaches exactly one process, roles and permissions,
  and a table that lists the test in `tests/security/` behind each guarantee.
  It also covers
  [the network a sandbox sits on](security/model.md#the-network-the-sandbox-sits-on),
  [how spending is attributed to people](security/model.md#who-spent-it-per-identity-attribution),
  and [knowledge sources](security/model.md#knowledge-sources): where a
  Confluence or Jira credential is kept, how projects are kept apart, and what
  happens when retrieved text tries to give an agent instructions.
- **[Threat model](security/threat-model.md)**: the threats at each trust
  boundary, what mitigates them and what risk remains, plus
  [two vulnerabilities found while building the egress filter](security/threat-model.md#vulnerabilities-found-while-building-this).
- **[Per-user Claude Code logins](security/claude-code-identity.md)**: on a hub
  with single sign-on, each person gets their own Claude Code login for the
  `claudecode` provider, instead of everyone sharing one. Explains why an
  exported `CLAUDE_CODE_OAUTH_TOKEN`
  [overrides all of this](security/claude-code-identity.md#the-ambient-token-outranks-the-directory),
  and what happens to a login when someone leaves. Automatic when OIDC is on.
- **[Per-person Copilot credentials](security/copilot-identity.md)**: the same
  for the `copilot` provider. Each person's Copilot credential is a personal
  secret granted to a project, and work on the hub's host never uses the hub's
  own `copilot login`, `GH_TOKEN` or `GITHUB_TOKEN`.
- **[Git interception proxy](git-interception-proxy.md)**: letting a sandbox
  push to some branches and not others without giving it a credential that
  could reach the others. A proxy run by the hub checks every branch a push
  updates. Includes [how to run it](git-interception-proxy.md#operating-it)
  with `executors.git_proxy`. Off by default.

## Guides

- **[Device forwarders](guides/device-forwarders.md)**: a small program you
  install on an on-premises machine to share one USB device or network
  interface with the hub over a single outbound connection, so that an agent
  in a cloud sandbox can use local hardware.
- **[Developing features in parallel](guides/features.md)**: several lines of
  work on one repository at once, each in its own git worktree and branch, with
  its own task list and settings, and opened as a GitHub pull request when
  done.
- **[Requirements](guides/requirements.md)**: writing down what the project
  must do, with or without tests, and checking that it still does. Covers the
  Requirements tab and `cloop requirements`, letting the model draft
  requirements from a specification, holding tasks to their requirements, and
  keeping requirements as code in `.cloop/requirements.yaml`.
- **[Knowledge sources: Confluence and Jira](guides/knowledge-sources.md)**:
  letting agents read what your organisation has written down. Setting up a
  read-only account, connecting Confluence or Jira (Cloud or Data Center),
  choosing which spaces or projects to index, binding sources to projects, and
  what an agent sees during a run.
- **[Task attachments](guides/attachments.md)**: files a run produces for
  people to look at (reports, charts, screenshots, exports, logs), attached to
  the task. Where an agent puts them, `cloop task attachments`, and how they
  appear in the dashboard.
- **[Stopping a run for review](guides/human-review-gates.md)**: human review
  gates in the task list. A run stops at one until someone approves it, so you
  can check the work above it and add or change tasks before the run goes on.
  Covers adding and moving gates, approving them and what remote executors
  need.
- **[Reviewing tasks before they are published](guides/review-gate.md)**: the
  review gate, where a second model (which can differ from the one doing the
  work) reads each task's changes before anything is pushed or merged. Covers
  the `fix`, `block` and `advisory` modes.
- **[Done means committed](guides/done-means-committed.md)**: counting a task as
  done only once its changes are committed, and optionally pushed, instead of
  taking the agent's word for it. Changes that were already there and files
  under `.cloop/` are never held against a task.
- **[Secrets and egress](guides/secrets.md)**: giving tasks access to a GitHub
  repository or token, a kubeconfig, a registry login, environment variables
  or the Internet, with expiry times and limits, and real command output.
- **[Running an agent in CI](guides/ci-pipelines.md)**: letting a GitHub
  Actions job use Claude through the hub, so the repository doesn't need an
  `ANTHROPIC_API_KEY` secret. Covers OIDC federation, which pipelines are
  allowed, the workflow step to paste, and how to find out why a job was
  refused.
- **[Proving a commit reproduces](guides/reproduce.md)**:
  `cloop task reproduce` runs a task again in a fresh sandbox and compares the
  resulting commit with the original, using your own test suite to judge
  whether they are equivalent.
- **[Kata Containers](guides/kata.md)**: running each sandbox in its own
  lightweight VM with its own kernel. Installing Kata, setting it up with docker
  or podman, what it needs from the host, the Kubernetes path, and how to check
  that a workload really runs in a VM.
- **[Critical hosts as executors](guides/enterprise-hosts.md)**: running agent
  tasks on a powerful machine without letting them reach the rest of your
  network. Per-project repository access, a firewall that allows the Internet
  but blocks private addresses, a gVisor sandbox that only sees one mounted
  directory, and passing a serial port, GPU or TUN device into it.
- **[Virtual executors](guides/virtual-executors.md)**: several sandboxes on one
  enrolled machine, each with its own container engine and runtime, its own
  firewall rules, and its own USB devices (a hardware security module or a
  serial adapter, for example). Explains why the agent needs `CAP_NET_ADMIN`.
- **[Firewall rules: devices, virtual executors and projects](guides/firewall.md)**:
  how an administrator's rules for a machine set the limit for every sandbox on
  it, and how virtual executors and projects can only narrow those rules
  further.
- **[Following the hub's build: the edge channel](guides/edge-channel.md)**:
  keeping enrolled machines on the same build as the hub, signed by CI and
  upgraded from the Executors panel. Covers `edge.yml`, opting a machine in,
  rolling back, and what the channel does not promise.
- **[SCIM provisioning](guides/scim-provisioning.md)**: letting Microsoft Entra
  ID or Okta keep the hub's users and groups up to date at `/scim/v2`, so that
  disabling someone there also locks them out of the hub: their sessions,
  tokens and running tasks end straight away. Covers `offboard_after_days`,
  the `scim_group` claim, and setting up each provider.

## Operations

- **[Operator runbook](operations/runbook.md)**: backups and restores,
  database maintenance, checking and exporting the audit trail, key rotation,
  upgrades, rollbacks, managing executors, and what to do in an incident.
- **[Metrics](operations/metrics.md)**: the `/metrics` endpoint, how to let a
  scraper in, every metric and its labels, which alerts are worth setting up,
  and what happens when a metric produces too many series.
- **[Front-end telemetry](operations/telemetry.md)**: an optional diagnostic
  trail recorded by the dashboard and the display-glasses page. Off by default.
  How to switch it on, how to read a session back, and what is removed before
  anything is stored.
- **[Live sandbox attach](operations/attach.md)**: opening a shell inside a
  running task's sandbox. Who may do it, why a task running directly on a host
  can never be entered, what each executor supports, and how read-only sessions
  work.
- **[Multi-tenant soak](operations/soak.md)**: a long-running concurrency test
  that looks for data leaking between tenants, leaked containers, credentials
  or goroutines, and growth that gets out of hand. How to run it and what it
  found.

## Elsewhere in the repository

- [`README.md`](../README.md): what cloop is, how to install it, and a quick
  start.
- [`deploy/README.md`](../deploy/README.md): the container image, a
  docker-compose stack for trying cloop out, and the Helm chart.
- [`deploy/terraform/azure-entra-id/`](../deploy/terraform/azure-entra-id/README.md):
  a Terraform module that sets up single sign-on with Microsoft Entra ID,
  including cloop's four roles as app roles and the Entra settings that are
  easy to get wrong.
- [`tests/security/`](../tests/security/): the tests behind the security
  guarantees in the threat model.

---

### Reading order

To understand how cloop fits together: the
[component and security architecture](architecture/README.md), then whichever
page it points you to.

To run a hub: the [runbook](operations/runbook.md), then the
[secrets guide](guides/secrets.md).

To assess cloop's security:
[component and security architecture](architecture/README.md#security-architecture),
then the [security model](security/model.md), then the
[threat model](security/threat-model.md). The threat model builds on the
boundaries the security model defines.

To extend cloop: [executors](architecture/executors.md), then the
[no-host-execution guarantee](security/model.md#the-no-host-execution-guarantee).
A new backend has to report its isolation level truthfully, because the policy
that decides where work may run relies on it.
