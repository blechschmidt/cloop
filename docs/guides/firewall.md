# Firewall rules: devices, virtual executors and projects

Up to four levels decide what a sandbox can reach over IP. Each level can only
narrow the one above it:

| level | who sets it | where |
|---|---|---|
| the executor's configuration | whoever deploys the hub | `executors.container.egress_filter` / `executors.kubernetes.egress_filter` in `config.yaml` (executors on the hub's side only) |
| the **device**'s rule set | an admin (`executor.manage`) | Executors → the device's card → **Firewall** |
| a **virtual executor**'s firewall, or the network a device gives its own sandboxes | an admin | the virtual-executor dialog ([virtual executors](virtual-executors.md)) |
| the **project**'s rule set | the project's maintainers (`config.write` on that project) | the project's Overview → **Network Firewall** |

The device's rule set is the outer limit: nothing that runs on the machine,
directly or under one of its virtual executors, reaches anything it doesn't
allow. A project's rules can narrow its own runs further but never widen them,
which is what makes them safe to hand to a project's maintainers. Otherwise a
maintainer on a device whose admin kept it off `10.0.0.0/8` could give
themselves the operator's network.

## The rules

Every level uses the same form as the virtual-executor dialog: **Allow the
public Internet**, an **allowlist**, a **denylist**, **ports** and **DNS
resolvers** ([the firewall](virtual-executors.md#the-firewall) explains each
field). In short: TCP to the allowed addresses on the listed ports (every port
when the list is empty), UDP and TCP to each resolver's own address and port,
nothing in the denylist, and nothing else.

Only the denylist is inherited. A level's effective denylist is its own plus
those of every level above it, because a deny can only take reach away: a
project doesn't need to copy its device's denylist, and can't undo it. An empty
port list means every port, as on a virtual executor, so under a device that
allows only 443 a project has to list 443. A save that doesn't is refused, and
the error names the ports it may use. A project also names its own resolvers.
The Overview form starts from the rules that govern the project, so you narrow
them by deleting what you don't need.

An empty rule set is different from no rule set. **Remove rules** hands the
level back to the levels above it, while saving with every field empty means
the sandbox can reach nothing.

## Cloud metadata services

An allowlist opens the ranges it names, except that a cloud metadata service is
opened only by an entry for its own address. A metadata service gives whatever
runs on a machine that machine's cloud identity: instance credentials, user
data, a pod's role. So a prefix that contains one (`169.254.0.0/16` around
`169.254.169.254`, `fc00::/7` around AWS's IPv6 `fd00:ec2::254`,
`100.64.0.0/10` around Alibaba Cloud's `100.100.100.200`) opens everything in
the range except the service. Saving such a range without the service is
refused, and the error names the service and both ways to fix it:

```
400 Bad Request
{"error": "allow_cidrs: 169.254.0.0/16 contains 2 cloud metadata services without
  naming them: 169.254.169.252 (GKE metadata server for Workload Identity),
  169.254.169.254 (instance metadata on AWS, Azure, Google Cloud, Oracle Cloud and
  most other clouds). Add their addresses (169.254.169.252/32, 169.254.169.254/32)
  to the allowlist if a sandbox should reach them, or to the denylist so they stay
  closed"}
```

To let a sandbox reach a metadata service, add its `/32` or `/128` to the
**Allowlist**. To keep it closed while allowing the range around it, add its
address to the **Denylist**, or allow a narrower range. A rule set saved before
this check existed still keeps the service closed (the compiled filter drops it
before the allow), and its card says so. Saving it again asks you to resolve
it. `pkg/cloudmeta` has the full table of services cloop knows.

## Containment, and where it is checked

Whether one rule set fits inside another is decided by set arithmetic on what
the rules compile to. "The public Internet" is compared as every address outside
the block set, and an allowed range with a denied hole in it as the range minus
the hole. A rule set that doesn't fit is refused with one reason per thing
outside it:

```
409 Conflict
{"code": "firewall_exceeds_bound",
 "error": "this project's rule set reaches further than the rule set above it (…)",
 "reasons": ["port 22 is not allowed by the governing rule set (443)",
             "10.0.0.0/8 is private (RFC1918/ULA), which the governing rule set does not reach: …"]}
```

The rule is checked three times, and the guarantee rests on the last check:

1. **When you save**, in the same database transaction as the write, so the
   error shows on the form you are looking at.
2. **When a run is dispatched**, against the executor it actually goes to,
   since a project can be bound elsewhere, or its device tightened, after its
   rules were saved. The combined rules travel with the run. A run whose rules
   can't be read, whose levels don't nest, or whose executor can't enforce
   them is refused, and the reason goes to the project's event history. A run
   moved off a failed executor has its rules combined again for the
   replacement, which may be on another device with rules of its own.
3. **In the driver**, immediately before it installs anything. The hub's
   container and Kubernetes drivers, and the agent on a device, check the
   rules again against their own level and the device's rule set. On the hub
   this reads the device's rules as stored at that moment, so a run dispatched
   by a path that skipped step 2 is refused instead of starting outside them.

## Tightening a device

Saving a narrower device rule set narrows everything saved under it, in the
same transaction:

- each virtual executor's firewall is cut down to the part the device still
  allows. An **Unfiltered** virtual executor becomes **Firewalled** with the
  device's own rules, because an unfiltered network can't be limited;
- each project rule set whose runs go to the device, or to one of its virtual
  executors, is cut down to fit.

The dialog lists every change ("Narrowed to fit: …"), and each one is recorded
in the audit trail. Editing a virtual executor narrows the projects on it in the
same way, and so does moving a project to another executor. Clearing a device's
rules narrows nothing.

## Enforcement

| executor | enforces rules by | needs |
|---|---|---|
| hub container executor | a bridge and nftables table for each rule set (`cloop-sbx-<id>-r<fingerprint>`), with the filter in place before any sandbox joins | `nft(8)` and `CAP_NET_ADMIN` on the hub; a rootful engine |
| enrolled device, container mode | the same, on the device | an agent speaking protocol **v15**, with the packet filter granted (`cloop executor agent install --packet-filter`); **v24** to report what it refused |
| virtual executor | the same, on its device | as above |
| Kubernetes | the Pod's NetworkPolicy, with the denylist cut out of every allow | a cluster whose NetworkPolicy enforcement is proven or asserted (`cloop hub doctor --probe-network-policy`) |
| the hub's host-process executor, a device in host mode | nothing | can't enforce rules, so runs are refused while rules apply |

Two rule sets never share a bridge, since the second would replace the first
one's ruleset. The bridge and table are named after the rule set's fingerprint
and removed when the last run on them ends. A rule set that reaches nothing
needs no filter: the run gets no network.

A host interface granted to a project (an L2 passthrough) bypasses any IP
firewall, so a run that carries one is refused while rules apply.

## Diagnosing a blocked connection

A connection the firewall denies is refused at once. TCP gets a reset, so
`connect` fails with `ECONNREFUSED`. Everything else gets an ICMP
"administratively prohibited", so a UDP socket reads `EHOSTUNREACH` (IPv4) or
`EACCES` (IPv6). Inside the sandbox it looks like this:

```
$ curl -sS -m 6 -o /dev/null https://1.0.0.1/
curl: (7) Failed to connect to 1.0.0.1 port 443 after 0 ms: Couldn't connect to server
```

The failure is immediate: no six-second timeout, and no harness retrying for
minutes. If you'd rather a sandbox couldn't tell a filtered destination from one
that doesn't exist, set **Drop denied connections silently** (`drop_denied` in
the API, `drop_denied: true` under `executors.container.egress_filter`). Levels
below inherit it.

Every deny path also logs the refused packet to an NFLOG group, rate-limited,
under a prefix that names the rule set's fingerprint and the rule. Whoever
installed the ruleset reads the log: the hub for its own container executor,
the device's agent for its sandboxes (protocol **v24**, with no privilege
beyond the packet-filter grant it already needs to install the ruleset). Each
run's refusals are grouped by destination, port, protocol and rule, and show up
in four places:

| where | what you see |
|---|---|
| the run's **Event history** | `blocked 203.0.113.7:443/tcp x14, not in the project's allow list` the first time a destination is refused during a task, and all of the run's refusals when it ends |
| the task's **details → Network** | every destination the task's runs were refused, how often, when and why, and next to them what the [egress proxy](secrets.md#egress-leases) refused (its `egress.*` rows) |
| the project's **Network Firewall** card → **Recently blocked** | the last week's refusals, one line per destination and rule; admins also get **Propose allow rule** |
| the audit trail and the metrics | `run.firewall_denied` (below), `cloop_firewall_denials_total` |

The text after each destination tells you which level to change:

| rule | reads | to let it through |
|---|---|---|
| `default` | "not in the project's allow list", "port 22 is not one the project's allow list opens (443)", "UDP is not allowed: … opens TCP only" | add the address (and the port) to the allowlist of the innermost level that set rules |
| `deny:<range>` | "in device sgx's deny list (203.0.113.0/24)" | take the range out of the named deny list. An allow never overrides a deny |
| `block:<range>` | "private (RFC1918/ULA) range 10.0.0.0/8, which the project's allow list does not name" | add the address to the allowlist. Only an explicit entry opens blocked space |
| `meta:<address>` | "the cloud metadata service at …" | add the service's own address at every level, if the sandbox really needs it |
| `xlat:<range>` | "an IPv6 translation prefix …" | allow the IPv4 range it stands for |

**Propose allow rule** adds the destination as a `/32` (`/128`) to the
project's rule set (its own, or the rules governing it if it has none), with the
port if the rule set lists ports, and saves it through the same check as the
form. A destination the device's rule set doesn't reach is refused with the
reason, and an admin has to widen the device first. It is offered only for
`default` and `block` refusals over TCP, since an allow doesn't open a deny
list, a metadata service or a translation prefix.

About the counts: the log is limited to ten lines a second per deny path, so a
flood counts as at least that rate, not as every packet. A run itemises at most
64 destinations and only counts the rest ("and 120 more refused, counted but not
itemised"). Only addresses, ports and counts are kept: the kernel copies at most
80 bytes of a refused packet, and nothing past the ports is read.

When the list is empty, the card and the task say why:

- **Kubernetes**: "Denials are not observable on this executor", because a
  NetworkPolicy has no portable log of what it refused;
- **a device whose agent is older than protocol v24**: the upgrade it needs,
  worded like every other protocol refusal. Its sandboxes are filtered as
  strictly, but their refusals aren't reported.

The hub's host-process executor and a device in host mode run no sandbox
firewall at all, so nothing is refused and the views show no list.

On the host, the ruleset shows each path's counter and log statement. There is
one table per executor and rule set, `cloop_sbx_<executor>`, suffixed
`_r<fingerprint>` for rules the hub combined (the fingerprint is the twelve hex
digits a `run.firewall_denied` row carries). Each path logs under the prefix
`cloop:<fingerprint>:<rule>`:

```bash
sudo nft list tables | grep cloop_sbx_
sudo nft list table inet cloop_sbx_<executor>_r<fingerprint>
```

## Auditing

| action | when |
|---|---|
| `executor.firewall` | a device's rule set is set or cleared; `constrained` counts what the save narrowed |
| `executor.virtual` with `"action": "constrain"` | a virtual executor's firewall was narrowed to fit its device |
| `project.firewall` | a project's rule set is set, cleared, or (`"action": "constrain"`) narrowed |
| `run.firewall_denied` | a run ended whose sandbox firewall refused connections: one row per run and deny path (never one per packet), with `count`, `destinations`, the `top` eight and `why` |

A run's refusals are also `network_blocked` rows in its project's event history,
and the egress proxy's own refusals are `egress.connect` and `egress.request`
rows with `"decision": "deny"`.

See [audit events](../reference/audit-events.md).

## HTTP API

```bash
# a device's rule set
curl -H "Authorization: Bearer $TOKEN" https://hub/api/executors/sgx/firewall
curl -X PUT -H "Authorization: Bearer $TOKEN" https://hub/api/executors/sgx/firewall \
  -d '{"allow_public_internet": true, "allow_ports": [443], "resolvers": ["1.1.1.1"],
       "deny_cidrs": ["203.0.113.0/24"]}'

# a project's, by its index in the project list
curl -X PUT -H "Authorization: Bearer $TOKEN" 'https://hub/api/firewall?project_idx=2' \
  -d '{"allow_cidrs": ["140.82.112.0/20"], "allow_ports": [443], "resolvers": ["1.1.1.1"]}'

# either, back to the levels above it
curl -X PUT … -d '{"clear": true}'
```

The device route refuses a virtual executor, whose firewall is part of its
definition, and the host-process executor, which has no per-run network to
filter.
