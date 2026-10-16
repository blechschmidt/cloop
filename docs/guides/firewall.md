# Firewall rules: devices, virtual executors and projects

A sandbox's IP-layer egress is decided at up to four levels, and each one may
only **narrow** the one above it:

| level | who sets it | where |
|---|---|---|
| the executor's configuration | whoever deploys the hub | `executors.container.egress_filter` / `executors.kubernetes.egress_filter` in `config.yaml` — hub-side executors only |
| the **device**'s rule set | an admin (`executor.manage`) | Executors → the device's card → **Firewall** |
| a **virtual executor**'s firewall, or the network a device gives its own sandboxes | an admin | the virtual-executor dialog ([virtual executors](virtual-executors.md)) |
| the **project**'s rule set | the project's maintainers (`config.write` on that project) | the project's Overview → **Network Firewall** |

The device's rule set is the superset: whatever runs on that machine — on the
device itself or under any of its virtual executors — reaches nothing it does
not allow. A project's rules can make its own runs narrower still, and never
wider. That is what makes the project level safe to hand to a project's
maintainers: someone who can name CIDRs on a device whose admin kept it off
`10.0.0.0/8` would otherwise have given themselves the operator's network.

## The rules

Every level uses the form the virtual-executor dialog uses — **Allow the public
Internet**, an **allowlist**, a **denylist**, **ports** and **DNS resolvers**;
see [the firewall](virtual-executors.md#the-firewall) for what each field opens.
In short: TCP to the allows on the ports (every port when the list is empty),
UDP and TCP to each resolver's own address and port, nothing in the denylist,
and nothing else.

One thing is inherited rather than restated: **the denylist**. A level's
effective denylist is its own plus every one above it, because a deny can only
take reach away — a project need not copy its device's denylist, and cannot
undo it. Nothing else is inherited. An empty port list means every port, as it
does on a virtual executor, so under a device that allows only 443 a project
lists 443 — and a save that does not is refused, naming the ports it may use.
Likewise a project names the resolvers it uses; the Overview form starts from
the governing rules, so narrowing is a matter of deleting what is not needed.

An empty rule set is not the same as none. **Remove rules** hands the level back
to the ones above it; saving with every field empty means *reach nothing*.

## Cloud metadata services

An allowlist opens exactly the ranges it names — except a cloud metadata
service, which only its own address opens. A metadata service hands whatever
runs on a machine that machine's cloud identity: instance credentials, user
data, a pod's role. So a prefix that merely *contains* one — `169.254.0.0/16`
around `169.254.169.254`, `fc00::/7` around AWS's IPv6 `fd00:ec2::254`,
`100.64.0.0/10` around Alibaba Cloud's `100.100.100.200` — opens everything in
the range **except** the service, and a save that names such a range and not the
service is refused with the service named and both ways out:

```
400 Bad Request
{"error": "allow_cidrs: 169.254.0.0/16 contains 2 cloud metadata services without
  naming them: 169.254.169.252 (GKE metadata server for Workload Identity),
  169.254.169.254 (instance metadata on AWS, Azure, Google Cloud, Oracle Cloud and
  most other clouds). Add their addresses (169.254.169.252/32, 169.254.169.254/32)
  to the allowlist if a sandbox should reach them, or to the denylist so they stay
  closed"}
```

To let a sandbox reach one, add its `/32` or `/128` to the **Allowlist**; to
keep it closed while allowing the range around it, add the address to the
**Denylist** (or just allow a narrower range). A rule set saved before this rule
existed keeps the service closed regardless — the compiled filter drops it ahead
of the allow — and its card says so; saving it again asks you to resolve it. The
full table of services cloop knows is in `pkg/cloudmeta`.

## Containment, and where it is checked

"Fits inside" is decided by exact set arithmetic over what the rules compile
to — so "the public Internet" is compared as every address outside the block
set, and an allowed range with a denied hole in it as the range minus the hole.
A rule set that does not fit is refused with one reason per thing outside it:

```
409 Conflict
{"code": "firewall_exceeds_bound",
 "error": "this project's rule set reaches further than the rule set above it (…)",
 "reasons": ["port 22 is not allowed by the governing rule set (443)",
             "10.0.0.0/8 is private (RFC1918/ULA), which the governing rule set does not reach: …"]}
```

The rule is checked three times, and the last check is the one the guarantee
rests on:

1. **When you save**, in the same database transaction as the write, so the
   error lands on the form you are looking at.
2. **When a run is dispatched**, against the executor it actually lands on — a
   project can be rebound, or its device tightened, after its rules were saved.
   The composed rules travel with the run; a run whose rules cannot be read,
   whose levels do not nest, or whose executor cannot enforce them is refused
   and the reason is written to the project's event history. A run moved off a
   failed executor is composed again for its replacement, which may sit on
   another device with rules of its own.
3. **In the driver**, immediately before it installs anything: the hub's
   container and Kubernetes drivers and, on a device, the agent prove the rules
   against their own level and the device's rule set again. On the hub this
   reads the device's rules as stored *now*, so a run dispatched by a path that
   skipped step 2 is refused rather than started outside them.

## Tightening a device

Saving a narrower device rule set narrows what was saved under it, in the same
transaction:

- each virtual executor's firewall is cut down to the part of it the device
  still allows — an **Unfiltered** virtual executor becomes **Firewalled**
  with the device's own rules, since an unfiltered network cannot be bounded;
- each project rule set whose runs go to the device, or to one of its virtual
  executors, is cut down to fit.

The dialog lists every narrowing ("Narrowed to fit: …") and each one is in the
audit trail. Editing a virtual executor narrows the projects on it the same way,
and so does moving a project to another executor. Clearing a device's rules
narrows nothing.

## Enforcement

| executor | enforces rules by | needs |
|---|---|---|
| hub container executor | a bridge and nftables table of the rule set's own (`cloop-sbx-<id>-r<fingerprint>`), filtered before any sandbox joins | `nft(8)` and `CAP_NET_ADMIN` on the hub; a rootful engine |
| enrolled device, container mode | the same, on the device | an agent speaking protocol **v15**, with the packet filter granted (`cloop executor agent install --packet-filter`); **v24** to report what it refused |
| virtual executor | the same, on its device | as above |
| Kubernetes | the Pod's NetworkPolicy, the denylist carved out of every allow | a cluster whose NetworkPolicy enforcement is proven or asserted (`cloop hub doctor --probe-network-policy`) |
| the hub's host-process executor, a device in host mode | — | cannot: runs are refused while rules apply |

Two rule sets never share a bridge — the second would replace the first's
ruleset — so the bridge and table are named after the rule set's fingerprint,
and removed when the last run on them ends. A rule set that reaches nothing
needs no filter: the run simply gets no network.

A host interface granted to a project (an L2 passthrough) is a route around any
IP firewall, so a run carrying one is refused while rules apply.

## Diagnosing a blocked connection

A connection a sandbox's firewall denies is **refused at once**: TCP gets a
reset, so `connect` fails with `ECONNREFUSED`; everything else gets an ICMP
"administratively prohibited", so a UDP socket reads `EHOSTUNREACH` (IPv4) or
`EACCES` (IPv6). Inside the sandbox it looks like this:

```
$ curl -sS -m 6 -o /dev/null https://1.0.0.1/
curl: (7) Failed to connect to 1.0.0.1 port 443 after 0 ms: Couldn't connect to server
```

— not a six-second timeout, and not a harness retrying for minutes. Rule sets
that would rather a sandbox could not tell a filtered destination from one that
is not there set **Drop denied connections silently** (`drop_denied` in the
API, `drop_denied: true` under `executors.container.egress_filter`); a level
below inherits it.

Every deny path also logs the refused packet, rate-limited, to an NFLOG group —
its prefix names the rule set's fingerprint and the rule — and whoever installed
the ruleset reads it: the hub for its own container executor, the device's agent
for its sandboxes (protocol **v24**; no privilege beyond the packet-filter grant
installing the ruleset already needs). Each run's refusals are aggregated by
destination, port, protocol and rule and land in four places:

| where | what you see |
|---|---|
| the run's **Event history** | `blocked 203.0.113.7:443/tcp x14, not in the project's allow list` the first time the run is refused a destination under a task, and when the run ends, its refusals in all |
| the task's **details → Network** | every destination its runs were refused, how often, when and why — and, beside them, what the [egress proxy](secrets.md#egress-leases) refused (its `egress.*` rows) |
| the project's **Network Firewall** card → **Recently blocked** | the last week's refusals, one line per destination and rule; admins get **Propose allow rule** |
| the audit trail and the metrics | `run.firewall_denied` (below), `cloop_firewall_denials_total` |

The sentence after each destination names the level to change:

| rule | reads | to let it through |
|---|---|---|
| `default` | "not in the project's allow list", "port 22 is not one the project's allow list opens (443)", "UDP is not allowed: … opens TCP only" | name the address (and the port) in that level's allowlist — the innermost level that set rules |
| `deny:<range>` | "in device sgx's deny list (203.0.113.0/24)" | take the range out of the deny list named; an allow never wins over a deny |
| `block:<range>` | "private (RFC1918/ULA) range 10.0.0.0/8, which the project's allow list does not name" | name the address in the allowlist: an explicit entry is what opens blocked space |
| `meta:<address>` | "the cloud metadata service at …" | name its own address at every level, if that is really what the sandbox needs |
| `xlat:<range>` | "an IPv6 translation prefix …" | allow the IPv4 range it stands for |

**Propose allow rule** adds the destination as a `/32` (`/128`) to the
project's rule set — its own, or the rules governing it when it has none — and
the port when the rule set names ports, then saves it through the same check as
the form: a destination the device's rule set does not reach is refused with the
reason, and an admin widens the device first. It is offered only for `default`
and `block` refusals over TCP; a deny list, a metadata service and a translation
prefix are not opened by an allow.

What the counts mean: the log is limited to ten lines a second per deny path, so
a flood counts as at least that rate, not as every packet. A run itemises at most
64 destinations; past that its refusals are counted, not listed ("and 120 more
refused, counted but not itemised"). Only addresses, ports and counts are kept —
the kernel copies at most 80 bytes of a refused packet and nothing past the ports
is read.

Where the list is empty, the card and the task say why instead:

- **Kubernetes**: "Denials are not observable on this executor" — a
  NetworkPolicy has no portable log of what it refused;
- **a device whose agent predates protocol v24**: the upgrade, in the same words
  as every other protocol refusal; its sandboxes are filtered as strictly, only
  unreported.

The hub's host-process executor and a device in host mode run no sandbox
firewall at all, so there is nothing to refuse and the views show no list.

On the host, the ruleset itself shows each path's counter and log statement.
There is one table per executor and rule set — `cloop_sbx_<executor>`,
suffixed `_r<fingerprint>` for rules the hub composed, where the fingerprint is
the twelve hex digits a `run.firewall_denied` row carries — and each path logs
under the prefix `cloop:<fingerprint>:<rule>`:

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
| `run.firewall_denied` | a run ended whose sandbox firewall refused connections: one row per run and deny path, with `count`, `destinations`, the `top` eight and `why` — never one per packet |

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

The device route refuses a virtual executor (its firewall is part of its
definition) and the host-process executor (it has no network of a run's own to
filter).
