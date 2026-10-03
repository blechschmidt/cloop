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
| enrolled device, container mode | the same, on the device | an agent speaking protocol **v15**, with the packet filter granted (`cloop executor agent install --packet-filter`) |
| virtual executor | the same, on its device | as above |
| Kubernetes | the Pod's NetworkPolicy, the denylist carved out of every allow | a cluster whose NetworkPolicy enforcement is proven or asserted (`cloop hub doctor --probe-network-policy`) |
| the hub's host-process executor, a device in host mode | — | cannot: runs are refused while rules apply |

Two rule sets never share a bridge — the second would replace the first's
ruleset — so the bridge and table are named after the rule set's fingerprint,
and removed when the last run on them ends. A rule set that reaches nothing
needs no filter: the run simply gets no network.

A host interface granted to a project (an L2 passthrough) is a route around any
IP firewall, so a run carrying one is refused while rules apply.

## Auditing

| action | when |
|---|---|
| `executor.firewall` | a device's rule set is set or cleared; `constrained` counts what the save narrowed |
| `executor.virtual` with `"action": "constrain"` | a virtual executor's firewall was narrowed to fit its device |
| `project.firewall` | a project's rule set is set, cleared, or (`"action": "constrain"`) narrowed |

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
