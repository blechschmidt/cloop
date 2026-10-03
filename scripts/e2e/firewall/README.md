# Live check: the firewall levels on a device

`pkg/fwpolicy`'s tests prove the containment rule against the compiled filter,
and `pkg/ui`'s prove the saves. This kit proves the whole path on a real device:
a test hub, an enrolled agent holding the packet-filter grant, a virtual
executor with a firewall, a project bound to it with a narrower rule set of its
own, and the sandbox's own TCP connections. It was written for, and first run
in, Task 20363 against the sgx device.

The workload is `cloop run` with the ordinary `claudecode` provider and the
stand-in harness from [`../gitproxy`](../gitproxy/README.md): the
[`Dockerfile`](../gitproxy/Dockerfile) there builds the sandbox image, and
[`claude`](../gitproxy/claude) runs the probe carried in the task description.
[`probe.sh`](probe.sh) tries a TCP connection to each target and prints one
`RESULT <host:port> open|blocked` line; [`mktask.sh`](mktask.sh) adds it as a
task over the hub API.

## The checks

With a virtual executor whose firewall allows `1.1.1.1/32` and `1.0.0.1/32` on
443 — both reachable from the device itself:

| step | expected |
| --- | --- |
| probe `1.1.1.1:443 1.0.0.1:443 8.8.8.8:443` with no project rules | open, open, blocked: the virtual executor alone |
| `PUT /api/firewall?project_idx=N` `{"allow_cidrs":["1.1.1.1/32"],"allow_ports":[443]}`, probe again | open, **blocked**, blocked: the project's narrower rule set binds |
| `PUT /api/executors/<device>/firewall` with a superset of both | 200, nothing narrowed |
| a virtual executor or project save naming `8.8.8.8/32` | **409** `firewall_exceeds_bound`, naming it |
| the device tightened to `1.0.0.0/24` | 200, the virtual executor and the project narrowed and listed |

## The rig

Never through a production hub's database: run a hub of its own (its own
`HOME`, `CLOOP_HOME`, workdir and port, an API token since `cloop ui` binds all
interfaces), reach it from the device over `ssh -R` so the agent dials
loopback, and install the agent under the device's real hardened unit as a
second service, which also gives it the packet filter:

```bash
# on the hub's host
cloop executor enroll --name dev-fw --server ws://127.0.0.1:18363/api/executors/connect \
  --bundle-file bundle
ssh -N -R 18363:127.0.0.1:18363 device &
# on the device, with the cloop under test at /usr/local/bin/cloop-fw
CLOOP_ENROLL_BUNDLE=$(cat bundle) cloop-fw executor agent install --service-name cloop-fw \
  --user cloop-executor --group cloop-executor --binary /usr/local/bin/cloop-fw --packet-filter
docker build -t cloop-harness:fw-probe <dir with ../gitproxy/Dockerfile, ../gitproxy/claude and the cloop under test>
```

While a run under project rules is going, the device shows a bridge and a table
of the rule set's own (`docker network ls | grep cloop-sbx-vx-`, `nft list
tables | grep _r`); both go when the run ends. Tear down with `cloop-fw executor
agent install --uninstall --purge --service-name cloop-fw`, then delete the
virtual executor's own `cloop-sbx-<id>` network and `cloop_sbx_<id>` table.
