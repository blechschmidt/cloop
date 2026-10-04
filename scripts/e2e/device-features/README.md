# Live check: device firewalls and features through the dashboard

[`../firewall`](../firewall/README.md) proves the firewall levels from the API.
This kit drives the same checks, and a parallel feature, through the
dashboard itself in headless Chrome: the Executors panel's **Firewall**
dialog, a project's **Network Firewall** card, **+ New feature** with *Start
now*, and the feature's **Open pull request**. It was written for, and first
run in, Task 20371 against the sgx device: once on a rehearsal hub, then on
the production hub's test project.

[`drive.js`](drive.js) takes one step per invocation and prints what the page
showed as JSON. The hub's bearer token goes in `CLOOP_HUB_TOKEN`; it rides on
every request, the page navigation included, so on an SSO hub a scoped API
token (`cloop hub token create … --role admin`) stands in for a sign-in.

```bash
C=/opt/cft/chrome-linux64/chrome            # any Chrome with --headless=new
export CLOOP_HUB_TOKEN=…                    # API token, or the hub's UI token
node drive.js $C $HUB $PROJECT device-fw <executor-id> 1.1.1.1/32,1.0.0.1/32 443
node drive.js $C $HUB $PROJECT project-fw 1.1.1.1/32 443
node drive.js $C $HUB $PROJECT project-fw 1.1.1.1/32,8.8.8.8/32 443   # refused
node drive.js $C $HUB $PROJECT feature "name" "what it achieves" "first task"
node drive.js $C $HUB $PROJECT start $PROJECT/.cloop/features/<slug>   # Start run, Tasks tab
node drive.js $C $HUB $PROJECT tasks $PROJECT/.cloop/features/<slug>   # the Tasks tab's list
node drive.js $C $HUB $PROJECT pr <slug>
node drive.js $C $HUB $PROJECT upgrade-dialog <executor-id>   # what Upgrade offers, cancelled
```

## The checks

| step | expected |
| --- | --- |
| `device-fw` | `"saved": true`, the dialog reads "Set by …" with the rule set |
| `project-fw` narrower than the device | `"saved": true` |
| `project-fw` naming `8.8.8.8/32` | `"saved": false`, `refusal` names `8.8.8.8/32`; the API's `PUT /api/firewall` answers 409 `firewall_exceeds_bound` |
| a probe task ([`../firewall/mktask.sh`](../firewall/mktask.sh)) with the device in container mode | `1.1.1.1:443 open`, `1.0.0.1:443 blocked` (project), `8.8.8.8:443 blocked` (device) |
| `feature` | the crumb opens `<project>/<slug>`, the run starts |
| the feature's run | its task done; on the hub the worktree fast-forwarded onto the run's commits (or the work parked on `cloop/returned/<slug>/<run>`); the device's journal says the branch came "as a standalone checkout" and the write-back was bundled |
| a second task, `start` again | the device's journal shows the branch arriving as an *N-byte bundle* — a new feature's first run has no commits to ship |
| `pr` | the banner reads "PR #N open"; the PR's files are only what the task changed |
| `tasks` | every task ✓ |

The device must be in **container** mode for rule sets to apply (host mode
refuses runs while rules exist), and a run of the real harness needs the
network the rules take away — so do the firewall half, restore the rules and
the sandbox mode, then the feature half.

## What the first run found

Three defects, each fixed with a test, none visible to a hub that had never
run a feature on a real device with a private repository:

- a feature's upstream clone leased its grant as the feature's own path, which
  no grant names (`pkg/executor/gitcreds`);
- a host-mode payload's `HOME` was its checkout, so the harness's own state
  (`.claude.json`, `.claude/`, its session transcript) was committed by the
  write-back onto the feature's branch (`pkg/executor/agent/payloadhome.go`);
- the hub's push of a feature's branch dropped its Authorization header, so
  every pull request failed with 403 (`pkg/featureops`).

On the production hub (2026-10-04, sgx upgraded to protocol v16) every row
held: 1.1.1.1:443 open, 1.0.0.1:443 and 8.8.8.8:443 blocked; the feature's
branch went out as a 566-byte bundle, both runs fast-forwarded, and PR #4 of
`bb-selforg/cloop-app-e2e` opened with exactly the two commits. Before the
upgrade the same hub refused the feature (409) and the rule-bound run with
the protocol each needed and the build path that gets there. A dashboard
signed in with an API token toasts "no identity on request" from a side
panel; it is not the step failing — read the run's state.

## Cleanup

Close the pull request and delete its branch (the App's installation token
from `/root/.cloop/appjwt.sh` can do both), remove the feature, clear the
rule sets and the device's sandbox mode back to how they were, and revoke the
API token.
