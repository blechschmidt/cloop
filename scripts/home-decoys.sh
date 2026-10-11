#!/usr/bin/env bash
#
# Dirty the home directory before CI's tests, and prove afterwards that they
# left it exactly as they found it. Every job that runs a part of the unit
# suite does both: Build and Test, and each pkg/ui shard (Task 20414).
#
#   scripts/home-decoys.sh seed     # before the tests
#   scripts/home-decoys.sh verify   # after them, under if: always()
#
# # Why
#
# cloop keeps per-user state outside the working tree (the multi-project
# registry at ~/.cloop/projects.json, budgets and ledgers under
# ~/.config/cloop). A test that writes there passes on a fresh runner and fails
# on a developer's machine once enough state has accumulated — which is exactly
# what happened: one dashboard test appended an entry per run to a real registry
# until project index 99 resolved and three authorization tests began failing,
# for that developer only. CI could not see it, because CI always starts empty.
#
# So `seed` dirties the home directory first, and the suite has to prove it does
# not care: without it every run is the clean case. `verify` is the assertion
# that makes the seeding meaningful. If a test wrote to the real registry the
# entry count changes, failing at the leak rather than at whichever unrelated
# test the accumulated entries eventually break; and nothing may appear beside
# it, or in the other per-user state directory — pkg/globalbudget and pkg/cost
# write budget.yaml, costs.jsonl and global.db under ~/.config/cloop, which an
# entry-count check on the registry alone would not notice.
#
# The structural half of the guarantee is tests/hermetic, which checks that
# every package reading $HOME isolates it in TestMain; this catches what that
# misses.

set -euo pipefail

decoys=150

case ${1:-} in
seed)
	mkdir -p "$HOME/.cloop" "$HOME/.config/cloop"
	DECOYS=$decoys python3 - <<'PY'
import json, os
entries = [{"name": f"ci-decoy-{i}", "path": f"/nonexistent/ci-decoy-{i}"}
           for i in range(int(os.environ["DECOYS"]))]
with open(os.path.expanduser("~/.cloop/projects.json"), "w") as f:
    json.dump({"projects": entries}, f)
PY
	echo "seeded $HOME/.cloop/projects.json with $decoys unresolvable projects"
	;;
verify)
	DECOYS=$decoys python3 - <<'PY'
import json, os, sys
want = int(os.environ["DECOYS"])
p = os.path.expanduser("~/.cloop/projects.json")
n = len(json.load(open(p))["projects"])
if n != want:
    sys.exit(f"::error::the test suite modified {p}: {want} entries before, "
             f"{n} after — a test is writing to the user's home directory")
print(f"{p} still has {n} entries; nothing wrote to it")
PY
	unexpected=$(
		find "$HOME/.cloop" -mindepth 1 ! -name projects.json
		find "$HOME/.config/cloop" -mindepth 1
	)
	if [ -n "$unexpected" ]; then
		echo "::error::the test suite created files under the home directory:"
		echo "$unexpected"
		exit 1
	fi
	echo "no per-user state was written"
	;;
*)
	echo "usage: home-decoys.sh seed|verify" >&2
	exit 2
	;;
esac
