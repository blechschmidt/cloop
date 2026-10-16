#!/bin/bash
# The firewall probe (Task 20363), run inside a sandbox by the stand-in harness
# in ../gitproxy/claude. TARGETS ("host:port …") is prepended by mktask.sh.
#
# One RESULT line per target: "open" when a TCP connection completes, "blocked"
# when it does not, followed by how it failed and how long that took. Since
# Task 20437 a firewalled sandbox's filter refuses rather than drops, so a
# blocked connect fails at once with "Connection refused"; one that times out
# instead is a filter dropping silently (drop_denied) or a target that is down.
# Every attempt is still bounded.
for t in $TARGETS; do
	h=${t%:*} p=${t##*:}
	t0=$(date +%s%N)
	out=$(timeout "${PROBE_SECONDS:-8}" bash -c "exec 3<>/dev/tcp/$h/$p" 2>&1)
	rc=$? ms=$((($(date +%s%N) - t0) / 1000000))
	if [ "$rc" = 0 ]; then
		echo "RESULT $t open"
		continue
	fi
	# GNU timeout exits 124, busybox's 143 (SIGTERM); either way bash was
	# killed before it could say why.
	if [ "$rc" = 124 ] || [ "$rc" = 143 ] || [ -z "$out" ]; then
		echo "RESULT $t blocked (timed out after ${ms} ms)"
	else
		echo "RESULT $t blocked (${out##*: } after ${ms} ms)"
	fi
done
