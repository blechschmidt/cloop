#!/bin/bash
# The firewall probe (Task 20363), run inside a sandbox by the stand-in harness
# in ../gitproxy/claude. TARGETS ("host:port …") is prepended by mktask.sh.
#
# One RESULT line per target: "open" when a TCP connection completes, "blocked"
# when it does not within the bound. A firewalled sandbox's filter drops rather
# than rejects, so a blocked connect hangs until the timeout — which is why
# every attempt is bounded.
for t in $TARGETS; do
	h=${t%:*} p=${t##*:}
	if timeout "${PROBE_SECONDS:-8}" bash -c "exec 3<>/dev/tcp/$h/$p" 2>/dev/null; then
		echo "RESULT $t open"
	else
		echo "RESULT $t blocked"
	fi
done
