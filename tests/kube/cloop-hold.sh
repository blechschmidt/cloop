#!/bin/sh
# The harness image's cloop (tests/kube, Task 20455). Every invocation is the
# cloop under test, except one: the workspace provisioner of the repository
# acme/held waits, before it fetches, until /tmp/cloop-e2e-release exists in
# its container. TestAPodsWorkspaceSurvivesItsHubBeingKilled kills the hub in
# that window — the Pod holds a session the dead process minted — and creates
# the file with `kubectl exec -c workspace` once a new process adopted the run.
# Every other repository's provisioner, and every other command, runs at once.
if [ "${1:-}" = workspace ] && [ "${2:-}" = provision ]; then
	case " $* " in
	*/acme/held" "* | */acme/held.git" "*)
		echo "cloop-e2e: holding the fetch of acme/held until /tmp/cloop-e2e-release exists" >&2
		i=0
		while [ ! -e /tmp/cloop-e2e-release ] && [ "$i" -lt 1200 ]; do
			sleep 1
			i=$((i + 1))
		done
		;;
	esac
fi
exec /usr/local/bin/cloop-real "$@"
