#!/bin/sh
# share_probe.sh — the sandbox side of share_test.go (Task 20416).
#
# The hub dispatches a run whose one task carries this script; the stand-in
# claude (scripts/e2e/gitproxy/claude) runs it inside the run, with the lease
# the hub delivered: KUBECONFIG names the Kubernetes access monitor, and the
# monitor holds the share's ServiceAccount token. The test substitutes the
# __PLACEHOLDERS__ and drives the phases through files in __DIR__:
#
#   phase 1  read, write, and the refusals — then touch phase1-done
#   phase 2  once the test says the token the session started with has expired
#            (go-renewed): read and write again, with the hub's renewed token
#   phase 3  once the test has revoked the share (go-revoked): nothing works
#
# Every check prints one "RESULT <id> PASS|FAIL <detail>" line, to stdout and
# to __DIR__/results.txt.
NS_A='__NS_A__'
NS_SA='__NS_SA__'
SA='__SA__'
GUARD='__GUARD__'
DIR='__DIR__'
OUT="$DIR/results.txt"

r() {
	printf 'RESULT %s %s %s\n' "$1" "$2" "$3" | tee -a "$OUT"
}
last() { tail -n 2 "$1" | tr '\n\r' '  ' | cut -c1-280; }
wait_for() {
	waited=0
	while [ ! -e "$1" ]; do
		sleep 5
		waited=$((waited + 5))
		[ "$waited" -ge "$2" ] && return 1
	done
	return 0
}
tmp="$DIR/probe-tmp"
mkdir -p "$tmp"
# A copy of the kubeconfig, as a workload that wanted to keep its access past a
# revocation would make one: P7 uses it after the lease's own file is wiped.
cp "$KUBECONFIG" "$tmp/kubeconfig.copy"

# P0: the delivered kubeconfig points at the monitor and carries a session
# token — not the API server, and not the ServiceAccount's JWT.
tok=$(sed -n 's/^ *token: *//p' "$KUBECONFIG" | head -n 1)
if ! grep -q "server: https://$GUARD" "$KUBECONFIG"; then
	r P0 FAIL "the kubeconfig names $(sed -n 's/^ *server: *//p' "$KUBECONFIG" | head -n 1), not the monitor"
elif printf '%s' "$tok" | grep -q '^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.'; then
	r P0 FAIL "the kubeconfig carries a JWT"
elif env | grep -q 'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.'; then
	r P0 FAIL "the environment carries a JWT"
else
	r P0 PASS "monitor at $GUARD, session token only"
fi

# P1: read through the monitor.
if kubectl -n "$NS_A" get configmaps >"$tmp/p1" 2>&1; then
	r P1 PASS "get configmaps in $NS_A"
else
	r P1 FAIL "$(last "$tmp/p1")"
fi

# P2: write, which the grant allows.
if kubectl -n "$NS_A" create configmap share-probe-1 --from-literal=phase=1 >"$tmp/p2" 2>&1; then
	r P2 PASS "created configmap share-probe-1"
else
	r P2 FAIL "$(last "$tmp/p2")"
fi

# P3: the ServiceAccount's own token, which its self-renewal Role would let
# the cluster mint — refused by the monitor under this write grant.
if kubectl -n "$NS_SA" create token "$SA" >"$tmp/p3" 2>&1; then
	r P3 FAIL "the monitor let the sandbox mint the share's token"
elif grep -q "serviceaccounts/token is refused by the cloop Kubernetes monitor" "$tmp/p3"; then
	r P3 PASS "refused by the monitor"
else
	r P3 FAIL "refused, but not by the monitor: $(last "$tmp/p3")"
fi

# P4: the same through the raw API, for another ServiceAccount, in a
# namespace the grant writes.
printf '{"apiVersion":"authentication.k8s.io/v1","kind":"TokenRequest","spec":{"expirationSeconds":3600}}' >"$tmp/tr.json"
if kubectl create --raw "/api/v1/namespaces/$NS_A/serviceaccounts/default/token" -f "$tmp/tr.json" >"$tmp/p4" 2>&1; then
	r P4 FAIL "the monitor forwarded a raw TokenRequest"
elif grep -q "serviceaccounts/token is refused" "$tmp/p4"; then
	r P4 PASS "raw TokenRequest refused by the monitor"
else
	r P4 FAIL "refused, but not by the monitor: $(last "$tmp/p4")"
fi

# P5: outside the grant's namespaces.
if kubectl -n kube-system get pods >"$tmp/p5" 2>&1; then
	r P5 FAIL "read kube-system"
elif grep -q "not in this session's allowlist" "$tmp/p5"; then
	r P5 PASS "kube-system refused by the monitor"
else
	r P5 FAIL "refused, but not by the monitor: $(last "$tmp/p5")"
fi
touch "$DIR/phase1-done"

# P6: after the token this session started with has expired.
if ! wait_for "$DIR/go-renewed" 1500; then
	r P6 FAIL "the test never said the first token had expired"
elif kubectl -n "$NS_A" get configmaps >"$tmp/p6" 2>&1 &&
	kubectl -n "$NS_A" create configmap share-probe-2 --from-literal=phase=2 >>"$tmp/p6" 2>&1; then
	r P6 PASS "read and wrote after the first token expired"
else
	r P6 FAIL "$(last "$tmp/p6")"
fi
touch "$DIR/phase2-done"

# P7: after the share was revoked — through the copy, so what refuses is the
# monitor, which closed the session, and not a missing file.
if ! wait_for "$DIR/go-revoked" 600; then
	r P7 FAIL "the test never said the share was revoked"
elif KUBECONFIG="$tmp/kubeconfig.copy" kubectl -n "$NS_A" get configmaps >"$tmp/p7" 2>&1; then
	r P7 FAIL "still read the cluster after the revoke, with a copy of the kubeconfig"
elif grep -qE "session was revoked|Unauthorized|logged in to the server" "$tmp/p7"; then
	gone="kept"
	[ -e "$KUBECONFIG" ] || gone="wiped"
	r P7 PASS "the monitor refuses the session (the lease's kubeconfig was $gone): $(last "$tmp/p7")"
else
	r P7 FAIL "refused, but not as a revoked session: $(last "$tmp/p7")"
fi
touch "$DIR/probe-done"
