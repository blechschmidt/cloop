#!/bin/sh
# share_probe.sh — the sandbox side of share_test.go (Task 20416).
#
# The hub dispatches a run whose one task carries this script; the stand-in
# claude (scripts/e2e/gitproxy/claude) runs it inside the run, with the lease
# the hub delivered: KUBECONFIG names the Kubernetes access monitor, and the
# monitor holds the share's ServiceAccount token. The test substitutes the
# __PLACEHOLDERS__ and drives the phases through files in __DIR__:
#
#   phase 1  read, write, and the refusals — including every way a write grant
#            could mint a ServiceAccount credential of its own (Task 20420) —
#            then touch phase1-done
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

# P8-P13 (Task 20420): this write grant's verbs, and the edit role behind the
# share, both allow creating Secrets, Pods and Deployments in NS_A — and each of
# these would hand the workload a ServiceAccount credential that never passes
# through the monitor and outlives a revoke. So what refuses them can only be
# the monitor reading the request body. The test checks from outside that none
# of them exists.
#
# refused ID FILE PHRASE: PASS when kubectl failed with the monitor's message.
refused() {
	if grep -q "$3" "$2"; then
		r "$1" PASS "refused by the monitor: $(last "$2")"
	else
		r "$1" FAIL "refused, but not by the monitor: $(last "$2")"
	fi
}
kubectl -n "$NS_A" create serviceaccount probe-other >"$tmp/sa" 2>&1 || r P8 FAIL "could not create probe-other: $(last "$tmp/sa")"

# P8: a ServiceAccount token Secret, which the cluster would fill in.
cat >"$tmp/p8.json" <<'JSON'
{"apiVersion":"v1","kind":"Secret","metadata":{"name":"probe-token","annotations":{"kubernetes.io/service-account.name":"probe-other"}},"type":"kubernetes.io/service-account-token"}
JSON
if kubectl -n "$NS_A" create -f "$tmp/p8.json" >"$tmp/p8" 2>&1; then
	r P8 FAIL "the monitor let the sandbox create a ServiceAccount token Secret"
else
	refused P8 "$tmp/p8" "makes a Secret a ServiceAccount token"
fi

# P9: a Pod running as another ServiceAccount, whose token the cluster mounts.
cat >"$tmp/p9.json" <<'JSON'
{"apiVersion":"v1","kind":"Pod","metadata":{"name":"probe-sa"},"spec":{"serviceAccountName":"probe-other","containers":[{"name":"c","image":"registry.k8s.io/pause:3.9"}]}}
JSON
if kubectl -n "$NS_A" create -f "$tmp/p9.json" >"$tmp/p9" 2>&1; then
	r P9 FAIL "the monitor let the sandbox run a Pod as another ServiceAccount"
else
	refused P9 "$tmp/p9" "names ServiceAccount"
fi

# P10: the same through a Deployment's template.
cat >"$tmp/p10.json" <<'JSON'
{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"probe-deploy"},"spec":{"replicas":0,"selector":{"matchLabels":{"app":"probe"}},"template":{"metadata":{"labels":{"app":"probe"}},"spec":{"serviceAccountName":"probe-other","containers":[{"name":"c","image":"registry.k8s.io/pause:3.9"}]}}}}
JSON
if kubectl -n "$NS_A" create -f "$tmp/p10.json" >"$tmp/p10" 2>&1; then
	r P10 FAIL "the monitor let the sandbox create a Deployment running as another ServiceAccount"
else
	refused P10 "$tmp/p10" "names ServiceAccount"
fi

# P11: a Pod on the node's filesystem, where every Pod's token sits.
cat >"$tmp/p11.json" <<'JSON'
{"apiVersion":"v1","kind":"Pod","metadata":{"name":"probe-node"},"spec":{"volumes":[{"name":"kubelet","hostPath":{"path":"/var/lib/kubelet"}}],"containers":[{"name":"c","image":"registry.k8s.io/pause:3.9","volumeMounts":[{"name":"kubelet","mountPath":"/k"}]}]}}
JSON
if kubectl -n "$NS_A" create -f "$tmp/p11.json" >"$tmp/p11" 2>&1; then
	r P11 FAIL "the monitor let the sandbox mount the node's kubelet directory"
else
	refused P11 "$tmp/p11" "which reaches the node"
fi

# P12: a new image for a Deployment that already runs as another ServiceAccount
# (the test made it): the patch keeps the ServiceAccount.
if kubectl -n "$NS_A" set image deployment/probe-victim c=registry.k8s.io/busybox:1.36 >"$tmp/p12" 2>&1; then
	r P12 FAIL "the monitor let the sandbox change a Deployment that runs as another ServiceAccount"
else
	refused P12 "$tmp/p12" "already runs as ServiceAccount"
fi

# P13: a RoleBinding, which would give the namespace's default ServiceAccount
# whatever it names.
if kubectl -n "$NS_A" create rolebinding probe-rb --clusterrole=edit --serviceaccount="$NS_A:default" >"$tmp/p13" 2>&1; then
	r P13 FAIL "the monitor let the sandbox create a RoleBinding"
else
	refused P13 "$tmp/p13" "a binding hands"
fi

# P14: and the inspection lets an ordinary Pod through: one as the namespace's
# default ServiceAccount, as a server-side dry run so nothing is scheduled.
if kubectl -n "$NS_A" run probe-ok --image=registry.k8s.io/pause:3.9 --restart=Never --dry-run=server -o name >"$tmp/p14" 2>&1; then
	r P14 PASS "a Pod as the default ServiceAccount passes: $(last "$tmp/p14")"
else
	r P14 FAIL "an ordinary Pod was refused: $(last "$tmp/p14")"
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
