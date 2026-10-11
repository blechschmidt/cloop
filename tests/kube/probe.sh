#!/bin/sh
# Kubernetes probe (Task 20385). Runs INSIDE a workload Pod the hub dispatched
# to the in-cluster executor: the stand-in harness (scripts/e2e/gitproxy/claude)
# runs it from the task description, so everything here is what a real
# harness's own git and kubectl would see.
#
# kube_test.go prepends the parameters as shell assignments:
#   REPO, OTHER_REPO  owner/name: the granted repository, and one the same PAT
#                     reaches on the forge but the grant does not name
#   STAMP             unique suffix for every branch this run creates
#   ALLOWED, DENIED   branches inside / outside the grant's branch list (both
#                     inside the hub's refs/heads/cloop/**)
#   BRANCH_RULE       the grant's branch pattern, which a refusal must name
#   K8S_NS            the namespace the kubeconfig grant covers, read-only
#   K8S_NS2           the namespace a second grant of the same kubeconfig
#                     covers, with a write (Task 20413)
#   FORGE_URL         the forge's own in-cluster URL, for the egress check
#   EXPECT_EGRESS_BLOCKED  1 when the hub proved the CNI enforces NetworkPolicy
#   HARNESS_KEY_SHA256  sha256 of the ANTHROPIC_API_KEY the run was granted
#
# Every check prints "RESULT <id> PASS|FAIL <detail>"; the run ends with
# SUMMARY. Nothing here prints a credential: a token check reports where a
# token was found, never its value.
#
# Nothing else may reach stdout. `cloop run` shows at most 20 lines of what a
# harness printed — the first ten and the last ten — and captures its stderr
# instead of passing it through, so the stand-in's two lines plus one per check
# and the summary is the whole budget. A diagnostic belongs in a check's detail.
set -u
: "${REPO:?}" "${OTHER_REPO:?}" "${STAMP:?}" "${ALLOWED:?}" "${DENIED:?}" "${BRANCH_RULE:?}" "${K8S_NS:?}" "${K8S_NS2:?}"

pass=0
fail=0
res() {
	printf 'RESULT %s %s %s\n' "$1" "$2" "$3"
	if [ "$2" = PASS ]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
}
# brief renders the lines of a transcript that say what happened, as one line.
brief() {
	grep -E 'remote:|error:|fatal:|rejected|\[new|->|denied|refused|not found|returned error|Forbidden|Error' "$1" |
		tr -s ' \t' ' ' | tail -n 3 | tr '\n' ' ' | cut -c1-300
}
network_failure() { [ ! -s "$1" ] || grep -Eq 'Could not resolve host|Failed to connect|Connection timed out|Connection refused|Network is unreachable|timed out' "$1"; }
by_proxy() { grep -Eq 'cloop git proxy|remote rejected|\(ref update denied|session may not' "$1"; }

GH=https://github.com
BASE=$(pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/kube-e2e.XXXXXX") || { res SETUP FAIL "no temporary directory"; exit 0; }
O=$W/out.txt
export GIT_TERMINAL_PROMPT=0
GITC="git -c user.name=cloop-e2e -c user.email=cloop-e2e@example.invalid -c commit.gpgsign=false"
TOKRE='(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_.]{20,}|github_pat_[A-Za-z0-9_]{20,}'

# ── The harness login: in the environment, read from the run's Secret ─────
# The Pod object holds only a reference (kube_test.go checks that side); this
# is the other half — the kubelet resolved it into the container. Compared by
# digest, so the value is never printed.
keysum=$(printf %s "${ANTHROPIC_API_KEY:-}" | sha256sum | cut -d' ' -f1)
if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
	res A1 FAIL "ANTHROPIC_API_KEY is not set in the harness's environment"
elif [ "$keysum" = "${HARNESS_KEY_SHA256:-}" ]; then
	res A1 PASS "the granted ANTHROPIC_API_KEY is in the harness's environment (sha256 $(printf %s "$keysum" | cut -c1-12)…)"
else
	res A1 FAIL "ANTHROPIC_API_KEY is set, but is not the value the run was granted"
fi

# ── The credential helper and the token ───────────────────────────────────
HELPER=${CLOOP_LEASE_DIR:-/nonexistent}/git-credential-cloop
# -L: a projected Secret's file is a symlink into the volume's ..data
# directory, and the link's own mode is always 777.
mode=$(stat -L -c %a "$HELPER" 2>/dev/null || echo missing)
if [ "$mode" = 550 ]; then
	res H1 PASS "the lease's credential helper is mode 0550 ($HELPER, run as $(id -u):$(id -g)), so git can run it as the Pod's group"
else
	res H1 FAIL "the lease's credential helper is mode $mode, not 0550 ($HELPER)"
fi

leak=""
env | grep -Eq "$TOKRE" && leak="$leak env"
[ -n "${CLOOP_LEASE_DIR:-}" ] && grep -rEqs "$TOKRE" "$CLOOP_LEASE_DIR" && leak="$leak lease-dir"
grep -Eqs "$TOKRE" "$BASE/.git/config" && leak="$leak workspace-.git/config"
if [ -z "$leak" ]; then
	res T1 PASS "no GitHub token in the environment, the lease directory or the workspace's git config"
else
	res T1 FAIL "a GitHub token is readable in:$leak"
fi

# ── The hub's CA, trusted for the proxy's URL only (Task 20409) ────────────
# The release runs executor.monitorTLS.auto: the hub issued the proxy's
# certificate from its own CA, and the run's lease Secret carried that CA to
# /etc/cloop/hub-ca/ca.crt, named by http.<proxy URL>.sslCAInfo — the only
# sslCAInfo in the block, no GIT_SSL_CAINFO. The kube guard serves a leaf from
# the same CA at another URL, so git must refuse it: that is the scoping.
CAFILE=""
i=0
while [ "$i" -lt "${GIT_CONFIG_COUNT:-0}" ]; do
	eval "k=\${GIT_CONFIG_KEY_$i:-}; v=\${GIT_CONFIG_VALUE_$i:-}"
	[ "$k" = "http.${CLOOP_GIT_PROXY_URL:-none}/.sslCAInfo" ] && CAFILE=$v
	i=$((i + 1))
done
NCA=$(env | grep -c '^GIT_CONFIG_KEY_[0-9]*=http\.https://.*\.sslCAInfo$')
GUARD=$(sed -n 's/^ *server: *//p' "${KUBECONFIG:-/nonexistent}" | head -n 1)
if [ -z "$GUARD" ]; then
	other="no kube guard URL to try"
elif git ls-remote "$GUARD/acme/none" >"$W/c1.out" 2>&1; then
	other=trusted
elif grep -qi certificate "$W/c1.out"; then
	other=refused
else
	other="neither trusted nor refused on its certificate: $(brief "$W/c1.out")"
fi
if [ "$CAFILE" = /etc/cloop/hub-ca/ca.crt ] && [ -s "$CAFILE" ] && [ -z "${GIT_SSL_CAINFO:-}" ] &&
	[ "$NCA" = 1 ] && [ "$other" = refused ]; then
	res C1 PASS "the hub's CA is at $CAFILE and trusted for ${CLOOP_GIT_PROXY_URL:-?} only (no GIT_SSL_CAINFO); $GUARD, from the same CA, is refused"
else
	res C1 FAIL "the hub's CA is not trusted for the proxy's URL alone (file=${CAFILE:-none}, sslCAInfo keys=$NCA, GIT_SSL_CAINFO=${GIT_SSL_CAINFO:-unset}, $GUARD: $other)"
fi

# ── The workspace: fetched by the init container through the proxy ─────────
if git -C "$BASE" rev-parse --git-dir >/dev/null 2>&1; then
	WSURL=$(git -C "$BASE" config --get remote.origin.url)
	case $WSURL in
	"${CLOOP_GIT_PROXY_URL:-no-proxy-url}"/*) res WS1 PASS "the workspace was provisioned through the proxy: origin $WSURL" ;;
	*) res WS1 FAIL "the workspace's origin is $WSURL, not the proxy ${CLOOP_GIT_PROXY_URL:-unset}" ;;
	esac
	if grep -qis 'extraheader\|password' "$BASE/.git/config"; then
		res WS2 FAIL "the workspace's .git/config holds a credential"
	else
		res WS2 PASS "no credential in the workspace's .git/config"
	fi
else
	res WS1 FAIL "the working directory is not a git checkout"
fi

# ── The project came with the run, not with the repository (Task 20402) ────
# The repository commits no .cloop/; the run is reading the project the hub
# sent, which the init container placed — and git must not see it, or a
# write-back would commit the hub's project into the repository.
tracked=$(git -C "$BASE" ls-files -- .cloop 2>/dev/null | head -n 1)
if [ -n "$tracked" ]; then
	res S1 FAIL "the repository tracks $tracked, so this run may not have needed the seed"
elif [ ! -s "$BASE/.cloop/state.db" ] && [ ! -s "$BASE/.cloop/state.json" ]; then
	res S1 FAIL "the workspace has no project state in .cloop/"
elif git -C "$BASE" status --porcelain 2>/dev/null | grep -q '\.cloop'; then
	res S1 FAIL "git sees the placed .cloop/ as a change, so a write-back would commit it"
else
	res S1 PASS "the project came from the hub's seed: the repository tracks no .cloop/ and git ignores the placed one"
fi

# ── Clone and pushes through the proxy ────────────────────────────────────
cd "$W" || exit 0
if git clone -q "$GH/$REPO" repo >"$O" 2>&1; then
	res P1 PASS "cloned $GH/$REPO through $(git -C repo ls-remote --get-url origin)"
else
	res P1 FAIL "clone of the granted $REPO failed: $(brief "$O")"
	printf 'SUMMARY kube pass=%d fail=%d (clone failed)\n' "$pass" "$fail"
	exit 0
fi
cd repo || exit 0
printf 'Task 20385 kube e2e %s\n' "$STAMP" >"t20385-$STAMP.txt"
git add "t20385-$STAMP.txt" && $GITC commit -qm "Task 20385 kube e2e $STAMP" >/dev/null
remote_sha() { git ls-remote origin "$1" 2>/dev/null | cut -f1; }

# kube_test.go reads the commit from this detail: "at <sha>".
if git push origin "HEAD:refs/heads/$ALLOWED" >"$O" 2>&1 && [ "$(remote_sha "refs/heads/$ALLOWED")" = "$(git rev-parse HEAD)" ]; then
	res B1 PASS "push to $ALLOWED (inside the grant's $BRANCH_RULE) accepted at $(git rev-parse HEAD)"
else
	res B1 FAIL "push to $ALLOWED: $(brief "$O")"
fi

before=$(remote_sha "refs/heads/$DENIED")
if git push origin "HEAD:refs/heads/$DENIED" >"$O" 2>&1; then
	res B2 FAIL "push to $DENIED was ACCEPTED: $(brief "$O")"
elif [ "$(remote_sha "refs/heads/$DENIED")" != "$before" ]; then
	res B2 FAIL "push to $DENIED reported failure but the ref moved"
elif ! by_proxy "$O"; then
	res B2 FAIL "push to $DENIED failed, but not with a proxy refusal: $(brief "$O")"
elif ! grep -qF "${BRANCH_RULE#refs/heads/}" "$O"; then
	res B2 FAIL "push to $DENIED refused without naming the grant's branches ($BRANCH_RULE): $(brief "$O")"
else
	res B2 PASS "push to $DENIED refused with the policy message: $(brief "$O")"
fi

if git push "$GH/$OTHER_REPO" "HEAD:refs/heads/$ALLOWED" >"$O" 2>&1; then
	res R1 FAIL "pushed into $OTHER_REPO, which the grant does not name"
elif by_proxy "$O"; then
	res R1 PASS "push into $OTHER_REPO refused by the proxy: $(brief "$O")"
else
	res R1 FAIL "push into $OTHER_REPO refused, but not by the proxy: $(brief "$O")"
fi

# ── The cluster, through the kube guard ───────────────────────────────────
cd "$W" || exit 0
SERVER=$(sed -n 's/^ *server: *//p' "${KUBECONFIG:-/nonexistent}" | head -n 1)
case $SERVER in
*kubernetes.default* | "") res K0 FAIL "the delivered kubeconfig's server is '${SERVER:-none}', not the monitor" ;;
https://*:*) res K0 PASS "the delivered kubeconfig names the monitor ($SERVER), not the API server" ;;
*) res K0 FAIL "the delivered kubeconfig's server is '$SERVER'" ;;
esac
if kubectl get pods -n "$K8S_NS" >"$O" 2>&1; then
	res K1 PASS "kubectl get pods -n $K8S_NS succeeded through the monitor"
else
	res K1 FAIL "kubectl get pods -n $K8S_NS: $(brief "$O")"
fi
# The cluster credential stays in the hub: a ServiceAccount token is a JWT,
# and nothing the Pod can read holds one — the kubeconfig carries a session.
JWTRE='eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}'
jwt=""
env | grep -Eq "$JWTRE" && jwt="$jwt env"
[ -n "${CLOOP_LEASE_DIR:-}" ] && grep -rEqs "$JWTRE" "$CLOOP_LEASE_DIR" && jwt="$jwt lease-dir"
grep -Eqs "$JWTRE" "${KUBECONFIG:-/nonexistent}" && jwt="$jwt kubeconfig"
if [ -z "$jwt" ]; then
	res K3 PASS "no cluster token (JWT) in the environment, the lease directory or the delivered kubeconfig"
else
	res K3 FAIL "a cluster token (JWT) is readable in:$jwt"
fi
if kubectl create configmap "e2e-$STAMP" -n "$K8S_NS" --from-literal=probe=1 >"$O" 2>&1; then
	res K2 FAIL "kubectl create configmap was ALLOWED on a read-only grant"
elif grep -q 'read-only access to the cluster' "$O"; then
	res K2 PASS "kubectl create configmap refused by the monitor: $(brief "$O")"
else
	res K2 FAIL "kubectl create configmap failed, but not with the monitor's refusal: $(brief "$O")"
fi
# Two grants of one cluster, one document (Task 20413): K8S_NS read-only and
# K8S_NS2 with a write. kubectl sees a context per grant, current-context the
# narrower; each reaches its own grant's namespace through the monitor and is
# refused everywhere else, and the second writes where only it may. One RESULT
# line for all of it: the output budget above has room for one more.
k4() {
	ctxs=$(kubectl config get-contexts -o name 2>"$O") || { echo "kubectl config get-contexts: $(brief "$O")"; return 1; }
	[ "$(printf '%s\n' "$ctxs" | grep -c .)" = 2 ] || { echo "kubectl sees contexts '$(printf '%s' "$ctxs" | tr '\n' ' ')', want two"; return 1; }
	cur=$(kubectl config current-context 2>/dev/null)
	case ",${CLOOP_K8S_CONTEXTS:-}," in
	",$cur,"*) ;;
	*) echo "CLOOP_K8S_CONTEXTS='${CLOOP_K8S_CONTEXTS:-}' does not lead with current-context '$cur'"; return 1 ;;
	esac
	got=""
	for c in $ctxs; do
		ns=$(kubectl config view -o "jsonpath={.contexts[?(@.name==\"$c\")].context.namespace}" 2>/dev/null)
		case $ns in
		"$K8S_NS") other=$K8S_NS2 ;;
		"$K8S_NS2") other=$K8S_NS ;;
		*) echo "context $c is pinned to '$ns', neither granted namespace"; return 1 ;;
		esac
		[ "$c" != "$cur" ] || [ "$ns" = "$K8S_NS" ] || { echo "current-context $cur is the $ns grant, not the narrower"; return 1; }
		got="$got $c=$ns"
		kubectl --context "$c" get pods -n "$ns" >"$O" 2>&1 || { echo "--context $c get pods -n $ns: $(brief "$O")"; return 1; }
		for no in "$other" kube-system; do
			if kubectl --context "$c" get pods -n "$no" >"$O" 2>&1; then
				echo "--context $c reached namespace $no"
				return 1
			fi
			grep -q "is not in this session's allowlist" "$O" ||
				{ echo "--context $c -n $no failed, but not with the monitor's refusal: $(brief "$O")"; return 1; }
		done
		if [ "$ns" = "$K8S_NS2" ]; then
			kubectl --context "$c" create configmap "e2e2-$STAMP" -n "$ns" --from-literal=probe=1 >"$O" 2>&1 ||
				{ echo "--context $c create configmap -n $ns: $(brief "$O")"; return 1; }
		fi
	done
	case "$got" in
	*"=$K8S_NS "*"=$K8S_NS2" | *"=$K8S_NS2 "*"=$K8S_NS") ;;
	*) echo "contexts$got do not cover both grants"; return 1 ;;
	esac
	echo "contexts$got each reach only their own grant's namespace through the monitor; the second wrote there"
}
if detail=$(k4); then
	res K4 PASS "$detail"
else
	res K4 FAIL "$detail"
fi

# ── Egress: what a NetworkPolicy the CNI enforces takes away ──────────────
if [ -n "${FORGE_URL:-}" ]; then
	if [ "${EXPECT_EGRESS_BLOCKED:-0}" = 1 ]; then
		if timeout 15 env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 git -c http.sslVerify=false \
			ls-remote "$FORGE_URL/$REPO.git" >"$O" 2>&1; then
			res E1 FAIL "the forge answered this Pod directly, past its NetworkPolicy"
		elif network_failure "$O"; then
			res E1 PASS "the forge is unreachable from this Pod except through the hub: $(brief "$O")"
		else
			res E1 FAIL "the forge was reached directly (it refused only for want of a credential): $(brief "$O")"
		fi
	else
		egress=" (egress blocking not asserted: the hub did not prove this CNI enforces NetworkPolicy)"
	fi
fi

cd / && rm -rf "$W"
printf 'SUMMARY kube pass=%d fail=%d%s\n' "$pass" "$fail" "${egress:-}"
