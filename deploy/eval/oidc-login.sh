#!/usr/bin/env bash
# Drive the evaluation stack's OIDC login with curl, and report what the hub
# decided the user is.
#
#   deploy/eval/oidc-login.sh <email> [password]
#
# Prints the body of GET /api/me for the resulting session and exits 0 when a
# session was established. Exits non-zero when the login itself failed — which
# is NOT the same thing as the user being denied, and the difference is the
# whole reason this script exists. See "Two kinds of no" below.
#
# Invoked by e2e.sh; useful on its own while evaluating the stack:
#
#   CA_FILE=$(mktemp) && docker run --rm -v cloop-eval_certs:/c alpine:3.20 \
#     cat /c/cert.pem > "$CA_FILE"
#   CA_FILE=$CA_FILE deploy/eval/oidc-login.sh nobody@example.com
#
# ── Why script a browser flow at all ────────────────────────────────────────
#
# Everything else that talks to this hub in CI uses a PAT (`cloop hub token
# create`), because that is the designed path for non-interactive access. But a
# PAT deliberately bypasses the identity provider: it carries its own roles and
# never touches dex. So the entire SSO path — discovery, the authorization
# redirect, PKCE, the code exchange, ID-token verification, session minting and
# claim-to-role resolution — is exactly the part of the enterprise story that no
# token-authenticated test can reach, and it is the first thing the docs tell an
# operator to do.
#
# The flow below is the real one, with no shortcut: the hub is asked for a login
# the same way a browser asks, dex's own password form is submitted, and the
# authorization code comes back to the hub's real callback. Nothing here forges
# a cookie or calls an internal helper.
#
# ── Two kinds of no ─────────────────────────────────────────────────────────
#
# cloop creates a session for any identity the IdP successfully vouches for, and
# resolves that identity to a role separately, per request. So an unmapped user
# authenticates perfectly well and then can read nothing — they get a session
# with role "none". That is deny-by-default working as designed.
#
# This script therefore treats "authenticated but unmapped" as a successful run
# and reports role=none, rather than conflating it with a broken login. The
# caller asserts which of the two it wanted. Collapsing them here would make a
# hub that silently refuses *everyone* indistinguishable from one enforcing its
# policy correctly — and that is precisely the regression worth catching.

set -euo pipefail

EMAIL=${1:?usage: oidc-login.sh <email> [password]}
PASSWORD=${2:-password}

BASE=${BASE:-https://cloop.localtest.me:8443}
# How to reach the proxy, as curl arguments.
#
# The default maps the public name to loopback on the port compose publishes.
# --resolve rather than -k: the certificate is valid for cloop.localtest.me, and
# a hub that served one not matching its external_url is a real defect that -k
# would hide — the exact class of bug `cloop hub doctor` reports.
#
# Override when the stack is published somewhere else, keeping the *name and
# port* in the URL intact so SNI, the Host header and the issuer still agree:
#
#   CLOOP_EVAL_PORT=18443 \
#   CLOOP_EVAL_CURL_CONNECT='--connect-to cloop.localtest.me:8443:127.0.0.1:18443'
read -r -a CURL_CONNECT <<<"${CLOOP_EVAL_CURL_CONNECT:---resolve cloop.localtest.me:8443:127.0.0.1}"
CA_FILE=${CA_FILE:?CA_FILE must point at the cert.pem the certs service generated}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
JAR="$WORK/jar"

# Shared curl arguments. --cookie-jar and --cookie on the same file make curl
# carry state across the redirect chain the way a browser would.
CURL=(curl --silent --show-error --location
      --cacert "$CA_FILE" "${CURL_CONNECT[@]}"
      --cookie-jar "$JAR" --cookie "$JAR"
      --max-time 30)

fail() { printf 'oidc-login: %s\n' "$*" >&2; exit 1; }

# ── 1. Ask the hub to start a login, and follow it to dex's form ────────────
#
# GET /auth/login 302s to the issuer's authorize endpoint with state, nonce and
# a PKCE challenge. dex, having exactly one connector, forwards straight to that
# connector's password form. Following the whole chain lands on the form.
form_page="$WORK/form.html"
form_url=$("${CURL[@]}" "$BASE/auth/login" -o "$form_page" -w '%{url_effective}') \
  || fail "could not reach $BASE/auth/login"

case "$form_url" in
  *"/dex/"*) ;;
  *) fail "login did not reach the identity provider; landed on $form_url
         This usually means OIDC discovery failed — the hub could not fetch
         $BASE/dex/.well-known/openid-configuration, or does not trust its TLS." ;;
esac

# ── 2. Submit dex's password form ───────────────────────────────────────────
#
# The action is parsed from the page rather than hardcoded, so a dex upgrade
# that moves the endpoint fails here with a readable message instead of a 404
# three redirects later. It carries the request id in a query string, so the
# HTML entity has to be decoded or the id is lost and dex answers "Login
# Error: Invalid Request".
#
# The entity decode is deliberately sed and not ${action//&amp;/&}: bash 5.2
# turned on patsub_replacement by default, which makes a bare & in the
# replacement expand to the text that matched — so the obvious spelling is a
# silent no-op on a new bash and correct on an old one. dex then sees a
# parameter named "amp;state", loses the request id, and re-serves the form,
# which reads exactly like a rejected password.
action=$(sed -n 's/.*<form[^>]*action="\([^"]*\)".*/\1/p' "$form_page" | head -1 | sed 's/&amp;/\&/g')
[ -n "$action" ] || fail "no <form> on the page at $form_url — dex did not serve a login form"

case "$action" in
  http*) post_url=$action ;;
  /*)    post_url="$BASE$action" ;;
  *)     post_url="${form_url%/*}/$action" ;;
esac

# On success dex 303s to its approval endpoint, which (skipApprovalScreen)
# forwards to the hub's callback with the code. curl turns 303 into GET, so the
# whole tail of the flow is followed here, ending at the hub.
final_url=$("${CURL[@]}" "$post_url" \
  --data-urlencode "login=$EMAIL" --data-urlencode "password=$PASSWORD" \
  -o "$WORK/final.html" -w '%{url_effective}') \
  || fail "posting credentials to $post_url failed"

# A wrong password re-serves the form rather than erroring, so the landing URL
# is the discriminator: a real login ends at the hub, a rejected one stays at
# the IdP.
case "$final_url" in
  "$BASE"/dex/*) fail "the identity provider rejected $EMAIL — still at $final_url" ;;
esac

# ── 3. The session cookie, and what the hub says the user is ────────────────
#
# Checked explicitly: the callback answers 200 with a meta-refresh landing page
# when the cookie is Secure, so a failed login and a successful one can look
# alike to a script that only inspects the status code.
grep -q 'cloop_session' "$JAR" \
  || fail "no cloop_session cookie was set; the callback did not mint a session
         (landed on $final_url)"

me=$("${CURL[@]}" "$BASE/api/me") || fail "GET /api/me failed"
case "$me" in
  *'"authenticated":true'*) ;;
  *) fail "/api/me does not report an authenticated session: $me" ;;
esac

# Hand the live session to the caller when asked. What /api/me reports is the
# hub's own account of a user's role; whether a gated route actually enforces it
# is a different claim, and only a real request carrying this cookie can settle
# it. e2e.sh uses this to prove the unmapped user is refused rather than merely
# described as powerless.
if [ -n "${JAR_OUT:-}" ]; then
  cp "$JAR" "$JAR_OUT"
fi

printf '%s\n' "$me"
