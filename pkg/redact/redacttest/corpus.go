// Package redacttest is the credential corpus every pattern scanner in cloop
// is held to: realistic credentials in the context they leak in, and ordinary
// output that has to come through untouched.
//
// tests/security runs every scanner over every fixture; pkg/redact's own tests
// run the registry over them. One corpus for both is the point — a scanner can
// only be said to cover a credential if it is checked against the same text
// as the others.
//
// # Nothing in here is real
//
// Every credential is generated when the corpus is built, from a fixed seed so
// a failure reproduces, and none appears as a literal in this file. That keeps
// the source free of strings a push-protection scanner would stop, and it means
// the shapes are only as realistic as the generators: the GitHub long form is
// modelled on an installation token measured on 2026-10-03 (ghs_, seven
// digits, then 36, 254 and 86 characters with the last segment base64url) and
// revoked the same minute. No real token was ever written down.
package redacttest

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"strings"
)

// Seed fixes the corpus, so the fixture a failure names is the fixture a
// rerun produces.
const Seed = 20368

// Positive is a text carrying at least one credential.
type Positive struct {
	// Name identifies the fixture in failure messages: "<detector>/<context>".
	Name string
	// Detector is the registry detector that must report Text. Others may as
	// well — a token in an Authorization header is two findings.
	Detector string
	// Text is the credential in context, as a scanner would receive it.
	Text string
	// Secrets are the substrings that must not survive redacting Text.
	Secrets []string
	// Keep are substrings around the credential that must survive it. They are
	// what stops a scanner from passing by deleting everything.
	Keep []string
}

// Negative is ordinary output that looks enough like a credential to tempt a
// careless pattern, and must be left exactly as it is.
type Negative struct {
	Name string
	Text string
}

// Positives returns the credential fixtures.
func Positives() []Positive {
	return positives(rand.New(rand.NewPCG(Seed, 0)))
}

// Negatives returns the fixtures no scanner may touch.
func Negatives() []Negative {
	return negatives(rand.New(rand.NewPCG(Seed, 1)))
}

// --- generators ---------------------------------------------------------------

const (
	lowerAlpha = "abcdefghijklmnopqrstuvwxyz"
	upperAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars = "0123456789"
	base62     = digitChars + upperAlpha + lowerAlpha
	b64url     = base62 + "-_"
	hexChars   = "0123456789abcdef"
)

func pick(r *rand.Rand, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.IntN(len(alphabet))]
	}
	return string(b)
}

// generated returns n characters of alphabet with at least one digit and one
// capital in them when the alphabet has both. A real credential of any length
// worth matching always does; a generator that occasionally produced one
// without would make the corpus flaky for no gain in realism.
func generated(r *rand.Rand, alphabet string, n int) string {
	for {
		s := pick(r, alphabet, n)
		if n < 4 || !strings.ContainsAny(alphabet, digitChars) || !strings.ContainsAny(alphabet, upperAlpha) {
			return s
		}
		if strings.ContainsAny(s, digitChars) && strings.ContainsAny(s, upperAlpha) {
			return s
		}
	}
}

func randomBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.IntN(256))
	}
	return b
}

// GitHubToken returns a classic GitHub token: one of ghp_, gho_, ghu_, ghs_,
// ghr_ and 36 letters and digits.
func GitHubToken(r *rand.Rand, prefix string) string {
	return prefix + generated(r, base62, 36)
}

// GitHubLongFormToken returns a token in the shape GitHub has issued
// installation tokens in since September 2026: prefix, seven digits, then
// 36 and 254 base62 characters and an 86-character base64url tail, joined by
// "_", "." and ".". 390 characters for a ghs_ prefix.
//
// The tail carries both base64url punctuation characters on purpose, and ends
// in one when tailEnd is non-zero: a pattern that stops at "-" or demands a
// final letter would miss exactly those tokens, and a random tail would only
// sometimes produce them.
func GitHubLongFormToken(r *rand.Rand, prefix string, tailEnd byte) string {
	tail := []byte(generated(r, base62, 86))
	tail[r.IntN(40)] = '_'
	tail[40+r.IntN(40)] = '-'
	if tailEnd != 0 {
		tail[len(tail)-1] = tailEnd
	}
	return prefix + pick(r, digitChars, 7) + "_" + generated(r, base62, 36) +
		"." + generated(r, base62, 254) + "." + string(tail)
}

func jwt(r *rand.Rand) string {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(fmt.Sprintf(`{"alg":"RS256","kid":"%s","typ":"JWT"}`, pick(r, hexChars, 16))))
	claims := enc.EncodeToString([]byte(fmt.Sprintf(
		`{"iss":"https://kubernetes.default.svc","sub":"system:serviceaccount:apps:%s","exp":%d}`,
		pick(r, lowerAlpha, 8), 1759500000+r.IntN(100000))))
	return header + "." + claims + "." + enc.EncodeToString(randomBytes(r, 256))
}

// pemBody returns lines of base64 as a PEM encoder would wrap them.
func pemBody(r *rand.Rand, n int) []string {
	raw := base64.StdEncoding.EncodeToString(randomBytes(r, n))
	var lines []string
	for len(raw) > 64 {
		lines = append(lines, raw[:64])
		raw = raw[64:]
	}
	return append(lines, raw)
}

func pemBlock(label string, lines []string) string {
	return "-----BEGIN " + label + "-----\n" + strings.Join(lines, "\n") + "\n-----END " + label + "-----"
}

func b64(r *rand.Rand, n int) string {
	return base64.StdEncoding.EncodeToString(randomBytes(r, n))
}

// --- the corpus ----------------------------------------------------------------

func positives(r *rand.Rand) []Positive {
	var out []Positive
	add := func(p Positive) { out = append(out, p) }

	// GitHub, classic form: every prefix, each where it actually turns up.
	ghp := GitHubToken(r, "ghp_")
	add(Positive{Name: "github-token/ghp-exported", Detector: "github-token",
		Text:    "+export GITHUB_TOKEN=" + ghp + "\n+make release",
		Secrets: []string{ghp}, Keep: []string{"+export GITHUB_TOKEN=", "+make release"}})
	gho := GitHubToken(r, "gho_")
	add(Positive{Name: "github-token/gho-oauth-response", Detector: "github-token",
		Text:    `{"access_token":"` + gho + `","token_type":"bearer","scope":"repo"}`,
		Secrets: []string{gho}, Keep: []string{`"token_type":"bearer"`, `"scope":"repo"`}})
	ghu := GitHubToken(r, "ghu_")
	add(Positive{Name: "github-token/ghu-in-an-error", Detector: "github-token",
		Text:    "github: 401 Bad credentials for " + ghu + " (user-to-server)",
		Secrets: []string{ghu}, Keep: []string{"github: 401 Bad credentials for ", " (user-to-server)"}})
	ghs := GitHubToken(r, "ghs_")
	add(Positive{Name: "github-token/ghs-authorization-header", Detector: "github-token",
		Text:    "Authorization: token " + ghs + "\nAccept: application/vnd.github+json",
		Secrets: []string{ghs}, Keep: []string{"Authorization: token ", "Accept: application/vnd.github+json"}})
	ghr := GitHubToken(r, "ghr_")
	add(Positive{Name: "github-token/ghr-yaml", Detector: "github-token",
		Text:    "github:\n  refresh_token: " + ghr + "\n  expires_in: 15811200",
		Secrets: []string{ghr}, Keep: []string{"refresh_token: ", "expires_in: 15811200"}})

	// GitHub, long form. The one a remote URL carries is the leak that started
	// this: a clone that failed, quoting its own credential back.
	longGHS := GitHubLongFormToken(r, "ghs_", 0)
	add(Positive{Name: "github-token-long/ghs-git-remote", Detector: "github-token-long",
		Text: "fatal: unable to access 'https://x-access-token:" + longGHS +
			"@github.com/acme/widgets.git/': The requested URL returned error: 403",
		Secrets: []string{longGHS},
		Keep:    []string{"github.com/acme/widgets.git", "The requested URL returned error: 403"}})
	longCfg := GitHubLongFormToken(r, "ghs_", '-')
	add(Positive{Name: "github-token-long/ghs-committed-config-ending-in-dash", Detector: "github-token-long",
		Text:    "+github:\n+  token: " + longCfg + "\n+  repo: acme/widgets",
		Secrets: []string{longCfg}, Keep: []string{"+github:", "+  repo: acme/widgets"}})
	longSentence := GitHubLongFormToken(r, "ghs_", '_')
	add(Positive{Name: "github-token-long/ghs-ending-a-sentence", Detector: "github-token-long",
		Text:    "installation token " + longSentence + ". Retrying in 30s.",
		Secrets: []string{longSentence}, Keep: []string{"installation token ", ". Retrying in 30s."}})
	for _, p := range []string{"ghp_", "gho_", "ghu_", "ghr_"} {
		tok := GitHubLongFormToken(r, p, 0)
		add(Positive{Name: "github-token-long/" + strings.TrimSuffix(p, "_"), Detector: "github-token-long",
			Text:    "credential=" + tok + " expired",
			Secrets: []string{tok}, Keep: []string{" expired"}})
	}
	pat := "github_pat_11" + generated(r, base62, 20) + "_" + generated(r, base62, 59)
	add(Positive{Name: "github-fine-grained-pat/dotenv", Detector: "github-fine-grained-pat",
		Text:    "GH_PAT=" + pat + "\nGH_OWNER=acme",
		Secrets: []string{pat}, Keep: []string{"GH_PAT=", "GH_OWNER=acme"}})

	// Anthropic.
	apiKey := "sk-ant-api03-" + generated(r, b64url, 93) + "AA"
	add(Positive{Name: "anthropic-api-key/env-json", Detector: "anthropic-api-key",
		Text:    `{"ANTHROPIC_API_KEY":"` + apiKey + `","ANTHROPIC_MODEL":"claude-opus-5-5"}`,
		Secrets: []string{apiKey}, Keep: []string{`{"ANTHROPIC_API_KEY":"`, `"ANTHROPIC_MODEL":"claude-opus-5-5"`}})
	apiKey2 := "sk-ant-api03-" + generated(r, b64url, 93) + "AA"
	add(Positive{Name: "anthropic-api-key/x-api-key-header", Detector: "anthropic-api-key",
		Text:    "POST /v1/messages HTTP/1.1\r\nx-api-key: " + apiKey2 + "\r\nanthropic-version: 2023-06-01",
		Secrets: []string{apiKey2}, Keep: []string{"x-api-key: ", "anthropic-version: 2023-06-01"}})
	oat := "sk-ant-oat01-" + generated(r, b64url, 93) + "AA"
	ort := "sk-ant-ort01-" + generated(r, b64url, 93) + "AA"
	add(Positive{Name: "anthropic-oauth-token/claude-credentials-file", Detector: "anthropic-oauth-token",
		Text:    `{"claudeAiOauth":{"accessToken":"` + oat + `","refreshToken":"` + ort + `","expiresAt":1759500000000,"scopes":["user:inference"]}}`,
		Secrets: []string{oat, ort}, Keep: []string{`"expiresAt":1759500000000`, `"scopes":["user:inference"]`}})
	admin := "sk-ant-admin01-" + generated(r, b64url, 93) + "AA"
	add(Positive{Name: "anthropic-key/admin-key", Detector: "anthropic-key",
		Text:    "usage report: authenticating with " + admin + " failed (403)",
		Secrets: []string{admin}, Keep: []string{"usage report: authenticating with ", " failed (403)"}})

	// OpenAI.
	proj := "sk-proj-" + generated(r, b64url, 74) + "T3BlbkFJ" + generated(r, b64url, 74)
	add(Positive{Name: "openai-api-key/project-key", Detector: "openai-api-key",
		Text:    "OPENAI_API_KEY=" + proj,
		Secrets: []string{proj}, Keep: []string{"OPENAI_API_KEY="}})
	legacy := "sk-" + generated(r, base62, 20) + "T3BlbkFJ" + generated(r, base62, 20)
	add(Positive{Name: "openai-api-key/legacy-key", Detector: "openai-api-key",
		Text:    "openai.error.AuthenticationError: Incorrect API key provided: " + legacy + ".",
		Secrets: []string{legacy}, Keep: []string{"Incorrect API key provided: "}})

	// Slack.
	xoxb := "xoxb-" + pick(r, digitChars, 12) + "-" + pick(r, digitChars, 13) + "-" + generated(r, base62, 24)
	add(Positive{Name: "slack-token/bot-token", Detector: "slack-token",
		Text:    "SLACK_BOT_TOKEN=" + xoxb + "\nSLACK_CHANNEL=#deploys",
		Secrets: []string{xoxb}, Keep: []string{"SLACK_BOT_TOKEN=", "SLACK_CHANNEL=#deploys"}})
	xapp := "xapp-1-A0" + pick(r, upperAlpha+digitChars, 9) + "-" + pick(r, digitChars, 13) + "-" + pick(r, hexChars, 64)
	add(Positive{Name: "slack-token/app-level-token", Detector: "slack-token",
		Text:    "socket mode: connecting with " + xapp,
		Secrets: []string{xapp}, Keep: []string{"socket mode: connecting with "}})

	// AWS.
	akia := "AKIA" + generated(r, upperAlpha+digitChars, 16)
	awsSecret := b64(r, 30)
	add(Positive{Name: "aws-access-key-id/credentials-file", Detector: "aws-access-key-id",
		Text:    "[default]\naws_access_key_id = " + akia + "\naws_secret_access_key = " + awsSecret + "\nregion = eu-central-1",
		Secrets: []string{akia, awsSecret}, Keep: []string{"[default]", "region = eu-central-1"}})
	asia := "ASIA" + generated(r, upperAlpha+digitChars, 16)
	stsSecret := b64(r, 30)
	session := b64(r, 300)
	add(Positive{Name: "aws-secret-access-key/sts-credentials", Detector: "aws-secret-access-key",
		Text: `{"Credentials":{"AccessKeyId":"` + asia + `","SecretAccessKey":"` + stsSecret +
			`","SessionToken":"` + session + `","Expiration":"2026-10-03T18:00:00+00:00"}}`,
		Secrets: []string{asia, stsSecret, session},
		Keep:    []string{`"Expiration":"2026-10-03T18:00:00+00:00"`}})

	// Google.
	gkey := "AIza" + generated(r, b64url, 35)
	add(Positive{Name: "google-api-key/request-url", Detector: "google-api-key",
		Text:    "GET https://maps.googleapis.com/maps/api/geocode/json?address=Berlin&key=" + gkey + " 403 Forbidden",
		Secrets: []string{gkey}, Keep: []string{"maps.googleapis.com/maps/api/geocode/json?address=Berlin", " 403 Forbidden"}})

	// JWTs.
	idTok := jwt(r)
	add(Positive{Name: "jwt/rejected-id-token", Detector: "jwt",
		Text:    "oidc: id token rejected: " + idTok + " (audience mismatch)",
		Secrets: []string{idTok}, Keep: []string{"oidc: id token rejected: ", " (audience mismatch)"}})
	cookie := jwt(r)
	add(Positive{Name: "jwt/set-cookie", Detector: "jwt",
		Text:    "Set-Cookie: hub_session=" + cookie + "; Path=/; HttpOnly; Secure",
		Secrets: []string{cookie}, Keep: []string{"Set-Cookie: hub_session=", "; Path=/; HttpOnly; Secure"}})

	// PEM private keys: committed, JSON-escaped, and cut off mid-key.
	rsa := pemBody(r, 600)
	add(Positive{Name: "pem-private-key/committed-deploy-key", Detector: "pem-private-key",
		Text: "diff --git a/.cloop/deploy_key b/.cloop/deploy_key\nnew file mode 100600\n--- /dev/null\n+++ b/.cloop/deploy_key\n" +
			prefixLines("+", pemBlock("RSA PRIVATE KEY", rsa)) + "\ndiff --git a/README.md b/README.md",
		Secrets: rsa, Keep: []string{"diff --git a/.cloop/deploy_key b/.cloop/deploy_key", "diff --git a/README.md b/README.md"}})
	ssh := pemBody(r, 300)
	add(Positive{Name: "pem-private-key/json-escaped-openssh-key", Detector: "pem-private-key",
		Text:    `{"ssh_key":"` + strings.ReplaceAll(pemBlock("OPENSSH PRIVATE KEY", ssh), "\n", `\n`) + `\n","host":"git.example.com"}`,
		Secrets: ssh, Keep: []string{`{"ssh_key":"`, `"host":"git.example.com"}`}})
	ec := pemBody(r, 90)
	add(Positive{Name: "pem-private-key/cut-off-in-an-error", Detector: "pem-private-key",
		Text:    "x509: failed to parse private key: -----BEGIN EC PRIVATE KEY-----\n" + strings.Join(ec[:1], "\n"),
		Secrets: ec[:1], Keep: []string{"x509: failed to parse private key: "}})

	// Kubeconfigs: the client key goes, the public certificates stay.
	ca, cert, key := b64(r, 800), b64(r, 800), b64(r, 1200)
	add(Positive{Name: "kubeconfig-client-key/client-certificate-user", Detector: "kubeconfig-client-key",
		Text:    kubeconfig("    client-certificate-data: "+cert+"\n    client-key-data: "+key, ca),
		Secrets: []string{key},
		Keep:    []string{"certificate-authority-data: " + ca, "client-certificate-data: " + cert, "server: https://k8s.example.com:6443"}})
	static := generated(r, base62, 40)
	add(Positive{Name: "token-field/kubeconfig-static-token", Detector: "token-field",
		Text:    kubeconfig("    token: "+static, ca),
		Secrets: []string{static}, Keep: []string{"certificate-authority-data: " + ca, "server: https://k8s.example.com:6443"}})
	saTok := jwt(r)
	add(Positive{Name: "jwt/kubeconfig-service-account-token", Detector: "jwt",
		Text:    kubeconfig("    token: "+saTok, ca),
		Secrets: []string{saTok}, Keep: []string{"certificate-authority-data: " + ca}})

	// Credential fields.
	access, refresh := generated(r, b64url, 40), generated(r, b64url, 64)
	add(Positive{Name: "token-field/oauth-token-response", Detector: "token-field",
		Text:    `{"access_token":"` + access + `","token_type":"Bearer","expires_in":3599,"refresh_token":"` + refresh + `","scope":"openid email"}`,
		Secrets: []string{access, refresh}, Keep: []string{`"token_type":"Bearer"`, `"expires_in":3599`, `"scope":"openid email"`}})
	clientSecret := generated(r, b64url, 40)
	add(Positive{Name: "token-field/oidc-client-secret", Detector: "token-field",
		Text:    "auth-provider:\n  config:\n    client-id: cloop-hub\n    client_secret: " + clientSecret + "\n    idp-issuer-url: https://login.example.com",
		Secrets: []string{clientSecret}, Keep: []string{"client-id: cloop-hub", "idp-issuer-url: https://login.example.com"}})

	// Authorization headers, as each tool prints them.
	basic := base64.StdEncoding.EncodeToString([]byte("deploy:" + generated(r, base62, 24)))
	add(Positive{Name: "authorization-header/curl-verbose-basic", Detector: "authorization-header",
		Text:    "> GET /v2/ HTTP/1.1\n> Host: registry.example.com\n> Authorization: Basic " + basic + "\n> User-Agent: curl/8.5.0",
		Secrets: []string{basic}, Keep: []string{"> Host: registry.example.com", "> User-Agent: curl/8.5.0"}})
	fetchTok := generated(r, b64url, 43)
	add(Positive{Name: "authorization-header/fetch-headers-json", Detector: "authorization-header",
		Text:    `{"url":"/api/state","headers":{"Authorization":"Bearer ` + fetchTok + `","Accept":"application/json"}}`,
		Secrets: []string{fetchTok}, Keep: []string{`"url":"/api/state"`, `"Accept":"application/json"`}})
	goTok := generated(r, hexChars+upperAlpha, 40)
	add(Positive{Name: "authorization-header/go-http-header", Detector: "authorization-header",
		Text:    `Get "https://api.example.com/v1/jobs": headers map[Authorization:[Bearer ` + goTok + `] User-Agent:[cloop/0.0.4]]`,
		Secrets: []string{goTok}, Keep: []string{`Get "https://api.example.com/v1/jobs"`, "User-Agent:[cloop/0.0.4]"}})
	add(Positive{Name: "authorization-header/letters-only-value", Detector: "authorization-header",
		Text:    "Authorization: Bearer supersecretpassword\nContent-Type: application/json",
		Secrets: []string{"supersecretpassword"}, Keep: []string{"Authorization: Bearer ", "Content-Type: application/json"}})
	bare := pick(r, hexChars, 40)
	add(Positive{Name: "bearer-token/in-prose", Detector: "bearer-token",
		Text:    "upstream answered 401 to bearer " + bare + "; refreshing",
		Secrets: []string{bare}, Keep: []string{"upstream answered 401 to bearer ", "; refreshing"}})

	// Credentials in URLs.
	proxySecret := pick(r, hexChars, 64)
	add(Positive{Name: "url-userinfo/egress-proxy", Detector: "url-userinfo",
		Text:    "proxyconnect tcp: dial http://sess_" + pick(r, hexChars, 24) + ":" + proxySecret + "@10.0.0.7:3128: connection refused",
		Secrets: []string{proxySecret}, Keep: []string{"proxyconnect tcp: dial http://", "@10.0.0.7:3128: connection refused"}})
	dbPass := generated(r, base62, 20)
	add(Positive{Name: "url-userinfo/database-dsn", Detector: "url-userinfo",
		Text:    "pq: password authentication failed for postgres://cloop:" + dbPass + "@db.internal:5432/cloop?sslmode=require",
		Secrets: []string{dbPass}, Keep: []string{"@db.internal:5432/cloop?sslmode=require"}})
	userTok := pick(r, hexChars, 40)
	add(Positive{Name: "url-userinfo/token-as-username", Detector: "url-userinfo",
		Text:    "git clone https://" + userTok + "@git.example.com/acme/widgets.git",
		Secrets: []string{userTok}, Keep: []string{"git clone https://", "@git.example.com/acme/widgets.git"}})

	// cloop's own credentials.
	pat1 := "cloop_pat_" + pick(r, hexChars, 16) + "_" + pick(r, hexChars, 64)
	add(Positive{Name: "cloop-api-token/curl", Detector: "cloop-api-token",
		Text:    `curl -fsS -H "Authorization: Bearer ` + pat1 + `" https://hub.example.com/api/state`,
		Secrets: []string{pat1}, Keep: []string{"curl -fsS -H ", " https://hub.example.com/api/state"}})
	pat2 := "cloop_pat_" + pick(r, hexChars, 16) + "_" + pick(r, hexChars, 64)
	add(Positive{Name: "cloop-api-token/glasses-link", Detector: "cloop-api-token",
		Text:    "TypeError: Failed to fetch at https://hub.example.com/glasses?token=" + pat2 + "#tasks",
		Secrets: []string{pat2}, Keep: []string{"TypeError: Failed to fetch at https://hub.example.com/glasses?token=", "#tasks"}})
	glasses := "cloop_glasses_" + pick(r, hexChars, 8) + "_" + pick(r, hexChars, 24)
	add(Positive{Name: "cloop-glasses-link/legacy-prefix", Detector: "cloop-glasses-link",
		Text:    "401 for " + glasses + ", retrying",
		Secrets: []string{glasses}, Keep: []string{"401 for ", ", retrying"}})
	ci := "cloop_ci_" + pick(r, hexChars, 24) + "." + pick(r, hexChars, 64)
	add(Positive{Name: "cloop-ci-token/relay-environment", Detector: "cloop-ci-token",
		Text:    "ANTHROPIC_BASE_URL=https://hub.example.com/api/ci/claude\nANTHROPIC_AUTH_TOKEN=" + ci,
		Secrets: []string{ci}, Keep: []string{"ANTHROPIC_BASE_URL=https://hub.example.com/api/ci/claude", "ANTHROPIC_AUTH_TOKEN="}})
	clet := "clet1." + generated(r, b64url, 16) + "." + generated(r, b64url, 43) + "." + pick(r, hexChars, 32)
	add(Positive{Name: "cloop-enrollment-token/install-command", Detector: "cloop-enrollment-token",
		Text:    "curl -fsSL https://hub.example.com/install.sh | sh -s -- --token " + clet + " --name edge-01",
		Secrets: []string{clet}, Keep: []string{"curl -fsSL https://hub.example.com/install.sh | sh -s -- --token ", " --name edge-01"}})
	bundle := "cloopenroll1." + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"server":"https://hub.example.com","token":"%s","name":"edge-01","pin":"sha256:%s"}`,
		"clet1."+generated(r, b64url, 16)+"."+generated(r, b64url, 43)+"."+pick(r, hexChars, 32),
		base64.StdEncoding.EncodeToString(randomBytes(r, 32)))))
	add(Positive{Name: "cloop-enrollment-bundle/agent-install", Detector: "cloop-enrollment-bundle",
		Text:    "sudo cloop executor agent install --bundle " + bundle + " --packet-filter",
		Secrets: []string{bundle}, Keep: []string{"sudo cloop executor agent install --bundle ", " --packet-filter"}})
	clac := "clac1." + generated(r, b64url, 16) + "." + generated(r, b64url, 43) + "." + pick(r, hexChars, 32)
	add(Positive{Name: "cloop-agent-credential/credential-file", Detector: "cloop-agent-credential",
		Text:    "# /var/lib/cloop-agent/credential\n" + clac + "\n",
		Secrets: []string{clac}, Keep: []string{"# /var/lib/cloop-agent/credential"}})

	// A credential is not always set off by plain delimiters. A logger that
	// truncates long values runs its marker straight into one, and a URL
	// carried inside another URL percent-encodes the "=" in front of it.
	truncated := generated(r, b64url, 43)
	add(Positive{Name: "authorization-header/truncated-by-a-logger", Detector: "authorization-header",
		Text:    "> GET /v1/jobs HTTP/1.1\n> Authorization: Bearer " + truncated + "[truncated]\n> Accept: application/json",
		Secrets: []string{truncated}, Keep: []string{"[truncated]", "> Accept: application/json"}})
	encoded := "sk-proj-" + generated(r, b64url, 74) + "T3BlbkFJ" + generated(r, b64url, 74)
	add(Positive{Name: "openai-api-key/percent-encoded-in-a-redirect", Detector: "openai-api-key",
		Text:    "GET /auth/return?next=%2Fv1%2Fmodels%3Fkey%3D" + encoded + "%26limit%3D20 HTTP/1.1",
		Secrets: []string{encoded}, Keep: []string{"GET /auth/return?next=%2Fv1%2Fmodels%3Fkey%3D", "%26limit%3D20 HTTP/1.1"}})
	carried := generated(r, b64url, 40)
	add(Positive{Name: "token-field/percent-encoded-field", Detector: "token-field",
		Text:    "GET /login?next=%2Foauth%2Fcallback%3Faccess_token%3D" + carried + "%26state%3Dq7 HTTP/1.1",
		Secrets: []string{carried}, Keep: []string{"GET /login?next=%2Foauth%2Fcallback%3Faccess_token%3D", "%26state%3Dq7 HTTP/1.1"}})

	// The forms of OpenAI key that predate projects carry sk-None-.
	none := "sk-None-" + generated(r, b64url, 48) + "T3BlbkFJ" + generated(r, b64url, 48)
	add(Positive{Name: "openai-api-key/none-key", Detector: "openai-api-key",
		Text:    "openai.AuthenticationError: Incorrect API key provided: " + none + ". You can find your API key at https://platform.openai.com/account/api-keys.",
		Secrets: []string{none}, Keep: []string{"Incorrect API key provided: ", "You can find your API key at https://platform.openai.com/account/api-keys."}})

	// Fields as programs print them: behind a prefix, inside a JSON document
	// that is itself a JSON string, as a Go http.Header.
	prefixed := "glpat-" + generated(r, b64url, 20)
	add(Positive{Name: "token-field/prefixed-environment-variable", Detector: "token-field",
		Text:    "+export GITLAB_TOKEN=" + prefixed + "\n+export X_REGION=eu",
		Secrets: []string{prefixed}, Keep: []string{"+export GITLAB_TOKEN=", "+export X_REGION=eu"}})
	escAccess, escRefresh := "ya29.a0"+generated(r, b64url, 60), "1//0g"+generated(r, b64url, 50)
	add(Positive{Name: "token-field/escaped-json", Detector: "token-field",
		Text: `oauth2: cannot fetch token: 400 Bad Request: "{\"access_token\":\"` + escAccess +
			`\",\"expires_in\":3599,\"refresh_token\":\"` + escRefresh + `\",\"scope\":\"openid\"}"`,
		Secrets: []string{escAccess, escRefresh}, Keep: []string{`\"expires_in\":3599`, `\"scope\":\"openid\"}"`}})
	headerTok := generated(r, base62, 32)
	add(Positive{Name: "token-field/go-http-header", Detector: "token-field",
		Text:    "request headers: map[Access-Token:[" + headerTok + "] User-Agent:[cloop/0.0.4]]",
		Secrets: []string{headerTok}, Keep: []string{"request headers: map[Access-Token:[", "] User-Agent:[cloop/0.0.4]]"}})
	escBasic := base64.StdEncoding.EncodeToString([]byte("ci:" + generated(r, base62, 24)))
	add(Positive{Name: "authorization-header/escaped-json", Detector: "authorization-header",
		Text:    `level=warn msg="retrying" headers="{\"Authorization\":\"Basic ` + escBasic + `\",\"Accept\":\"*/*\"}"`,
		Secrets: []string{escBasic}, Keep: []string{`level=warn msg="retrying" headers="{\"Authorization\":\"Basic `, `\",\"Accept\":\"*/*\"}"`}})
	escSecret := generated(r, base62+"+/", 40)
	add(Positive{Name: "aws-secret-access-key/escaped-json", Detector: "aws-secret-access-key",
		Text:    `{"Credentials":"{\"SecretAccessKey\":\"` + escSecret + `\",\"Expiration\":\"2026-10-03T18:00:00Z\"}"}`,
		Secrets: []string{escSecret}, Keep: []string{`\",\"Expiration\":\"2026-10-03T18:00:00Z\"}"}`}})

	// A generated password may begin with anything a template does not: a
	// percent-encoded "!", a "*".
	pctPass := "%21" + generated(r, base62, 16)
	add(Positive{Name: "url-userinfo/percent-encoded-password", Detector: "url-userinfo",
		Text:    "pq: connection refused for postgres://cloop:" + pctPass + "@db.internal:5432/cloop",
		Secrets: []string{pctPass}, Keep: []string{"pq: connection refused for postgres://", "@db.internal:5432/cloop"}})
	symPass := "*" + generated(r, base62, 15)
	add(Positive{Name: "url-userinfo/password-led-by-a-symbol", Detector: "url-userinfo",
		Text:    "proxyconnect tcp: dial http://deploy:" + symPass + "@10.0.0.7:3128: i/o timeout",
		Secrets: []string{symPass}, Keep: []string{"proxyconnect tcp: dial http://", "@10.0.0.7:3128: i/o timeout"}})

	// A value is removed whole, whatever punctuation it holds: a Sanctum-style
	// "<id>|<token>", and base64 whose "+" and "/" were percent-encoded.
	sanctum := generated(r, base62, 40)
	add(Positive{Name: "bearer-token/value-holding-a-pipe", Detector: "bearer-token",
		Text:    "laravel: 401 for bearer 7|" + sanctum + " on /api/user",
		Secrets: []string{sanctum}, Keep: []string{"laravel: 401 for bearer ", " on /api/user"}})
	seg1, seg2, seg3 := generated(r, base62, 20), generated(r, base62, 20), generated(r, base62, 19)
	add(Positive{Name: "authorization-header/percent-encoded-base64", Detector: "authorization-header",
		Text:    "proxy log: Authorization: Bearer " + seg1 + "%2B" + seg2 + "%2F" + seg3 + "%3D (expired)",
		Secrets: []string{seg1, seg2, seg3}, Keep: []string{"proxy log: Authorization: Bearer ", " (expired)"}})

	return out
}

func prefixLines(prefix, s string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n")
}

func kubeconfig(user, ca string) string {
	return "apiVersion: v1\nkind: Config\nclusters:\n- name: prod\n  cluster:\n" +
		"    certificate-authority-data: " + ca + "\n    server: https://k8s.example.com:6443\n" +
		"contexts:\n- name: prod\n  context:\n    cluster: prod\n    user: deployer\n    namespace: apps\n" +
		"current-context: prod\nusers:\n- name: deployer\n  user:\n" + user + "\n"
}

func negatives(r *rand.Rand) []Negative {
	var out []Negative
	add := func(name, text string) { out = append(out, Negative{Name: name, Text: text}) }

	// Base64 in a diff: an image, then a base64url key modulus.
	img := base64.StdEncoding.EncodeToString(randomBytes(r, 3000))
	var img76 []string
	for len(img) > 76 {
		img76 = append(img76, img[:76])
		img = img[76:]
	}
	img76 = append(img76, img)
	add("base64 image in a diff",
		"diff --git a/docs/img/logo.png.b64 b/docs/img/logo.png.b64\nnew file mode 100644\nindex 0000000..3b18e51\n"+
			"--- /dev/null\n+++ b/docs/img/logo.png.b64\n@@ -0,0 +1,40 @@\n"+prefixLines("+", strings.Join(img76, "\n")))
	add("base64url key modulus in a diff",
		"+{\n+  \"kty\": \"RSA\",\n+  \"e\": \"AQAB\",\n+  \"n\": \""+
			base64.RawURLEncoding.EncodeToString(randomBytes(r, 256))+"\"\n+}")
	var gosum strings.Builder
	for _, mod := range []string{"golang.org/x/crypto v0.31.0", "golang.org/x/net v0.33.0", "nhooyr.io/websocket v1.8.17", "modernc.org/sqlite v1.34.4"} {
		h := base64.StdEncoding.EncodeToString(randomBytes(r, 32))
		gm := base64.StdEncoding.EncodeToString(randomBytes(r, 32))
		gosum.WriteString(mod + " h1:" + h + "\n" + mod + "/go.mod h1:" + gm + "\n")
	}
	add("go.sum lines", gosum.String())
	add("public SSH key", "ssh-ed25519 "+base64.StdEncoding.EncodeToString(append([]byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 "), randomBytes(r, 32)...))+" deploy@edge-01")

	// Commit SHAs and object ids, as git prints them.
	sha := func() string { return hex.EncodeToString(randomBytes(r, 20)) }
	add("git log with SHAs",
		"commit "+sha()+"\nMerge: "+sha()[:7]+" "+sha()[:7]+"\nAuthor: Aiden <claude@blechschmidt.io>\nDate:   Sat Oct 3 17:07:00 2026 +0000\n\n"+
			"    fix(features): let go of a run's output before showing how it came back\n\n"+
			"diff --git a/pkg/feature/land.go b/pkg/feature/land.go\nindex "+sha()[:7]+".."+sha()[:7]+" 100644")
	add("abbreviated SHAs in a oneline log",
		"fa5af0c fix(features): let go of a run's output before showing how it came back\n"+
			"67d453e test: pin the feature e2e's broker; cover overlay provisioning on a forge\n"+
			"be25ddb test(e2e): name the stub claude's files so two runs in a second differ")

	// Identifiers: UUIDs, prefixed ids, digests.
	uuid := func() string {
		h := hex.EncodeToString(randomBytes(r, 16))
		return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	}
	add("UUIDs", "request_id="+uuid()+" trace="+strings.ToUpper(uuid())+" run "+uuid()+" finished")
	add("task ids that end in sk-", "worktree task-"+hex.EncodeToString(randomBytes(r, 16))+" removed; task-42 requeued; disk-full warning cleared")
	add("prefixed object ids",
		"lease_"+hex.EncodeToString(randomBytes(r, 12))+" granted to sess_"+hex.EncodeToString(randomBytes(r, 12))+
			" for run_"+hex.EncodeToString(randomBytes(r, 16))+" (hub_"+hex.EncodeToString(randomBytes(r, 8))+")")
	add("image digests", "ghcr.io/blechschmidt/cloop-harness@sha256:"+hex.EncodeToString(randomBytes(r, 32))+
		"\nsha256:"+hex.EncodeToString(randomBytes(r, 32))+"  cloop_linux_amd64.tar.gz")

	// Public halves of things that have a private half.
	add("kubeconfig without credentials",
		kubeconfig("    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: aws\n"+
			"      args: [eks, get-token, --cluster-name, prod]\n    token-file: /var/run/secrets/kubernetes.io/serviceaccount/token",
			b64(r, 800)))
	add("certificate and public key blocks",
		pemBlock("CERTIFICATE", pemBody(r, 700))+"\n"+pemBlock("PUBLIC KEY", pemBody(r, 294)))
	add("JOSE header on its own", "kid lookup failed for header "+base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)))

	// cloop's own names that share a prefix with nothing secret.
	add("nftables table names",
		"sudo nft list table inet cloop_sbx_vx_abcdefghij\ncloop egress firewall preview --table cloop_sbx_preview --format nft-bridge")
	add("Prometheus metric names",
		"cloop_apitoken_auth_failures_total{reason=\"expired\"} 3\ncloop_secret_leases_live 2\ncloop_gitproxy_push_denials_total 0")

	// Prose about credentials, which mentions their shapes without one.
	add("prose about token formats",
		"Tokens look like cloop_pat_<id>_<secret>. Set GITHUB_TOKEN to a ghp_… token or paste a github_pat_… one. "+
			"Requests need a Bearer token in the Authorization header; bearer authentication is required.")
	add("placeholders where a credential would go",
		"curl -H \"Authorization: Bearer $CLOOP_TOKEN\" https://hub.example.com/api/state\n"+
			"token: ${{ secrets.CLOOP_TOKEN }}\nAuthorization: Bearer YOUR_API_TOKEN\npassword: %s")
	add("URLs without credentials",
		"https://github.com/acme/widgets.git ssh://git@github.com/acme/widgets.git git@github.com:acme/widgets.git "+
			"https://user@example.com/ http://[::1]:8080/healthz")
	add("token counts and config keys",
		"max_tokens: 4096\ninput_tokens=1234 output_tokens=567\n\"token_type\": \"Bearer\"\n--max-tokens 4096\ntoken_budget: 50000\nauth_token_ttl: 3600")

	// What scanners themselves write, which must be stable under a second pass.
	add("redaction markers", "token=[redacted] Bearer [REDACTED] https://[redacted]@github.com/acme/x sk-ant-api03-[REDACTED] ghs_[REDACTED]")
	add("provider audit headers",
		`{"authorization":"Bearer [REDACTED]","extended_thinking":false,"max_tokens":4096,"timeout_seconds":600}`)

	// The kind of text the scanners see most.
	add("Go stack trace", "panic: runtime error: index out of range [3] with length 3\n\ngoroutine 1 [running]:\n"+
		"main.main()\n\t/root/Projects/cloop/main.go:12 +0x1d\nexit status 2")
	add("audit reasons",
		"grant expired at 2026-03-01T12:00:00Z\nrepository org/tool is not in the grant's repository allowlist (org/*)\n"+
			"issued 2 material(s): deploy-pat,prod-kube")
	add("telemetry paths", "/api/tokens/list?page=1 /api/glasses/tasks?project_idx=2 /api/secrets/github-deploy-key")
	add("versions and addresses", "cloop 0.0.4 (fa5af0c) listening on 10.0.0.7:3128 and [2001:db8::1]:8443")

	// Near-misses the review of the first registry found, each once matched.
	add("a private-key header with no key after it",
		"x509: no -----BEGIN RSA PRIVATE KEY----- block found in deploy key for acme/widgets; check the file\n"+
			`<textarea placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;…"></textarea>`)
	add("field keys with their values on the next line",
		"authorization:\n  allowedGroups: [admins]\ntoken:\n  expiresInSeconds: 3600\ntoken_type: Bearer\nexpiresIn: 3600")
	add("code that names credentials",
		"Token:   cfg.APIToken,\ntoken = os.Getenv(\"CLOOP_TOKEN\")\nAuthorization: r.Header.Get(\"Authorization\"),\n"+
			"authorization: forbidden for role viewer\nwrap the Bearer TokenSource in a cache\nrefresh token: ExpiredTokenError")
	add("documentation placeholders",
		"GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\ngh auth login --with-token <<< ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"+
			"ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxx\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"+
			"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	add("URL templates",
		"postgres://cloop:${DB_PASSWORD}@db:5432/cloop https://deploy:$REGISTRY_PASSWORD@registry.example.com/v2/ "+
			"http://u:%s@proxy:3128 https://ci:****@git.example.com/acme/x.git")
	return out
}
