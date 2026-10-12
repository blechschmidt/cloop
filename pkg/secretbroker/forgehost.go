package secretbroker

// forgehost.go binds a GitHub grant to the forge host its credential is good
// against (Task 20423).
//
// A repository allowlist names owner/name, and nothing else. Before this file a
// grant for acme/* therefore matched https://attacker.example/acme/tool as
// readily as https://github.com/acme/tool, and every path that chose a
// credential by AllowsRepo alone — workspace provisioning, the git proxy's
// pinned sessions, a feature's push and pull request — handed the token to
// whatever host a project's origin named. Whoever could point a project's
// origin elsewhere received the token the git proxy exists to keep on the hub.
//
// So a GitHub material now carries its host, and a repository reference is
// (host, path) wherever a credential is chosen or bound:
//
//   - github_pat: github.com, unless the payload recorded a GitHub Enterprise
//     Server host — {"token": "...", "host": "ghes.example.com"}. The host lives
//     in the sealed payload, where nothing that can edit a row can move it.
//   - github_app: the web host of the payload's base_url
//     (forgehost.WebHostForAPI): github.com for the public API, the server for
//     a GitHub Enterprise Server /api/v3.
//
// Secrets minted before this change carry bare-token PATs, which are
// github.com, and App payloads whose base_url already says where they belong,
// so nothing written earlier is widened: every one of them is bound to exactly
// the host its credential was always good against.
//
// Mint also records the host as metadata (MetaForgeHost), derived from the
// payload and never taken from the caller, so a path that must not open a
// payload — the hub's grant picker — can still choose by host. The metadata is
// a convenience for choosing; the sealed payload is what binds, and a lease
// re-derives the host from it every time.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/forgehost"
)

// MetaForgeHost is the metadata key Mint records a GitHub secret's forge host
// under. It is derived from the payload; a value a caller supplies is replaced.
const MetaForgeHost = "forge_host"

// gitHubPATDocument is a github_pat payload that records the GitHub Enterprise
// Server host the token was issued by. A bare token is a github.com token.
type gitHubPATDocument struct {
	Token string `json:"token"`
	Host  string `json:"host"`
}

// GitHubPATPayload renders token, issued by the GitHub host host, as a
// github_pat payload. An empty host, or github.com, renders the bare token:
// the form every PAT was stored in before hosts were recorded.
func GitHubPATPayload(token, host string) ([]byte, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, wrapf(ErrMalformedPayload, "github_pat payload: the token is empty")
	}
	if strings.TrimSpace(host) == "" {
		return []byte(token), nil
	}
	c, err := recordedHost(host)
	if err != nil {
		return nil, err
	}
	if c == forgehost.GitHub {
		return []byte(token), nil
	}
	return json.Marshal(gitHubPATDocument{Token: token, Host: c})
}

// parseGitHubPAT reads a github_pat payload: a bare token, which is a
// github.com token, or the JSON document GitHubPATPayload writes.
//
// The document is decoded strictly. A misspelt field — "hostname" — would
// otherwise read as no host recorded, binding a GitHub Enterprise Server token
// to github.com; refused instead, it surfaces where it was made.
func parseGitHubPAT(plaintext []byte) (token, host string, err error) {
	trimmed := bytes.TrimSpace(plaintext)
	if len(trimmed) == 0 {
		return "", "", wrapf(ErrMalformedPayload, "github_pat payload is empty")
	}
	if trimmed[0] != '{' {
		return string(trimmed), forgehost.GitHub, nil
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	var doc gitHubPATDocument
	if err := dec.Decode(&doc); err != nil {
		// The decoder's message can quote the payload; it holds a token.
		return "", "", wrapf(ErrMalformedPayload,
			`github_pat payload looks like a JSON document but is not {"token": ..., "host": ...}`)
	}
	if dec.More() {
		return "", "", wrapf(ErrMalformedPayload, "github_pat payload carries more than one JSON document")
	}
	token = strings.TrimSpace(doc.Token)
	if token == "" {
		return "", "", wrapf(ErrMalformedPayload, "github_pat payload names no token")
	}
	host = forgehost.GitHub
	if strings.TrimSpace(doc.Host) != "" {
		if host, err = recordedHost(doc.Host); err != nil {
			return "", "", err
		}
	}
	return token, host, nil
}

// recordedHost canonicalises the host a PAT document records: a host, with a
// port if it needs one — not a URL, whose scheme, userinfo or path would say
// something the document has no field for, and so is refused rather than
// guessed at.
func recordedHost(raw string) (string, error) {
	if strings.ContainsAny(raw, "/@?#") {
		return "", wrapf(ErrMalformedPayload, "github_pat payload: host %q is not a bare host[:port]", raw)
	}
	c, err := forgehost.Canonical(raw)
	if err != nil {
		return "", wrapf(ErrMalformedPayload, "github_pat payload: host %q: %v", raw, err)
	}
	return c, nil
}

// appForgeHost is the web host a GitHub App credential's tokens are good
// against.
func appForgeHost(cred *AppCredential) (string, error) {
	host, err := forgehost.WebHostForAPI(cred.BaseURL)
	if err != nil {
		return "", wrapf(ErrMalformedPayload, "github_app payload: base_url %q names no forge host: %v",
			cred.BaseURL, err)
	}
	return host, nil
}

// payloadForgeHost derives a GitHub secret's forge host from its payload.
func payloadForgeHost(kind Kind, payload []byte) (string, error) {
	switch kind {
	case KindGitHubPAT:
		_, host, err := parseGitHubPAT(payload)
		return host, err
	case KindGitHubApp:
		cred, err := parseGitHubApp(payload, false)
		if err != nil {
			return "", err
		}
		return appForgeHost(cred)
	}
	return "", wrapf(ErrInvalidKind, "a %s secret has no forge host", kind)
}

// SecretForgeHost reports the forge host a GitHub secret's credential is good
// against, from what Mint recorded, without opening the payload; known is false
// when that cannot be said.
//
// A github_pat minted before hosts were recorded is a bare token, which is a
// github.com token, so it is known. A github_app minted then is not: where it
// belongs is in its sealed base_url. A caller that chooses by this treats an
// unknown host as "decided when the payload is opened", which a lease does —
// it never treats it as a match.
func SecretForgeHost(s Secret) (host string, known bool) {
	switch s.Kind {
	case KindGitHubPAT, KindGitHubApp:
	default:
		return "", false
	}
	if raw := strings.TrimSpace(s.Metadata[MetaForgeHost]); raw != "" {
		if c, err := forgehost.Canonical(raw); err == nil {
			return c, true
		}
		return "", false
	}
	if s.Kind == KindGitHubPAT {
		return forgehost.GitHub, true
	}
	return "", false
}

// withForgeHostMetadata returns meta with MetaForgeHost set to host — or
// removed, for host "" — copying rather than writing into the caller's map.
func withForgeHostMetadata(meta map[string]string, host string) map[string]string {
	if _, had := meta[MetaForgeHost]; !had && host == "" {
		return meta
	}
	out := make(map[string]string, len(meta)+1)
	for k, v := range meta {
		out[k] = v
	}
	if host == "" {
		delete(out, MetaForgeHost)
	} else {
		out[MetaForgeHost] = host
	}
	return out
}

// GitHubHost returns the forge host a GitHub material's token is good against,
// in forgehost's canonical form — github.com, or a GitHub Enterprise Server
// host — and "" for any other kind. A material is presented to this host and
// to no other.
func (m Material) GitHubHost() string {
	switch m.Kind {
	case KindGitHubPAT, KindGitHubApp:
	default:
		return ""
	}
	if m.githubHost != "" {
		return m.githubHost
	}
	// A material built outside this package's deliveries — a test's — names
	// no host; the bare token it carries is a github.com token.
	return forgehost.GitHub
}

// CheckForgeHost reports why a reference to a repository on originHost may not
// be authenticated with this material, or nil when it may: a
// *forgehost.Mismatch naming both hosts when they differ.
func (m Material) CheckForgeHost(originHost string) error {
	host := m.GitHubHost()
	if host == "" {
		return fmt.Errorf("%w: %s carries a %s secret, not a GitHub credential", ErrInvalidKind, m.SecretName, m.Kind)
	}
	return forgehost.Check(originHost, host)
}
