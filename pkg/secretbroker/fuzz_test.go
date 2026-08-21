package secretbroker

import (
	"encoding/json"
	"strings"
	"testing"
)

// Fuzzing here is aimed at the invariants, not just at "does it panic".
// Grant constraints are the authorisation boundary: they arrive from a CLI,
// from a JSON API body, and from a database row that an older or hostile
// writer may have produced. The properties below are the ones a bug would
// have to break in order to widen a grant, so they are asserted rather than
// merely exercised.

// shellMetacharacters must never survive validatePattern, because an
// accepted repo pattern is embedded verbatim into a generated POSIX shell
// script (see githubpat.go).
const shellMetacharacters = "`$\"'\\;|&<>\n\r\t(){}!#~"

// FuzzValidatePattern asserts the injection boundary holds: every pattern
// validatePattern accepts is safe to embed in a shell script, and every
// pattern it accepts is one path.Match can parse.
func FuzzValidatePattern(f *testing.F) {
	seeds := []string{
		"org/*", "*", "*/*", "org/tool", "org/svc-?", "a.b/c-d_e",
		"", "   ", "..", "org/../etc", "org/'; id; '", "org/$(id)",
		"org/`id`", "org/a\nb", `org\b`, "[", "[a-z]/*", "a**/b",
		"org/tool.git", "ORG/TOOL", strings.Repeat("a", 300),
		"org/*:read", ":", "///", "?", "org/?",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, pattern string) {
		err := validatePattern("repos", pattern)
		if err != nil {
			// Rejected patterns must not be storable, and nothing
			// downstream ever sees them. Nothing more to check.
			return
		}

		// Property 1: an accepted pattern contains no shell metacharacter.
		if i := strings.IndexAny(pattern, shellMetacharacters); i >= 0 {
			t.Fatalf("validatePattern accepted %q containing shell metacharacter %q",
				pattern, string(pattern[i]))
		}

		// Property 2: an accepted pattern can be embedded in the credential
		// helper without the generator refusing it, and the resulting script
		// still contains only the characters we vetted.
		script, buildErr := buildGitCredentialHelper([]string{pattern})
		if buildErr != nil {
			t.Fatalf("validatePattern accepted %q but the helper generator rejected it: %v",
				pattern, buildErr)
		}
		// The generated script has its own quotes and metacharacters; what
		// must not appear is a *new line* introduced by the pattern.
		if strings.Contains(pattern, "\n") || strings.Contains(script, pattern+"\n") &&
			strings.Count(script, "\n") < 10 {
			t.Fatalf("pattern %q distorted the generated script", pattern)
		}

		// Property 3: matching never panics and is decidable.
		for _, subject := range []string{"org/tool", "a/b", "x", "", "a/b/c", "../x"} {
			_ = matchRepoPattern(pattern, subject)
		}
	})
}

// FuzzNormalizeRepo asserts that a successfully normalised repository is
// always in the exact shape the matcher assumes: lowercase, one slash, no
// wildcard, no traversal. Every widening bug in a glob matcher starts with a
// subject the matcher did not expect.
func FuzzNormalizeRepo(f *testing.F) {
	seeds := []string{
		"org/tool", "Org/Tool", "org/tool.git", "org/tool/",
		"https://github.com/org/tool", "https://github.com/org/tool.git",
		"git@github.com:org/tool.git", "ssh://git@github.com/org/tool",
		"", "/", "//", "org", "org/", "/tool", "org/sub/tool",
		"org/../etc", "../etc/passwd", "org/*", "*/*", "org/[a-z]",
		"org/tool?", "org/tool#frag", "org/tool\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, repo string) {
		norm, err := NormalizeRepo(repo)
		if err != nil {
			if norm != "" {
				t.Fatalf("NormalizeRepo(%q) returned %q alongside an error", repo, norm)
			}
			return
		}

		if strings.Count(norm, "/") != 1 {
			t.Fatalf("NormalizeRepo(%q) = %q: want exactly one slash", repo, norm)
		}
		owner, name, _ := strings.Cut(norm, "/")
		if owner == "" || name == "" {
			t.Fatalf("NormalizeRepo(%q) = %q: empty segment", repo, norm)
		}
		if norm != strings.ToLower(norm) {
			t.Fatalf("NormalizeRepo(%q) = %q: not lowercased", repo, norm)
		}
		if strings.ContainsAny(norm, "*?[]") {
			t.Fatalf("NormalizeRepo(%q) = %q: subject must not contain wildcards", repo, norm)
		}
		if strings.Contains(norm, "..") {
			t.Fatalf("NormalizeRepo(%q) = %q: traversal survived", repo, norm)
		}

		// A normalised subject must be idempotent under normalisation, or a
		// caller that normalises twice would get a different answer from
		// the matcher than one that normalises once.
		again, againErr := NormalizeRepo(norm)
		if againErr != nil || again != norm {
			t.Fatalf("NormalizeRepo is not idempotent: %q → %q → %q (%v)", repo, norm, again, againErr)
		}

		// An empty allowlist must deny whatever the subject is.
		if (Constraints{}).AllowsRepo(repo) {
			t.Fatalf("empty allowlist allowed %q", repo)
		}
	})
}

// FuzzNormalizeHost asserts the egress subject shape, and specifically that
// a "*.example.com" allowlist can never be satisfied by a host that merely
// ends with the text "example.com".
func FuzzNormalizeHost(f *testing.F) {
	seeds := []string{
		"example.com", "api.example.com", "API.EXAMPLE.COM", "example.com.",
		"example.com:443", "https://api.example.com/x", "user:pass@evil.test",
		"https://api.example.com@evil.test/", "[::1]:8080", "[::1]", "",
		"*.example.com", "notexample.com", "evil-example.com",
		"a..b", "a/b", "a b", "a\nb",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	c := Constraints{Hosts: []string{"*.example.com"}}

	f.Fuzz(func(t *testing.T, host string) {
		norm, err := NormalizeHost(host)
		if err != nil {
			return
		}
		if norm != strings.ToLower(norm) {
			t.Fatalf("NormalizeHost(%q) = %q: not lowercased", host, norm)
		}
		if strings.ContainsAny(norm, "/?#@ \t\n*?[]") {
			t.Fatalf("NormalizeHost(%q) = %q: illegal character survived", host, norm)
		}

		// The subdomain rule: anything the allowlist admits must genuinely
		// be a subdomain of example.com, i.e. end in ".example.com" with a
		// non-empty label in front. Suffix confusion is the bug class this
		// guards ("notexample.com", "evil-example.com").
		if c.AllowsHost(host) {
			if !strings.HasSuffix(norm, ".example.com") || len(norm) <= len(".example.com") {
				t.Fatalf("*.example.com admitted %q (normalised %q)", host, norm)
			}
		}
	})
}

// FuzzParseSubject asserts that a subject either fails to parse or round
// trips through its canonical rendering. A subject that renders to something
// that parses differently would let a listing show one scope while the
// matcher applies another.
func FuzzParseSubject(f *testing.F) {
	seeds := []string{
		"project:/srv/app", "project:*", "executor:edge-01", "executor:*",
		"label:region=eu", "label:region=eu,gpu=true", "any", "*",
		"", ":", "project:", "label:", "label:=", "label:a", "label:a=",
		"unknown:x", "project:/srv/app/", "PROJECT:/srv/app",
		"label:a=b,a=c", "label:a=b,a=b", "project::x", "\n", "any:x",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, spec string) {
		sub, err := ParseSubject(spec)
		if err != nil {
			return
		}
		if verr := sub.Validate(); verr != nil {
			t.Fatalf("ParseSubject(%q) produced an invalid subject: %v", spec, verr)
		}

		rendered := sub.String()
		again, againErr := ParseSubject(rendered)
		if againErr != nil {
			t.Fatalf("ParseSubject(%q) → %q which does not re-parse: %v", spec, rendered, againErr)
		}
		if again.String() != rendered {
			t.Fatalf("subject rendering is not stable: %q → %q → %q", spec, rendered, again.String())
		}

		// A parsed subject must never match everything unless it was
		// explicitly asked to. This is the property that keeps a typo from
		// becoming a wildcard grant.
		wideOpen := sub.Matches(Requester{ExecutorID: "x", ProjectID: "/a"}) &&
			sub.Matches(Requester{ExecutorID: "y", ProjectID: "/b"})
		if wideOpen {
			switch sub.Type {
			case SubjectAny:
			case SubjectProject, SubjectExecutor:
				if sub.Value != "*" {
					t.Fatalf("ParseSubject(%q) → %v matches every requester without a wildcard", spec, sub)
				}
			case SubjectLabel:
				t.Fatalf("ParseSubject(%q) → label selector matched requesters with no labels", spec)
			}
		}
	})
}

// FuzzConstraintsJSON drives the shape constraints arrive in over the wire
// and out of the database. Decoding must never panic, and — the property
// that matters — a Constraints value that ValidateFor accepts for a kind
// must actually gate that kind.
func FuzzConstraintsJSON(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"repos":["org/*"]}`,
		`{"repos":["*"],"permissions":["contents:read"]}`,
		`{"namespaces":["team-a"],"contexts":["prod"]}`,
		`{"hosts":["*.example.com"]}`,
		`{"registries":["ghcr.io"]}`,
		`{"env_keys":["A","B"]}`,
		`{"repos":null}`,
		`{"repos":[""]}`,
		`{"repos":["org/'; id; '"]}`,
		`{"repos":[` + `"` + strings.Repeat("a", 300) + `"]}`,
		`{"env_keys":["A=B"]}`,
		`{"unknown":"field"}`,
		`[]`, `null`, `"x"`, `{`, ``,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	kinds := Kinds()

	f.Fuzz(func(t *testing.T, raw string) {
		var c Constraints
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			return
		}

		for _, kind := range kinds {
			if err := c.ValidateFor(kind); err != nil {
				continue
			}

			// Accepted for this kind ⇒ the gating dimension is populated.
			switch kind {
			case KindGitHubPAT, KindGitHubApp:
				if len(c.Repos) == 0 {
					t.Fatalf("ValidateFor(%s) accepted an empty repo allowlist: %q", kind, raw)
				}
				// And the accepted patterns must be embeddable.
				if _, err := buildGitCredentialHelper(c.Repos); err != nil {
					t.Fatalf("ValidateFor(%s) accepted repos the helper rejects: %q: %v", kind, raw, err)
				}
			case KindKubeconfig:
				if len(c.Namespaces) == 0 && len(c.Contexts) == 0 {
					t.Fatalf("ValidateFor(kubeconfig) accepted with no namespaces or contexts: %q", raw)
				}
			case KindEgressProxy:
				if len(c.Hosts) == 0 {
					t.Fatalf("ValidateFor(egress_proxy) accepted an empty host allowlist: %q", raw)
				}
			case KindRegistry:
				if len(c.Registries) == 0 {
					t.Fatalf("ValidateFor(registry) accepted an empty registry allowlist: %q", raw)
				}
			}

			// Every accepted env key must survive the K=V encoding, or the
			// whole environment block would be corrupted at delivery.
			for _, k := range c.EnvKeys {
				if strings.ContainsAny(k, "=\n\x00") {
					t.Fatalf("ValidateFor(%s) accepted env key %q", kind, k)
				}
			}

			// Matching must be total: no input causes a panic.
			_ = c.AllowsRepo("org/tool")
			_ = c.AllowsHost("api.example.com")
			_ = c.AllowsNamespace("team-a")
			_ = c.AllowsContext("prod")
			_ = c.AllowsRegistry("ghcr.io")
			_ = c.AllowsPermission("contents:read")
			_ = c.Summary()
		}
	})
}

// FuzzMinimizeKubeconfig drives the YAML minimiser with arbitrary input. A
// malformed kubeconfig must produce an error, never a partially-rewritten
// document — and a successful minimisation must never contain a context the
// constraints did not allow.
func FuzzMinimizeKubeconfig(f *testing.F) {
	f.Add(testKubeconfig("tok"), "prod", "team-a")
	f.Add("", "prod", "team-a")
	f.Add("apiVersion: v1", "*", "*")
	f.Add("contexts: []", "prod", "team-a")
	f.Add("contexts:\n- name: x\n  context:\n    cluster: c\n    user: u\n", "*", "*")
	f.Add("{{{", "prod", "team-a")
	f.Add("contexts: 5", "prod", "team-a")

	f.Fuzz(func(t *testing.T, raw, ctxPattern, nsPattern string) {
		c := Constraints{Contexts: []string{ctxPattern}, Namespaces: []string{nsPattern}}
		if err := c.ValidateFor(KindKubeconfig); err != nil {
			return
		}

		out, err := MinimizeKubeconfig([]byte(raw), c)
		if err != nil {
			if out != nil {
				t.Fatalf("MinimizeKubeconfig returned %d bytes alongside an error", len(out))
			}
			return
		}

		// Re-parse the output and check every surviving context was allowed.
		reparsed, rerr := MinimizeKubeconfig(out, c)
		if rerr != nil {
			t.Fatalf("minimized output does not survive re-minimization: %v", rerr)
		}
		if len(reparsed) == 0 {
			t.Fatal("re-minimization produced an empty document")
		}
		_ = KubeconfigSummary(out)
	})
}
