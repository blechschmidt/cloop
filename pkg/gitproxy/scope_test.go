package gitproxy

import (
	"strings"
	"testing"
)

// TestAllowsRepoScoped pins the matching semantics a PAT allowlist relies on.
//
// The cases that matter are the ones where a looser matcher would be wrong in
// the widening direction: "*" crossing a slash, a case-mismatched owner, and a
// ".git" suffix or leading slash making a path miss a pattern it should hit.
func TestAllowsRepoScoped(t *testing.T) {
	cases := []struct {
		name     string
		patterns []string
		repo     string
		want     bool
	}{
		{"exact", []string{"acme/tool"}, "acme/tool", true},
		{"exact miss", []string{"acme/tool"}, "acme/other", false},
		{"owner wildcard", []string{"acme/*"}, "acme/tool", true},
		{"owner wildcard excludes other owner", []string{"acme/*"}, "evil/tool", false},
		{"case insensitive", []string{"acme/*"}, "ACME/Tool", true},
		{"pattern case insensitive", []string{"ACME/Tool"}, "acme/tool", true},
		{"dot git suffix tolerated", []string{"acme/tool"}, "acme/tool.git", true},
		{"leading slash tolerated", []string{"acme/tool"}, "/acme/tool", true},
		// The one that would silently widen every allowlist if path.Match were
		// swapped for a shell-style glob: "*" must not cross a separator.
		{"star does not cross a slash", []string{"acme/*"}, "acme/group/tool", false},
		{"three components refused outright", []string{"*/*"}, "a/b/c", false},
		{"one component refused outright", []string{"*/*"}, "acme", false},
		{"global wildcard", []string{"*"}, "anyone/anything", true},
		{"empty repo", []string{"acme/*"}, "", false},
		{"multiple patterns, second hits", []string{"acme/*", "other/tool"}, "other/tool", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pats, err := normalizeRepoPatterns(tc.patterns)
			if err != nil {
				t.Fatalf("normalizeRepoPatterns(%v): %v", tc.patterns, err)
			}
			s := &Session{RepoPatterns: pats}
			if got := s.AllowsRepo(tc.repo); got != tc.want {
				t.Errorf("AllowsRepo(%q) with %v = %v, want %v", tc.repo, pats, got, tc.want)
			}
		})
	}
}

// TestAllowsRepoRejectsPathsThatChangeMeaningWhenReparsed is the regression
// test for a real bypass this package shipped with.
//
// AllowsRepo matches a string, and that string is then concatenated into a URL
// that net/http parses again on the way to the forge. Any character that
// survives matching and changes meaning during the second parse makes the
// approved path and the forwarded path two different things.
//
// "%252F" was the worst of them: it reaches the proxy as the literal text
// "%2F", which contains no separator, so it passed the one-slash check and
// matched "acme/*" — and a forge then decoded it back into "/", serving a
// repository the allowlist denies with the PAT attached. A full ref
// advertisement and upload-pack for an arbitrary repository, through a session
// scoped to somebody else's org.
//
// The cases below are the ones that were demonstrated end to end, not
// hypotheticals.
func TestAllowsRepoRejectsPathsThatChangeMeaningWhenReparsed(t *testing.T) {
	pats, err := normalizeRepoPatterns([]string{"acme/*"})
	if err != nil {
		t.Fatalf("normalizeRepoPatterns: %v", err)
	}
	s := &Session{RepoPatterns: pats, Upstream: "https://github.com"}

	for _, bad := range []string{
		// Double-encoded separator: decodes to "/" at the forge.
		"acme/..%252F..%252Fsomebody-else%252Fprivate",
		"acme/..%2F..%2Fsomebody-else%2Fprivate",
		// Truncation: "?" and "#" split the path at the second parse, so the
		// forge sees a prefix of what was matched.
		"acme/secret%3F-public",
		"acme/secret%23x",
		// A NUL on the wire.
		"acme/x%2500",
		// The same divergence through a suffix rather than an encoding.
		// ".git" is stripped by splitGitPath, again here, and a third time
		// where the upstream URL is assembled — so a name that survives
		// normalisation still ending in ".git" is approved as one repository
		// and fetched as another. With an allowlist of "acme/tool.*" this
		// reached acme/tool, which that allowlist denies.
		// Note "acme/tool.git" is NOT here: that is the ordinary form a git
		// client sends, and it normalises to acme/tool. The attack needs a
		// name that still ends in ".git" *after* normalising, which is what
		// the doubled suffix produces.
		"acme/tool.git.git",
		"acme/tool.git.git.git",
		// Traversal in the clear, and an embedded authority.
		"acme/../../somebody-else/private",
		"acme/..",
		"acme/a@evil.example",
		"acme/a:b",
		"acme/a b",
	} {
		if s.AllowsRepo(bad) {
			u, _ := s.upstreamFor(bad)
			t.Errorf("AllowsRepo(%q) = true; it would be forwarded as %q", bad, u)
		}
		// And the URL builder refuses independently, so the two cannot drift.
		if u, err := s.upstreamFor(bad); err == nil {
			t.Errorf("upstreamFor(%q) returned %q, want an error", bad, u)
		}
	}

	// The ordinary names a forge actually has must still work, including the
	// punctuation that is legal in a repository name.
	for _, good := range []string{
		"acme/tool", "acme/my-tool", "acme/my_tool", "acme/tool.js", "acme/v2.0",
	} {
		if !s.AllowsRepo(good) {
			t.Errorf("AllowsRepo(%q) = false; a legitimate repository name was refused", good)
		}
	}
}

// TestNormalizeIsIdempotentForEverythingAdmitted states the invariant that the
// two bypasses above were both violations of, rather than re-listing inputs.
//
// The check and the forward each normalise, at different points in the request.
// If normalising twice can differ from normalising once, then the path approved
// and the path fetched can differ — which is the entire bug class, whether the
// extra transformation comes from percent-decoding or from stripping a suffix.
// A future normalisation step that is not idempotent fails here rather than
// shipping as a third bypass.
func TestNormalizeIsIdempotentForEverythingAdmitted(t *testing.T) {
	pats, err := normalizeRepoPatterns([]string{"acme/tool.*", "acme/*.*", "acme/*", "*/*"})
	if err != nil {
		t.Fatalf("normalizeRepoPatterns: %v", err)
	}
	s := &Session{RepoPatterns: pats, Upstream: "https://github.com"}

	var admitted int
	for _, in := range []string{
		"acme/tool", "acme/tool.git", "acme/tool.git.git", "acme/tool.git.git.git",
		"acme/tool.GIT", "acme/tool.GIT.git", "acme/x.js", "acme/v2.0",
		"acme/.dotfiles", "acme/a.b.c", "ACME/Tool", "/acme/tool/",
	} {
		if !s.AllowsRepo(in) {
			continue
		}
		admitted++
		p := NormalizeRepoPath(in)
		if again := NormalizeRepoPath(p); again != p {
			t.Errorf("admitted %q normalises to %q and then to %q; "+
				"the path checked and the path fetched would differ", in, p, again)
		}
	}
	if admitted == 0 {
		t.Fatal("nothing was admitted, so the invariant was never exercised")
	}
}

// TestAllowsRepoPinnedIsUnchanged guards the existing mode against the
// refactor that introduced the scoped one: a session with no allowlist must
// still admit exactly its one repository and nothing else.
func TestAllowsRepoPinnedIsUnchanged(t *testing.T) {
	s := &Session{RepoPath: "acme/tool"}
	if !s.AllowsRepo("acme/tool") || !s.AllowsRepo("ACME/TOOL") || !s.AllowsRepo("acme/tool.git") {
		t.Error("a pinned session refused its own repository")
	}
	if s.AllowsRepo("acme/other") || s.AllowsRepo("evil/tool") {
		t.Error("a pinned session admitted a repository it was not minted for")
	}
	if s.Scoped() {
		t.Error("a session with no patterns reports itself as scoped")
	}
	// A session with neither is the zero value, and must admit nothing rather
	// than everything.
	if (&Session{}).AllowsRepo("acme/tool") {
		t.Error("a session with no repository and no allowlist admitted a repository")
	}
}

// TestUpstreamForCannotBeSteered is the property that keeps a scoped session
// from becoming a credential-forwarding oracle.
//
// The repository path on a scoped session comes from the request, so the check
// that matters is that nothing in that path can change the *host* the PAT is
// presented to, and that a repository outside the allowlist produces an error
// rather than a URL.
func TestUpstreamForCannotBeSteered(t *testing.T) {
	pats, err := normalizeRepoPatterns([]string{"acme/*"})
	if err != nil {
		t.Fatalf("normalizeRepoPatterns: %v", err)
	}
	s := &Session{RepoPatterns: pats, Upstream: "https://github.com"}

	got, err := s.upstreamFor("acme/tool")
	if err != nil {
		t.Fatalf("upstreamFor on an allowed repository: %v", err)
	}
	if got != "https://github.com/acme/tool" {
		t.Errorf("upstreamFor = %q, want https://github.com/acme/tool", got)
	}

	// Anything the allowlist does not admit must not yield a URL at all —
	// including inputs shaped to look like a different host.
	for _, bad := range []string{
		"evil/tool",
		"acme/group/tool",
		"",
		"..",
		"evil.com/x",
	} {
		if u, err := s.upstreamFor(bad); err == nil {
			t.Errorf("upstreamFor(%q) returned %q, want an error", bad, u)
		}
	}
}

// TestUpstreamForPinnedIgnoresTheRequest is the same property for the original
// mode, where the request's path must not influence the URL at all.
func TestUpstreamForPinnedIgnoresTheRequest(t *testing.T) {
	s := &Session{RepoPath: "acme/tool", Upstream: "https://github.com/acme/tool.git"}
	for _, req := range []string{"acme/tool", "evil/other", ""} {
		got, err := s.upstreamFor(req)
		if err != nil {
			t.Fatalf("upstreamFor(%q): %v", req, err)
		}
		if got != "https://github.com/acme/tool" {
			t.Errorf("upstreamFor(%q) = %q, want the session's own upstream", req, got)
		}
	}
}

// TestMintScopedRejectsABadUpstream checks the two Upstream shapes cannot be
// confused. A scoped session given a repository URL would prefix every request
// path with that repository.
func TestMintScopedRejectsABadUpstream(t *testing.T) {
	reg, err := NewRegistry("https://hub.internal:8443")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	pol := WriteBackPolicy()
	pol.AllowFetch = true

	for _, bad := range []string{
		"https://github.com/acme/tool", // a repository, not a base
		"http://github.com",            // cleartext
		"https://x:y@github.com",       // embedded credentials
		"",
	} {
		if _, err := reg.Mint(MintRequest{
			Upstream: bad, RepoPatterns: []string{"acme/*"}, Policy: pol,
		}); err == nil {
			t.Errorf("Mint accepted %q as a scoped session's upstream base", bad)
		}
	}

	// And the allowlist itself is validated.
	for _, bad := range [][]string{
		{"acme"},           // not owner/name
		{"a/b/c"},          // too deep
		{"acme/["},         // malformed glob
		{"   "},            // empty after trimming
		make([]string, 65), // over MaxRepoPatterns after the length check
	} {
		if _, err := reg.Mint(MintRequest{
			Upstream: "https://github.com", RepoPatterns: bad, Policy: pol,
		}); err == nil {
			t.Errorf("Mint accepted %v as an allowlist", bad)
		}
	}
}

// TestMintScopedSucceeds covers the shape of what a caller gets back, since the
// sandbox-facing half differs from a pinned session: there is no single
// repository, so RepoURL is the base the sandbox rewrites GitHub to.
func TestMintScopedSucceeds(t *testing.T) {
	reg, err := NewRegistry("https://hub.internal:8443")
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	pol := WriteBackPolicy()
	pol.AllowFetch = true

	m, err := reg.Mint(MintRequest{
		Upstream:     "https://github.com/", // trailing slash tolerated
		RepoPatterns: []string{"acme/*", "acme/*", "Other/Tool"},
		Policy:       pol,
		Credential:   Credential{Username: "x-access-token", Password: "pat-value"},
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !m.Session.Scoped() {
		t.Fatal("a session minted with patterns does not report itself scoped")
	}
	if m.Session.RepoPath != "" {
		t.Errorf("scoped session RepoPath = %q, want empty", m.Session.RepoPath)
	}
	if m.RepoURL != "https://hub.internal:8443" {
		t.Errorf("RepoURL = %q, want the bare proxy base", m.RepoURL)
	}
	// Deduplicated and lowercased, so an allowlist cannot grow by repetition.
	if len(m.Session.RepoPatterns) != 2 {
		t.Errorf("RepoPatterns = %v, want the duplicate collapsed", m.Session.RepoPatterns)
	}
	if strings.Contains(m.RepoURL, "pat-value") || strings.Contains(m.Token, "pat-value") {
		t.Error("the upstream credential leaked into the sandbox-facing session")
	}
	if !m.Session.AllowsRepo("other/tool") {
		t.Error("a pattern given in mixed case did not match a lowercase path")
	}
}
