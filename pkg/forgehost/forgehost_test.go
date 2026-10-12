package forgehost

import (
	"errors"
	"strings"
	"testing"
)

func TestCanonicalFoldsSpellingsOfOneHost(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"github.com", "github.com"},
		{"GitHub.COM", "github.com"},
		{"github.com.", "github.com"},
		{"github.com:443", "github.com"},
		{"github.com:0443", "github.com"},
		{"github.com:", "github.com"},
		{"git@github.com", "github.com"},
		{"https://github.com/acme/tool.git", "github.com"},
		{"https://x-access-token@GitHub.com.:443/acme/tool", "github.com"},
		{"ssh://git@github.com:22/acme/tool", "github.com"},
		// Full-width and ideographic spellings are the same name to a resolver.
		{"ｇｉｔｈｕｂ.com", "github.com"},
		{"github。com", "github.com"},
		{"ghes.example.com:8443", "ghes.example.com:8443"},
		{"https://ghes.example.com:8443/api/v3", "ghes.example.com:8443"},
		{"127.0.0.1:41234", "127.0.0.1:41234"},
		{"[::1]:8443", "[::1]:8443"},
		{"[0:0::1]", "[::1]"},
		{"git_server.corp", "git_server.corp"},
	} {
		got, err := Canonical(tc.in)
		if err != nil {
			t.Errorf("Canonical(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Canonical(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDifferentHostsStayDifferent is the half of the rule that protects
// anything: every one of these reaches a server other than github.com.
func TestDifferentHostsStayDifferent(t *testing.T) {
	for _, other := range []string{
		"attacker.example",
		"github.com:8443",
		"github.com.attacker.example",
		"attacker-github.com",
		"www.github.com",
		"api.github.com",
		"gіthub.com", // Cyrillic і
		"xn--gthub-n2e.com",
		"https://github.com@attacker.example/acme/tool",
		"https://attacker.example/github.com/acme/tool",
		"140.82.112.3",
		"github.co",
		"github.com..",
	} {
		if Equal(other, GitHub) {
			t.Errorf("Equal(%q, github.com) = true; it names another host", other)
		}
		if Equal(GitHub, other) {
			t.Errorf("Equal(github.com, %q) = true; it names another host", other)
		}
	}
}

func TestCanonicalRefusesWhatNamesNoHost(t *testing.T) {
	for _, in := range []string{
		"", " ", "https://", "https:///acme/tool", "[::1", "[::1]x", "::1",
		"github.com:99999", "github.com:-1", "github.com:44 3", "git hub.com",
		"github..com", "https://git\\hub.com/x", "https://%67ithub.com/x",
		"file:///etc/passwd", "[fe80::1%25eth0]", "[::ffff:1.2.3.4]",
		strings.Repeat("a", 64) + ".com",
	} {
		if got, err := Canonical(in); err == nil {
			t.Errorf("Canonical(%q) = %q, want an error", in, got)
		} else if !errors.Is(err, ErrInvalid) {
			t.Errorf("Canonical(%q) error %v does not wrap ErrInvalid", in, err)
		}
	}
}

func TestEqualIsNeverTrueForAnUnusableReference(t *testing.T) {
	if Equal("", "") || Equal("::1", "::1") || Equal("github..com", "github..com") {
		t.Fatal("two references naming no host compared equal")
	}
}

func TestWebHostForAPI(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "github.com"},
		{"https://api.github.com", "github.com"},
		{"https://API.GitHub.com/", "github.com"},
		{"https://ghes.example.com/api/v3", "ghes.example.com"},
		{"https://ghes.example.com/api/v3/", "ghes.example.com"},
		{"https://GHES.example.com:8443/API/V3", "ghes.example.com:8443"},
		{"https://api.acme.ghe.com", "acme.ghe.com"},
		{"https://127.0.0.1:41234/api/v3", "127.0.0.1:41234"},
		// Not where GitHub Enterprise Server serves its API: a stand-in for
		// the public one, whose tokens are github.com tokens.
		{"https://127.0.0.1:41234", "github.com"},
		{"https://github-proxy.corp/github", "github.com"},
	} {
		got, err := WebHostForAPI(tc.in)
		if err != nil {
			t.Errorf("WebHostForAPI(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("WebHostForAPI(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"http://ghes.example.com/api/v3", "https://u:p@ghes/api/v3", "https:///api/v3", "not a url"} {
		if got, err := WebHostForAPI(bad); err == nil {
			t.Errorf("WebHostForAPI(%q) = %q, want an error", bad, got)
		}
	}
}

func TestAPIBase(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"github.com", GitHubAPI},
		{"GitHub.com.", GitHubAPI},
		{"ghes.example.com", "https://ghes.example.com/api/v3"},
		{"ghes.example.com:8443", "https://ghes.example.com:8443/api/v3"},
	} {
		if got := APIBase(tc.in); got != tc.want {
			t.Errorf("APIBase(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// The two directions agree: the web host of a host's API base is the host.
	for _, h := range []string{"github.com", "ghes.example.com", "ghes.example.com:8443", "127.0.0.1:41234"} {
		back, err := WebHostForAPI(APIBase(h))
		if err != nil || back != h {
			t.Errorf("WebHostForAPI(APIBase(%q)) = %q, %v", h, back, err)
		}
	}
}

func TestCheckNamesBothHosts(t *testing.T) {
	err := Check("https://Attacker.example./acme/tool", "github.com")
	var m *Mismatch
	if !errors.As(err, &m) {
		t.Fatalf("Check = %v, want a *Mismatch", err)
	}
	if m.Origin != "attacker.example" || m.Grant != "github.com" {
		t.Fatalf("mismatch = %+v", m)
	}
	if !strings.Contains(err.Error(), "attacker.example") || !strings.Contains(err.Error(), "github.com") {
		t.Fatalf("message %q does not name both hosts", err)
	}
	if err := Check("https://GITHUB.com/acme/tool", "github.com"); err != nil {
		t.Fatalf("the same host was refused: %v", err)
	}
	if err := Check("::1", "github.com"); !errors.As(err, &m) {
		t.Fatalf("an unusable origin was not a mismatch: %v", err)
	}
	if err := Check("github.com", ""); err == nil {
		t.Fatal("a credential naming no host was checked as matching")
	}
}

// FuzzCanonical holds the properties every caller depends on: the canonical
// form is stable, Equal agrees with it, and a host equal to github.com is
// github.com — never a suffix, prefix or look-alike of it.
func FuzzCanonical(f *testing.F) {
	for _, s := range []string{
		"github.com", "GitHub.com.", "github.com:443", "https://u@github.com/a/b",
		"gіthub.com", "ｇｉｔｈｕｂ.com", "github.com.attacker.example", "[::1]:22",
		"ghes.example.com:8443", "xn--gthub-n2e.com", "a..b", "github.com@evil",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		c, err := Canonical(raw)
		if err != nil {
			if Equal(raw, raw) {
				t.Fatalf("%q does not canonicalise but equals itself", raw)
			}
			return
		}
		again, err := Canonical(c)
		if err != nil || again != c {
			t.Fatalf("Canonical is not stable: %q → %q → %q (%v)", raw, c, again, err)
		}
		if !Equal(raw, c) || !Equal(c, raw) {
			t.Fatalf("%q is not Equal to its canonical form %q", raw, c)
		}
		if Equal(raw, GitHub) != (c == GitHub) {
			t.Fatalf("Equal(%q, github.com) disagrees with its canonical form %q", raw, c)
		}
		if strings.ContainsAny(c, "@/?# \t\r\n") || c != strings.ToLower(c) {
			t.Fatalf("canonical form %q of %q carries something a host does not", c, raw)
		}
	})
}
