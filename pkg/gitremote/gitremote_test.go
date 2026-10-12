package gitremote

import (
	"errors"
	"strings"
	"testing"
)

// TestParseGitHubNormalisesEverySpelling is the table the task asks for: every
// form git writes a github.com remote in reads as the same owner/name, and
// everything else is refused for the reason it fails.
func TestParseGitHubNormalisesEverySpelling(t *testing.T) {
	for _, tc := range []struct {
		remote string
		want   string // owner/name; empty when refused
		kind   error  // the refusal, when want is empty
	}{
		// https, with and without the .git suffix and trailing slashes.
		{"https://github.com/acme/api.git", "acme/api", nil},
		{"https://github.com/acme/api", "acme/api", nil},
		{"https://github.com/acme/api/", "acme/api", nil},
		{"https://github.com/acme/api.git/", "acme/api", nil},
		{"  https://github.com/acme/api.git\n", "acme/api", nil},
		{"https://GitHub.com/Acme/Api", "Acme/Api", nil},
		{"https://www.github.com/acme/api", "acme/api", nil},
		{"https://github.com:443/acme/api.git", "acme/api", nil},
		{"http://github.com/acme/api", "acme/api", nil},
		{"git://github.com/acme/api.git", "acme/api", nil},
		// ssh: the scp form GitHub prints, ssh:// URLs, and ssh over 443.
		{"git@github.com:acme/api.git", "acme/api", nil},
		{"git@github.com:acme/api", "acme/api", nil},
		{"github.com:acme/api.git", "acme/api", nil},
		{"git@github.com:/acme/api.git", "acme/api", nil},
		{"ssh://git@github.com/acme/api.git", "acme/api", nil},
		{"ssh://git@github.com:22/acme/api.git", "acme/api", nil},
		{"ssh://git@ssh.github.com:443/acme/api.git", "acme/api", nil},
		{"git+ssh://git@github.com/acme/api.git", "acme/api", nil},
		{"ssh://alice@github.com/acme/api", "acme/api", nil},
		// Names GitHub allows.
		{"git@github.com:a-b_c/web.site-v2_x.git", "a-b_c/web.site-v2_x", nil},

		// Not on GitHub.
		{"https://gitlab.com/acme/api.git", "", ErrNotGitHub},
		{"git@gitlab.com:acme/api.git", "", ErrNotGitHub},
		{"ssh://git@bitbucket.org/acme/api.git", "", ErrNotGitHub},
		{"https://github.example.com/acme/api.git", "", ErrNotGitHub},
		{"https://evil.example/github.com/acme/api", "", ErrNotGitHub},
		{"https://github.com.evil.example/acme/api", "", ErrNotGitHub},
		{"/srv/git/api.git", "", ErrNotGitHub},
		{"../api", "", ErrNotGitHub},
		{"./api", "", ErrNotGitHub},
		{"~/src/api", "", ErrNotGitHub},
		{"file:///srv/git/api.git", "", ErrNotGitHub},
		{"C:\\src\\api", "", ErrNotGitHub},
		{"api", "", ErrNotGitHub},

		// A credential, in each place one turns up.
		{"https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/acme/api.git", "", ErrCredential},
		{"https://x-access-token:ghs_secret@github.com/acme/api.git", "", ErrCredential},
		{"https://alice:hunter2@github.com/acme/api", "", ErrCredential},
		{"https://alice@github.com/acme/api", "", ErrCredential},
		{"http://user:pw@github.com/acme/api", "", ErrCredential},
		{"ssh://git:hunter2@github.com/acme/api.git", "", ErrCredential},
		{"git:hunter2@github.com:acme/api.git", "", ErrCredential},
		{"https://github.com/acme/api?access_token=ghp_x", "", ErrCredential},

		// Not a repository URL.
		{"", "", ErrMalformed},
		{"https://github.com/acme", "", ErrMalformed},
		{"https://github.com/acme/api/tree/main", "", ErrMalformed},
		{"https://github.com/", "", ErrMalformed},
		{"https://github.com/-acme/api", "", ErrMalformed},
		{"https://github.com/acme/..", "", ErrMalformed},
		{"https://github.com/acme/a%20b", "", ErrMalformed},
		{"https://github.com/acme/api#readme", "", ErrMalformed},
		{"https://github.com/acme/api?ref=main", "", ErrMalformed},
		{"ftp://github.com/acme/api", "", ErrMalformed},
		{"https://github.com/acme/api\nhttps://x", "", ErrMalformed},
	} {
		got, err := ParseGitHub(tc.remote)
		if tc.want != "" {
			if err != nil || got.FullName() != tc.want {
				t.Errorf("ParseGitHub(%q) = %q, %v; want %q", tc.remote, got.FullName(), err, tc.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("ParseGitHub(%q) = %q, want a refusal (%v)", tc.remote, got.FullName(), tc.kind)
			continue
		}
		if !errors.Is(err, tc.kind) {
			t.Errorf("ParseGitHub(%q) refused with %v, want %v", tc.remote, err, tc.kind)
		}
	}
}

// TestErrorsNeverQuoteTheCredential: a refusal names the remote so the
// developer can find it, and never with the token in it.
func TestErrorsNeverQuoteTheCredential(t *testing.T) {
	for _, remote := range []string{
		"https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/acme/api.git",
		"https://x-access-token:ghs_secret@github.com/acme/api.git",
		"ssh://git:hunter2@github.com/acme/api.git",
		"git:hunter2@github.com:acme/api.git",
		"https://github.com/acme/api?access_token=ghp_qwerty",
		"https://tok@gitlab.com/acme/api",
	} {
		_, err := ParseGitHub(remote)
		if err == nil {
			t.Fatalf("ParseGitHub(%q) accepted a credential", remote)
		}
		for _, secret := range []string{"ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghs_secret", "hunter2", "ghp_qwerty", "tok@"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("the refusal of %q quotes %q: %v", remote, secret, err)
			}
		}
		if !strings.Contains(err.Error(), "***") {
			t.Errorf("the refusal of %q does not show where the credential was: %v", remote, err)
		}
	}
	// A user name that is not a credential stays visible.
	if got := Redact("git@github.com:acme/api.git"); got != "git@github.com:acme/api.git" {
		t.Errorf("Redact(scp form) = %q", got)
	}
	if got := Redact("ssh://git@github.com/acme/api.git"); got != "ssh://git@github.com/acme/api.git" {
		t.Errorf("Redact(ssh) = %q", got)
	}
}

func TestParseRepoReadsTheCommandLineForms(t *testing.T) {
	for in, want := range map[string]string{
		"acme/api":                        "acme/api",
		"acme/api.git":                    "acme/api",
		" acme/api ":                      "acme/api",
		"github.com/acme/api":             "acme/api",
		"https://github.com/acme/api.git": "acme/api",
		"git@github.com:acme/api.git":     "acme/api",
	} {
		got, err := ParseRepo(in)
		if err != nil || got.FullName() != want {
			t.Errorf("ParseRepo(%q) = %q, %v; want %q", in, got.FullName(), err, want)
		}
	}
	for _, bad := range []string{"", "api", "acme/api/x", "acme/", "/api", "https://gitlab.com/acme/api", "-x/api"} {
		if got, err := ParseRepo(bad); err == nil {
			t.Errorf("ParseRepo(%q) = %q, want a refusal", bad, got.FullName())
		}
	}
}

func TestRepoRendersItsAddresses(t *testing.T) {
	r := Repo{Owner: "acme", Name: "api"}
	if r.FullName() != "acme/api" || r.String() != "acme/api" || r.URL() != "https://github.com/acme/api" {
		t.Errorf("Repo renders %q / %q / %q", r.FullName(), r.String(), r.URL())
	}
}
