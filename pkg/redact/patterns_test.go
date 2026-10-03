package redact_test

import (
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/redact/redacttest"
)

// TestCorpusIsWellFormed keeps the corpus honest before anything is measured
// against it. A positive whose secret is not in its text would pass every
// scanner vacuously, and a detector with no fixture is a detector nobody has
// checked.
func TestCorpusIsWellFormed(t *testing.T) {
	known := map[string]bool{}
	for _, d := range redact.Detectors() {
		known[d.Name] = true
	}
	names := map[string]bool{}
	covered := map[string]bool{}
	for _, p := range redacttest.Positives() {
		if names[p.Name] {
			t.Errorf("fixture name %q is used twice", p.Name)
		}
		names[p.Name] = true
		if !known[p.Detector] {
			t.Errorf("%s names detector %q, which the registry does not have", p.Name, p.Detector)
		}
		covered[p.Detector] = true
		if len(p.Secrets) == 0 || len(p.Keep) == 0 {
			t.Errorf("%s needs at least one secret and one piece of context to keep", p.Name)
		}
		for _, s := range p.Secrets {
			if len(s) < redact.MinLen || !strings.Contains(p.Text, s) {
				t.Errorf("%s: secret %q is too short or absent from its own text", p.Name, abbreviate(s))
			}
		}
		for _, k := range p.Keep {
			if !strings.Contains(p.Text, k) {
				t.Errorf("%s: context %q is absent from its own text", p.Name, k)
			}
		}
	}
	for name := range known {
		if !covered[name] {
			t.Errorf("detector %q has no fixture in pkg/redact/redacttest; add one before relying on it", name)
		}
	}
	for _, n := range redacttest.Negatives() {
		if names[n.Name] {
			t.Errorf("fixture name %q is used twice", n.Name)
		}
		names[n.Name] = true
	}
}

// TestRegistryFindsEveryPositive: the detector a fixture names is among the
// ones Find reports, and the match covers the secret rather than a fragment.
func TestRegistryFindsEveryPositive(t *testing.T) {
	for _, p := range redacttest.Positives() {
		t.Run(p.Name, func(t *testing.T) {
			var hit bool
			for _, m := range redact.Find(p.Text) {
				if m.Detector == p.Detector {
					hit = true
				}
			}
			if !hit {
				t.Errorf("detector %s did not report %q", p.Detector, abbreviate(p.Text))
			}
		})
	}
}

func TestScrubRemovesEveryPositive(t *testing.T) {
	for _, p := range redacttest.Positives() {
		t.Run(p.Name, func(t *testing.T) {
			got := redact.Scrub(p.Text)
			for _, s := range p.Secrets {
				if strings.Contains(got, s) {
					t.Errorf("secret %q survived:\n%s", abbreviate(s), got)
				}
			}
			if !strings.Contains(got, redact.Marker) {
				t.Errorf("no %s marker in %q", redact.Marker, got)
			}
			for _, k := range p.Keep {
				if !strings.Contains(got, k) {
					t.Errorf("context %q was destroyed along with the credential:\n%s", k, got)
				}
			}
			if again := redact.Scrub(got); again != got {
				t.Errorf("a second pass changed the output:\n first: %s\nsecond: %s", got, again)
			}
		})
	}
}

func TestNegativesAreLeftAlone(t *testing.T) {
	for _, n := range redacttest.Negatives() {
		t.Run(n.Name, func(t *testing.T) {
			for _, m := range redact.Find(n.Text) {
				t.Errorf("%s matched %q", m.Detector, n.Text[m.Start:m.End])
			}
			if got := redact.Scrub(n.Text); got != n.Text {
				t.Errorf("ordinary text was rewritten:\n  in: %s\n out: %s", n.Text, got)
			}
		})
	}
}

// TestGitHubLongFormTokensOfEveryShape varies what a fixed corpus cannot: the
// prefix, the final character, and the punctuation around the token. Each
// must be matched exactly — not one character short, which would leak it, and
// not one long, which would eat the sentence's full stop.
func TestGitHubLongFormTokensOfEveryShape(t *testing.T) {
	prefixes := []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}
	ends := []byte{0, '-', '_'}
	frames := []struct{ before, after string }{
		{" ", " "}, {"'", "'"}, {`"`, `",`}, {"x-access-token:", "@github.com/acme/w.git"},
		{"token=", "&next=1"}, {"\n", ".\n"}, {"(", ")"},
	}
	for i := 0; i < 600; i++ {
		r := rand.New(rand.NewPCG(uint64(i), 7))
		tok := redacttest.GitHubLongFormToken(r, prefixes[i%len(prefixes)], ends[i%len(ends)])
		if strings.HasPrefix(tok, "ghs_") && len(tok) != 390 {
			t.Fatalf("generator drifted: a ghs_ long-form token is 390 characters, got %d", len(tok))
		}
		f := frames[i%len(frames)]
		text := "remote: " + f.before + tok + f.after
		var exact bool
		for _, m := range redact.Find(text) {
			if m.Detector == "github-token-long" && text[m.Start:m.End] == tok {
				exact = true
			}
		}
		if !exact {
			t.Fatalf("long-form token (iteration %d, %q…%q) was not matched exactly in %q",
				i, f.before, f.after, abbreviate(text))
		}
	}
}

// TestALongFormTokenCutByALineBreakLosesItsLead: a token broken across lines
// leaves its lead on the first, too short for the long form's 31 characters
// and cut at an underscore before the classic form's 16. The lead — the
// digits and the underscore after them — is distinctive on its own, and
// without it what is left on the next line is no credential.
func TestALongFormTokenCutByALineBreakLosesItsLead(t *testing.T) {
	r := rand.New(rand.NewPCG(9, 10))
	tok := redacttest.GitHubLongFormToken(r, "ghs_", 0)
	for _, cut := range []int{12, 16, 20, 34} {
		in := "token " + tok[:cut] + "\n" + tok[cut:] + "\nretrying"
		if got := redact.Scrub(in); strings.Contains(got, tok[:cut]) {
			t.Errorf("cut at %d: the token's lead %q survived:\n%s", cut, tok[:cut], abbreviate(got))
		}
	}
}

// TestScrubTimeIsLinearInRejectedCandidates: a candidate that fails its
// detector's checks used to be rescanned from one byte in, so that a
// credential starting inside it would still be found. For a shape whose body
// can hold its own prefix, every rejected candidate was then a rescan to the
// same far end: 64 KiB of "ghs_a." took 15 s, and a 2 MiB telemetry field
// would have taken hours. Each input is a quarter of a mebibyte of candidates
// the registry rejects; at the old cost the slowest takes minutes.
func TestScrubTimeIsLinearInRejectedCandidates(t *testing.T) {
	const size = 256 << 10
	for _, unit := range []string{
		"ghs_a.",                     // long form, one candidate every six bytes
		"ghs_aaaaaaaaaa",             // too short for the classic form, lowercase for the long
		"github_pat_aaaaa",           // fine-grained, lowercase
		"x-sk-proj-aaaaaaaaaaaaaaaa", // OpenAI, every candidate glued to a word
		"xtoken=aaaaaaaaaaaa ",
		"authorization: redactedXX ",
		"a://u:$x@h ",
		"bearer abcdefghij ",
		"xclet1.aaaa.aaaaaaaa",
	} {
		in := strings.Repeat(unit, size/len(unit))
		done := make(chan struct{})
		go func() {
			redact.Scrub(in)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatalf("Scrub of %d KiB of %q ran past 30s: rejected candidates are being rescanned", size>>10, unit)
		}
	}
}

// TestScrubFuncHandsTheKindToTheReplacement is the provider-call audit's
// style: keep the public lead, drop the value.
func TestScrubFuncHandsTheKindToTheReplacement(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	tok := redacttest.GitHubLongFormToken(r, "ghs_", 0)
	in := "clone failed with " + tok + "; Authorization: Bearer abcdef0123456789"
	got := redact.ScrubFunc(in, func(m redact.Match) string { return m.Kind + "[REDACTED]" })
	want := "clone failed with ghs_[REDACTED]; Authorization: Bearer [REDACTED]"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// TestOverlappingMatchesAreReplacedOnce: a token inside a URL inside an error
// is three findings and one replacement. Two adjacent markers, or a marker
// followed by the tail of the token, would both be wrong.
func TestOverlappingMatchesAreReplacedOnce(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	tok := redacttest.GitHubLongFormToken(r, "ghs_", 0)
	in := "fatal: unable to access 'https://x-access-token:" + tok + "@github.com/acme/widgets.git/'"

	detectors := map[string]bool{}
	for _, m := range redact.Find(in) {
		detectors[m.Detector] = true
	}
	for _, want := range []string{"github-token-long", "url-userinfo"} {
		if !detectors[want] {
			t.Errorf("Find did not report %s; got %v", want, detectors)
		}
	}
	got := redact.Scrub(in)
	if want := "fatal: unable to access 'https://[redacted]@github.com/acme/widgets.git/'"; got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// TestShapesThatEndAWordAreNotCredentials pins the boundary rules, each of
// which exists because the shape occurs inside ordinary words.
func TestShapesThatEndAWordAreNotCredentials(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	hex32 := pickHex(r, 32)
	bs := `\`
	key := "AKIA" + strings.ToUpper(pickHex(r, 16))
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"sk- ending a task id", "worktree task-" + hex32 + " removed", false},
		{"sk- standing alone", "key sk-" + hex32 + " revoked", true},
		{"access key id in a longer run", "X" + key + "Z", false},
		{"access key id with a digit after", key + "7", false},
		{"access key id standing alone", "id=" + key + ";", true},
		{"enrollment token glued to a word", "xclet1.abcdefgh.ijklmnopqrstuv.0123", false},
		// A quoted string's escaped newline is whitespace, not the letter n.
		{"sk- after an escaped newline", `{"log":"retrying\nsk-` + hex32 + `"}`, true},
		{"token field after an escaped newline", `{"cfg":"kind: Config\ntoken: Ab3dEf6hIj9lMn0p"}`, true},
		{"enrollment token after an escaped tab", `"--token\tclet1.abcdefgh.ijklmnopqrstuv.0123"`, true},
		{"sk- after a letter that is not an escape", `{"log":"tasksk-` + hex32 + `"}`, false},
		// A percent-encoded URL is read as what it encodes: %3D is "=", and an
		// escaped letter still joins a word.
		{"sk- after a percent-encoded equals sign", "next=%2Fv1%3Fkey%3Dsk-" + hex32 + "%26n%3D1", true},
		{"access key id after a percent-encoded equals sign", "X-Amz-Credential%3D" + key + "%252F20261003", true},
		{"enrollment token after a percent-encoded space", "--token%20clet1.abcdefgh.ijklmnopqrstuv.0123", true},
		{"sk- after a percent-encoded letter", "next=%41sk-" + hex32, false},
		{"sk- after a JSON-escaped angle bracket", `"` + bs + "u003csk-" + hex32 + `"`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := len(redact.Find(tc.text)) > 0; got != tc.want {
				t.Errorf("Find(%q) found=%v, want %v", tc.text, got, tc.want)
			}
		})
	}
}

// TestAValueRunningIntoABracketIsStillACredential: a field detector leaves a
// value alone when it runs into a redaction marker, because that value is the
// public lead a scanner kept — "token: sk-ant-oat01-[REDACTED]". Any other
// bracket after a value is punctuation, and the value is still a credential.
func TestAValueRunningIntoABracketIsStillACredential(t *testing.T) {
	const v = "Ab3dEf6hIj9lMn0pQr5tUv8x"
	for _, in := range []string{
		"Authorization: Bearer " + v + "[truncated]",
		"Authorization: Bearer " + v + "\x1b[0m",
		// What telemetry stores of the line above: control bytes are dropped.
		"Authorization: Bearer " + v + "[0m",
		"upstream answered 401 to bearer " + v + "[0]",
		`{"access_token":"` + v + `[…]"}`,
	} {
		if got := redact.Scrub(in); strings.Contains(got, v) {
			t.Errorf("Scrub(%q) = %q — the credential survived", in, got)
		}
	}
	for _, in := range []string{
		"token: sk-ant-oat01-[REDACTED]",
		`{"refresh_token":"sk-ant-ort01-[REDACTED]"}`,
		"Authorization: Bearer cloop_pat_[redacted]",
	} {
		if got := redact.Scrub(in); got != in {
			t.Errorf("Scrub(%q) = %q — a scanner's own output must be left as it is", in, got)
		}
	}
}

// TestTokenFieldForms: the field forms programs print, each of which the
// first registry let through — a key behind a prefix, a header with dashes in
// it, npm's config, an OAuth 1 parameter.
func TestTokenFieldForms(t *testing.T) {
	const v = "Zx81kQm2Lp9vTn4bWc7dRf3hYj6s"
	for _, in := range []string{
		"GITHUB_TOKEN=" + v,
		"ANTHROPIC_AUTH_TOKEN=" + v,
		"X-Auth-Token: " + v,
		"PRIVATE-TOKEN: " + v,
		"//registry.npmjs.org/:_authToken=" + v,
		"oauth_token=" + v + "&oauth_verifier=1",
		`"{\"access_token\":\"` + v + `\"}"`,
		"map[Token:[" + v + "]]",
		"client_secret=[" + v + "]",
	} {
		var hit bool
		for _, m := range redact.Find(in) {
			hit = hit || m.Detector == "token-field"
		}
		if !hit || strings.Contains(redact.Scrub(in), v) {
			t.Errorf("token-field missed the value in %q", in)
		}
	}
}

// TestAValueIsRemovedWhole: a value holding a byte the expression does not
// list is removed to its end, not cut at that byte with the rest left in
// place; and the end is a delimiter, so what follows the value survives.
func TestAValueIsRemovedWhole(t *testing.T) {
	for _, tc := range []struct{ in, gone, kept string }{
		{"Bearer AAAAB3NzaC1yc2EAAAADAQAB%2BuSeid%2BULvseaQ7%2FtTz9 rejected", "uSeid", " rejected"},
		{"bearer 1234567890123456|Zk9dE3xQ7mWp2LbN on /api/user", "Zk9dE3xQ7mWp2LbN", " on /api/user"},
		{"client_secret: Ab3dEf6hIj!Kl9mN0pQ_rest\nnext: 1", "Kl9mN0pQ_rest", "\nnext: 1"},
		{"https://x-access-token:Ab3dEf6hIj9lMn0pQr5t@github.com/acme/w.git", "Ab3dEf6hIj9lMn0pQr5t", "@github.com/acme/w.git"},
		{"GET /cb?next=%2Fcb%3Faccess_token%3DAb3dEf6hIj9lMn0p%26state%3D1", "Ab3dEf6hIj9lMn0p", "%26state%3D1"},
	} {
		got := redact.Scrub(tc.in)
		if strings.Contains(got, tc.gone) || !strings.HasSuffix(got, tc.kept) {
			t.Errorf("Scrub(%q) = %q; want %q gone and %q kept", tc.in, got, tc.gone, tc.kept)
		}
	}
}

// TestAURLPasswordIsAPasswordUnlessItIsATemplate: only the forms a template
// or a format string leaves stand for a password; one led by "%", "$" or "*",
// or shaped like an environment variable's name, is what the URL sends.
func TestAURLPasswordIsAPasswordUnlessItIsATemplate(t *testing.T) {
	for _, pass := range []string{"%21Xk9mPq2Lw7Rt", "$ecretP4ssw0rd", "*9xKpL2mQ7rT", "PROD_DB_2024_PW"} {
		in := "postgres://cloop:" + pass + "@db.internal/cloop"
		if got := redact.Scrub(in); strings.Contains(got, pass) {
			t.Errorf("Scrub(%q) = %q — the password survived", in, got)
		}
	}
	for _, pass := range []string{"${DB_PASSWORD}", "$DB_PASSWORD", "$password", "%s", "****"} {
		in := "postgres://cloop:" + pass + "@db.internal/cloop"
		if got := redact.Scrub(in); got != in {
			t.Errorf("Scrub(%q) = %q — a template is not a password", in, got)
		}
	}
}

// TestOneScrubRemovesACredentialGluedToAnother: a key that starts on a PEM
// block's last dash follows a word byte, so its boundary check fails against
// bytes the same pass replaces. One call still removes both: a second pass
// sees the key follow the marker.
func TestOneScrubRemovesACredentialGluedToAnother(t *testing.T) {
	key := "sk-proj-" + strings.Repeat("Ab3dEf6h", 4)
	in := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n" +
		"-----END RSA PRIVATE KEY-----" + key + " (deploy)"
	got := redact.Scrub(in)
	if strings.Contains(got, key) || !strings.HasSuffix(got, " (deploy)") {
		t.Errorf("Scrub kept the glued key or lost what followed it: %q", got)
	}
	if again := redact.Scrub(got); again != got {
		t.Errorf("a second Scrub changed the output:\n first: %q\nsecond: %q", got, again)
	}
}

// TestDetectorsAreDescribed: the reference page and cloop audit's report are
// rendered from these fields, so an empty one is a gap a reader sees.
func TestDetectorsAreDescribed(t *testing.T) {
	for _, d := range redact.Detectors() {
		if d.Name == "" || d.Label == "" || d.Recognises == "" {
			t.Errorf("detector %+v is missing a name, label or description", d.Name)
		}
		if strings.ToLower(d.Name) != d.Name || strings.ContainsAny(d.Name, " _") {
			t.Errorf("detector name %q is not kebab-case", d.Name)
		}
	}
}

// FuzzScrubNeverEmitsAPlantedCredential plants a corpus fixture — the
// credential and the context that identifies it — in arbitrary text. Whatever
// surrounds it, none of its secrets may come out the other side, and the scan
// must neither panic nor run away.
//
// The whole fixture is planted, not the bare value: an OAuth access token is
// a credential because of the "access_token" in front of it, and the same
// forty characters on their own are indistinguishable from a commit message.
func FuzzScrubNeverEmitsAPlantedCredential(f *testing.F) {
	positives := redacttest.Positives()
	for _, s := range []string{"", "plain", "-----BEGIN RSA PRIVATE KEY-----", "https://u:p@h/", "Bearer ", "token: ", "\x00\xff", "eyJ.eyJ."} {
		f.Add(s, uint8(0))
	}
	f.Fuzz(func(t *testing.T, noise string, which uint8) {
		p := positives[int(which)%len(positives)]
		in := noise + "\n" + p.Text + "\n" + noise
		out := redact.Scrub(in)
		for _, secret := range p.Secrets {
			if strings.Contains(out, secret) {
				t.Fatalf("planted %s survived.\n in: %q\nout: %q", p.Name, in, out)
			}
		}
		if len(out) > len(in)+len(redact.Marker)*(len(in)/redact.MinLen+1) {
			t.Fatalf("output grew from %d to %d bytes", len(in), len(out))
		}
	})
}

func pickHex(r *rand.Rand, n int) string {
	const hex = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hex[r.IntN(16)]
	}
	return string(b)
}

func abbreviate(s string) string {
	if len(s) <= 80 {
		return s
	}
	return s[:40] + "…" + s[len(s)-30:]
}
