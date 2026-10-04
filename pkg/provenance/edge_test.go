package provenance

// edge_test.go is the accept/reject matrix for the two trust roots
// (Task 20376): which signer each channel's verification accepts.
//
// The matrix is checked twice. Once against the regexps with Go's own engine,
// which is what cosign uses, so the pins themselves are proven; and once
// through VerifyBlob with a stand-in cosign that reads the signer out of the
// bundle, so the plumbing — ForChannel choosing the identity, the environment
// overrides staying in their own lanes — is proven as well.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/blechschmidt/cloop/internal/cosigntest"
)

// signers is every SAN the matrix considers, with whether each channel must
// accept it.
var signers = []struct {
	name           string
	san            string
	stable, edge   bool
	whyEdgeRefuses string
}{
	{"release.yml on a tag", cosigntest.Release, true, false,
		"a release signature does not make a build an edge build"},
	{"edge.yml on main", cosigntest.Edge, false, true, ""},
	{"edge.yml on another branch", cosigntest.EdgeOtherBranch, false, false,
		"anyone who can push a branch could otherwise sign edge builds"},
	{"edge.yml on a tag", cosigntest.EdgeOnTag, false, false,
		"the edge channel is main's builds, and a tag is not main"},
	{"ci.yml on main", cosigntest.CIOnMain, false, false,
		"CI runs on every pull request and must never be a signing oracle"},
	{"release.yml on main", cosigntest.ReleaseOnMain, false, false,
		"only edge.yml signs edge builds"},
	{"a fork's edge.yml", cosigntest.ForkEdge, false, false,
		"a fork is not this repository"},
	{"edge.yml on a branch that starts with main", "https://github.com/blechschmidt/cloop/.github/workflows/edge.yml@refs/heads/main-next", false, false,
		"the ref is pinned whole, not as a prefix"},
	{"edge.yml on a pull request's merge ref", "https://github.com/blechschmidt/cloop/.github/workflows/edge.yml@refs/pull/7/merge", false, false,
		"a pull request runs whatever its author pushed"},
	{"edge.yml behind an unanchored prefix", "https://evil.example/https://github.com/blechschmidt/cloop/.github/workflows/edge.yml@refs/heads/main", false, false,
		"the pin is anchored at both ends"},
	{"edge.yml in a repository whose name starts the same", "https://github.com/blechschmidt/cloop-evil/.github/workflows/edge.yml@refs/heads/main", false, false,
		"the repository is pinned whole"},
	{"a lookalike workflow name", "https://github.com/blechschmidt/cloop/.github/workflows/edgexyml@refs/heads/main", false, false,
		"the dots are literal"},
}

// TestEdgeAndReleasePinsMatrix checks the pins with Go's regexp engine.
func TestEdgeAndReleasePinsMatrix(t *testing.T) {
	stable := regexp.MustCompile(DefaultIdentityRegexp)
	edge := regexp.MustCompile(EdgeIdentityRegexp)
	for _, s := range signers {
		if got := stable.MatchString(s.san); got != s.stable {
			t.Errorf("release pin on %s (%s): accepted=%t, want %t", s.name, s.san, got, s.stable)
		}
		if got := edge.MatchString(s.san); got != s.edge {
			t.Errorf("edge pin on %s (%s): accepted=%t, want %t — %s", s.name, s.san, got, s.edge, s.whyEdgeRefuses)
		}
	}
}

// stageSigned writes a blob and a stand-in bundle claiming san signed it.
func stageSigned(t *testing.T, san string) (blob, bundle string) {
	t.Helper()
	dir := t.TempDir()
	blob = filepath.Join(dir, "cloop_linux_amd64.tar.gz")
	data := []byte("artifact bytes")
	if err := os.WriteFile(blob, data, 0o644); err != nil {
		t.Fatal(err)
	}
	bundle = BundleNameFor(blob)
	if err := os.WriteFile(bundle, cosigntest.Bundle(san, data), 0o644); err != nil {
		t.Fatal(err)
	}
	return blob, bundle
}

// TestChannelVerificationMatrix runs the matrix through VerifyBlob: each
// channel's verifier accepts its own signer and refuses every other one.
func TestChannelVerificationMatrix(t *testing.T) {
	bin := cosigntest.Install(t)
	base := &Verifier{Binary: bin}
	for _, s := range signers {
		blob, bundle := stageSigned(t, s.san)
		for _, c := range []struct {
			channel Channel
			want    bool
		}{{ChannelStable, s.stable}, {ChannelEdge, s.edge}} {
			err := base.ForChannel(c.channel).VerifyBlob(context.Background(), blob, bundle)
			switch {
			case c.want && err != nil:
				t.Errorf("%s channel refused %s: %v", c.channel, s.name, err)
			case !c.want && err == nil:
				t.Errorf("%s channel ACCEPTED %s (%s)", c.channel, s.name, s.san)
			case !c.want && !errors.Is(err, ErrUnverified):
				t.Errorf("%s channel refused %s, but not as a failed verification: %v", c.channel, s.name, err)
			}
		}
	}
}

// TestFakeCosignAgreesWithGoRegexp keeps the stand-in honest: for every signer
// and both pins, grep -E in the stand-in gives the verdict Go's regexp does.
func TestFakeCosignAgreesWithGoRegexp(t *testing.T) {
	bin := cosigntest.Install(t)
	for _, pin := range []string{DefaultIdentityRegexp, EdgeIdentityRegexp} {
		re := regexp.MustCompile(pin)
		v := &Verifier{Binary: bin, Identity: pin}
		for _, s := range signers {
			blob, bundle := stageSigned(t, s.san)
			err := v.VerifyBlob(context.Background(), blob, bundle)
			if got, want := err == nil, re.MatchString(s.san); got != want {
				t.Errorf("stand-in and Go disagree on %s under %s: stand-in accepted=%t, Go=%t (%v)",
					s.name, pin, got, want, err)
			}
		}
	}
}

// TestForChannelKeepsTheTwoPinsApart: an edge verification uses the edge pin
// whatever the release pin was set to, and repointing one never moves the
// other.
func TestForChannelKeepsTheTwoPinsApart(t *testing.T) {
	base := &Verifier{Binary: "cosign", Issuer: "https://issuer.example", Identity: `^release-only$`}
	if _, id := base.ForChannel(ChannelEdge).TrustRoot(); id != EdgeIdentityRegexp {
		t.Errorf("an edge verification inherited the release identity: %s", id)
	}
	if iss, _ := base.ForChannel(ChannelEdge).TrustRoot(); iss != "https://issuer.example" {
		t.Errorf("the issuer did not carry over to the edge verifier: %s", iss)
	}
	if _, id := base.ForChannel(ChannelStable).TrustRoot(); id != `^release-only$` {
		t.Errorf("the stable verification lost its configured identity: %s", id)
	}

	t.Setenv(IdentityEnv, `^fork-release$`)
	if _, id := (&Verifier{}).ForChannel(ChannelEdge).TrustRoot(); id != EdgeIdentityRegexp {
		t.Errorf("%s repointed the edge identity to %s", IdentityEnv, id)
	}
	t.Setenv(EdgeIdentityEnv, `^fork-edge$`)
	if _, id := (&Verifier{}).ForChannel(ChannelEdge).TrustRoot(); id != `^fork-edge$` {
		t.Errorf("%s was not honoured for the edge channel: %s", EdgeIdentityEnv, id)
	}
	if _, id := (&Verifier{}).ForChannel(ChannelStable).TrustRoot(); id != `^fork-release$` {
		t.Errorf("%s leaked into the release identity: %s", EdgeIdentityEnv, id)
	}
	// A nil verifier is the zero value's channel copy, not a panic.
	if _, id := (*Verifier)(nil).ForChannel(ChannelEdge).TrustRoot(); id != `^fork-edge$` {
		t.Errorf("nil verifier: %s", id)
	}
}

func TestParseChannel(t *testing.T) {
	for in, want := range map[string]Channel{"": ChannelStable, "stable": ChannelStable, " Edge ": ChannelEdge} {
		got, err := ParseChannel(in)
		if err != nil || got != want {
			t.Errorf("ParseChannel(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseChannel("nightly"); err == nil {
		t.Error("an unknown channel was accepted")
	}
}
