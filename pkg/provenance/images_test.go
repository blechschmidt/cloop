package provenance

import (
	"regexp"
	"testing"
)

// TestImagesPinIsItsOwn: the images pin has its own overrides, and the release
// and edge variables move nothing here — nor does this one move them. A fork
// that repoints its release pin at another issuer must not leave every image
// checked against a GitHub identity under that issuer, which would refuse them
// all as wrongly signed.
func TestImagesPinIsItsOwn(t *testing.T) {
	for _, env := range []string{IssuerEnv, IdentityEnv, EdgeIdentityEnv, ImagesIssuerEnv, ImagesIdentityEnv} {
		t.Setenv(env, "")
	}
	if ImagesIssuer() != DefaultIssuer || ImagesIdentity() != ImagesIdentityRegexp {
		t.Fatalf("default images pin = %s / %s", ImagesIssuer(), ImagesIdentity())
	}

	t.Setenv(IssuerEnv, "https://gitlab.example.com")
	t.Setenv(IdentityEnv, `^https://gitlab\.example\.com/acme/cloop//release$`)
	t.Setenv(EdgeIdentityEnv, `^https://gitlab\.example\.com/acme/cloop//edge$`)
	if ImagesIssuer() != DefaultIssuer || ImagesIdentity() != ImagesIdentityRegexp {
		t.Errorf("the release or edge overrides moved the images pin: %s / %s", ImagesIssuer(), ImagesIdentity())
	}

	const fork = `^https://github\.com/acme/cloop/\.github/workflows/images\.yml@refs/heads/main$`
	t.Setenv(ImagesIssuerEnv, "https://token.actions.example.com")
	t.Setenv(ImagesIdentityEnv, fork)
	if ImagesIssuer() != "https://token.actions.example.com" || ImagesIdentity() != fork {
		t.Errorf("the images overrides were not applied: %s / %s", ImagesIssuer(), ImagesIdentity())
	}
	// And they reach neither of the other pins.
	if got := (&Verifier{}).ForChannel(ChannelEdge).identity(); got == fork {
		t.Error("the images override repointed the edge pin")
	}
	t.Setenv(IdentityEnv, "")
	if got := (&Verifier{}).identity(); got != DefaultIdentityRegexp {
		t.Errorf("the images override repointed the release pin: %s", got)
	}
}

// TestImagesPinCompiles: a pin that does not compile would make cosign refuse
// every image as wrongly signed, which is the one refusal nothing overrides.
func TestImagesPinCompiles(t *testing.T) {
	if _, err := regexp.Compile(ImagesIdentityRegexp); err != nil {
		t.Fatal(err)
	}
}
