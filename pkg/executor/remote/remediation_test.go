package remote_test

// These tests exist because the failure they guard against is silence.
//
// A remediation that is merely absent does not break a build, fail a test or
// log a warning. It shows up as an operator standing at an edge device reading
// "remote: enrollment token already redeemed" and guessing — which is where
// this project was before Task 20274. So the contract is asserted directly:
// every enrollment sentinel an operator can actually hit carries a sentence,
// and the two that can mean an incident say so.

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// TestEveryEnrollmentErrorCarriesRemediation sweeps the sentinels a device or
// an operator can encounter during enrolment.
//
// ErrTokenExpired and ErrTokenAlreadyUsed are the two Task 20274 named as
// falling through: they are the *common* failures — a token outlives its TTL
// while a device is shipped, or someone runs enrolment twice — and they were
// the two with no advice attached.
func TestEveryEnrollmentErrorCarriesRemediation(t *testing.T) {
	for _, err := range []error{
		remote.ErrTokenExpired,
		remote.ErrTokenAlreadyUsed,
		remote.ErrTokenInvalid,
		remote.ErrRevoked,
		remote.ErrCredentialInvalid,
		remote.ErrAgentUnreachable,
		remote.ErrVersionUnsupported,
		remote.ErrRevocationUnsupported,
		remote.ErrAgentNotFound,
	} {
		t.Run(err.Error(), func(t *testing.T) {
			remedy := remote.EnrollmentRemediation(err)
			if strings.TrimSpace(remedy) == "" {
				t.Fatalf("%v reaches an operator with no remediation", err)
			}
			// A remediation that does not name a command is advice, not a fix.
			if !strings.Contains(remedy, "cloop ") {
				t.Errorf("the remediation names no command to run: %q", remedy)
			}
		})
	}
}

// TestRemediationSurvivesWrapping is the property that makes this usable at a
// call site. Errors reach the CLI wrapped in transport and session context, so
// a matcher that only handled the bare sentinel would answer "" for every real
// failure — passing this file's other tests while helping nobody.
func TestRemediationSurvivesWrapping(t *testing.T) {
	wrapped := fmt.Errorf("dial wss://hub.example:8443: %w: token tok_abc123",
		remote.ErrTokenExpired)
	if remote.EnrollmentRemediation(wrapped) == "" {
		t.Fatal("a wrapped ErrTokenExpired lost its remediation")
	}
	if !errors.Is(wrapped, remote.ErrTokenExpired) {
		t.Fatal("test fixture does not actually wrap the sentinel")
	}
}

// TestReplayRemediationNamesRevocation.
//
// A replayed token has two readings with opposite responses: the operator ran
// enrolment twice, or somebody else redeemed the token first. Only the second
// is an incident, and the remediation has to raise it — an operator who reads
// "already redeemed" as "oops, I did that twice" when it was a capture leaves
// an attacker holding a live credential on their fleet.
func TestReplayRemediationNamesRevocation(t *testing.T) {
	remedy := remote.EnrollmentRemediation(remote.ErrTokenAlreadyUsed)
	if !strings.Contains(remedy, "revoke") {
		t.Errorf("the replay remediation does not mention revoking the agent it created: %q", remedy)
	}
	if !strings.Contains(strings.ToLower(remedy), "not you") {
		t.Errorf("the replay remediation does not raise the possibility that someone else "+
			"redeemed the token: %q", remedy)
	}
}

// TestExpiryRemediationNamesTheFix: the fix is minting a new token, and the
// reason it expired is a TTL the operator can raise. Both belong in the line,
// or the next attempt fails the same way.
func TestExpiryRemediationNamesTheFix(t *testing.T) {
	remedy := remote.EnrollmentRemediation(remote.ErrTokenExpired)
	for _, want := range []string{"cloop executor enroll", "--ttl"} {
		if !strings.Contains(remedy, want) {
			t.Errorf("the expiry remediation does not mention %q: %q", want, remedy)
		}
	}
}

// TestUnknownErrorGetsNoAdvice.
//
// Returning "" rather than a generic line is deliberate: it lets a caller print
// its own context instead of a platitude, and a remediation that says "check
// your configuration" trains operators to stop reading them.
func TestUnknownErrorGetsNoAdvice(t *testing.T) {
	if got := remote.EnrollmentRemediation(errors.New("disk on fire")); got != "" {
		t.Errorf("an unrelated error produced advice: %q", got)
	}
	if got := remote.EnrollmentRemediation(nil); got != "" {
		t.Errorf("nil produced advice: %q", got)
	}
}
