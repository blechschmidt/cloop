package remote

// Turning enrollment failures into instructions.
//
// The errors in errors.go are precise, and precision is not the same as being
// actionable. An operator standing at a device that has just refused to enrol
// reads "remote: enrollment token already redeemed" and has to work out, on
// their own, that this is either a token they pasted twice or a token somebody
// else got to first — and that those have opposite responses. One is "mint
// another"; the other is "mint another *and* revoke the agent the stolen one
// produced, because an attacker is holding a live credential".
//
// So each of these carries the sentence that closes that gap. They live beside
// the errors rather than in the CLI because there are three callers — `cloop
// executor agent`, the enrollment API, and `cloop hub doctor --smoke` — and a
// remediation that exists in only one of them is a remediation most operators
// never see.

import "errors"

// EnrollmentRemediation returns the one-line fix for an enrollment failure, or
// "" when err is not one this function has advice for.
//
// Returning "" rather than a generic fallback is deliberate: a caller can then
// tell "I have specific advice" from "I do not", and print its own context
// instead of a platitude. A remediation line that says "check your
// configuration" trains operators to stop reading them.
func EnrollmentRemediation(err error) string {
	switch {
	case err == nil:
		return ""

	case errors.Is(err, ErrTokenExpired):
		// The common, benign case: enrollment tokens are deliberately
		// short-lived, and shipping a device to a site takes longer than the
		// TTL. Naming the TTL is what stops the next attempt failing the same
		// way.
		return "Enrollment tokens are short-lived by design. Mint a fresh one on the control " +
			"plane with `cloop executor enroll --name <device>` and redeem it promptly; use " +
			"--ttl to cover a longer shipping or provisioning window"

	case errors.Is(err, ErrTokenAlreadyUsed):
		// The case that can be an incident. Said plainly, because an operator
		// who reads this as "oops, pasted twice" when it was in fact a capture
		// leaves an attacker's credential live on their fleet.
		return "This token was already redeemed. If that was not you — or not this device — " +
			"a copy of the token was used first: revoke the agent it created with " +
			"`cloop executor revoke <token-id>`, which also revokes the agent, then mint a new " +
			"token. If you simply ran enrolment twice, the first run already succeeded and this " +
			"device needs only its stored credential"

	case errors.Is(err, ErrTokenInvalid):
		return "The token is malformed or unknown to this control plane. Check it was copied " +
			"whole, and that this device is pointed at the right hub (--url); mint a new one " +
			"with `cloop executor enroll --name <device>`"

	case errors.Is(err, ErrRevoked), errors.Is(err, ErrCredentialInvalid):
		return "This device's credential is no longer accepted. Mint a new token on the control " +
			"plane with `cloop executor enroll --name <device>` and re-run with --token"

	case errors.Is(err, ErrAgentUnreachable):
		return "The control plane has no live session for this agent. Start `cloop executor " +
			"agent` on the device, and check it can reach the hub's URL outbound — enrolment " +
			"is outbound-only, so no inbound port needs opening"

	case errors.Is(err, ErrVersionUnsupported):
		return "The agent and the hub do not share a protocol version. Upgrade the agent with " +
			"`cloop executor upgrade <id>`, or upgrade the hub if the device is the newer one"

	case errors.Is(err, ErrRevocationUnsupported):
		return "This agent is too old to honour a mid-run credential revocation, so the hub " +
			"refuses to hand it secrets. Upgrade it with `cloop executor upgrade <id>`"

	case errors.Is(err, ErrAgentNotFound):
		return "No agent with that ID is enrolled. `cloop executor list` shows the fleet; a " +
			"device appears only once it has connected at least once"
	}
	return ""
}
