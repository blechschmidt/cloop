package deviceforward

import "errors"

// Sentinel errors for the forwarder feature. They are errors.Is targets so a
// caller — the CLI, the hub endpoint, a test — can branch on what went wrong
// without matching on message text.
var (
	// ErrInvalidSpec reports a device descriptor or configuration that is not
	// admissible. It is the forwarder's ErrInvalidSpec, kept separate from
	// executor.ErrInvalidSpec because the two packages do not import each
	// other's error here and a caller branches on the one it was handed.
	ErrInvalidSpec = errors.New("deviceforward: invalid specification")

	// ErrTokenInvalid reports a malformed enrollment token or credential, or
	// one whose MAC does not verify against this control plane.
	ErrTokenInvalid = errors.New("deviceforward: token is invalid")
	// ErrTokenExpired reports an enrollment token past its TTL.
	ErrTokenExpired = errors.New("deviceforward: enrollment token expired")
	// ErrTokenAlreadyUsed reports an enrollment token redeemed before.
	ErrTokenAlreadyUsed = errors.New("deviceforward: enrollment token already redeemed")
	// ErrRevoked reports a token or credential that was explicitly revoked.
	ErrRevoked = errors.New("deviceforward: credential revoked")
	// ErrCredentialInvalid reports a long-lived forwarder credential that does
	// not authenticate — reported distinctly from a token so the device log
	// says "re-enroll" rather than "bad token".
	ErrCredentialInvalid = errors.New("deviceforward: credential is invalid")
	// ErrForwarderNotFound reports no enrollment token or forwarder with an ID.
	ErrForwarderNotFound = errors.New("deviceforward: no such forwarder")

	// ErrForwarderOffline reports that the named forwarder has no live session,
	// so the device it carries cannot be reached right now.
	ErrForwarderOffline = errors.New("deviceforward: forwarder is offline")
	// ErrChannelRefused reports that the forwarder declined to open a channel
	// to its device — the device is unplugged, or the request named something
	// other than the one device the forwarder is configured for.
	ErrChannelRefused = errors.New("deviceforward: forwarder refused to open the device")
	// ErrProtocol reports a wire-format violation on the forwarder connection.
	ErrProtocol = errors.New("deviceforward: protocol error")
)
