package secretbroker

import "errors"

// Sentinel errors. Callers match with errors.Is; every constructor in this
// package wraps one of these with %w and adds detail.
//
// The denial errors (ErrRepoDenied, ErrNamespaceDenied, ErrHostDenied,
// ErrGrantExpired, ErrGrantRevoked) are deliberately distinct from the
// validation errors: a denial is a security event that must reach the audit
// log, while a validation error is a malformed request that never became one.
var (
	// ErrInvalidKind: the secret kind is not one of the known kinds.
	ErrInvalidKind = errors.New("secretbroker: invalid secret kind")
	// ErrInvalidSecret: the secret failed structural validation.
	ErrInvalidSecret = errors.New("secretbroker: invalid secret")
	// ErrInvalidGrant: the grant failed structural validation.
	ErrInvalidGrant = errors.New("secretbroker: invalid grant")
	// ErrInvalidSubject: the grant subject could not be parsed or is empty.
	ErrInvalidSubject = errors.New("secretbroker: invalid subject")
	// ErrInvalidConstraint: a constraint pattern is malformed, unsafe to
	// embed, or missing where its kind requires one.
	ErrInvalidConstraint = errors.New("secretbroker: invalid constraint")

	// ErrSecretNotFound: no secret with that ID or name exists.
	ErrSecretNotFound = errors.New("secretbroker: secret not found")
	// ErrGrantNotFound: no grant with that ID exists.
	ErrGrantNotFound = errors.New("secretbroker: grant not found")
	// ErrLeaseNotFound: the lease ID is unknown or already released.
	ErrLeaseNotFound = errors.New("secretbroker: lease not found")
	// ErrDuplicateName: a secret with that name already exists.
	ErrDuplicateName = errors.New("secretbroker: secret name already in use")

	// ErrGrantExpired: the grant's TTL elapsed.
	ErrGrantExpired = errors.New("secretbroker: grant expired")
	// ErrGrantRevoked: the grant was revoked.
	ErrGrantRevoked = errors.New("secretbroker: grant revoked")
	// ErrLeaseExpired: the lease's TTL elapsed; Renew or re-Lease.
	ErrLeaseExpired = errors.New("secretbroker: lease expired")

	// ErrRepoDenied: the repository is outside the grant's allowlist, or
	// could not be normalised into owner/repo form.
	ErrRepoDenied = errors.New("secretbroker: repository denied")
	// ErrNamespaceDenied: the Kubernetes namespace is outside the allowlist.
	ErrNamespaceDenied = errors.New("secretbroker: namespace denied")
	// ErrHostDenied: the host is outside the egress allowlist, or could not
	// be normalised.
	ErrHostDenied = errors.New("secretbroker: host denied")

	// ErrMinimizedEmpty: minimising the payload against the grant's
	// constraints left nothing to deliver. This is a denial, not an empty
	// success — delivering an empty kubeconfig would look like a working
	// credential that mysteriously cannot reach anything.
	ErrMinimizedEmpty = errors.New("secretbroker: nothing remains after minimization")
	// ErrMalformedPayload: the stored payload is not in the shape its kind
	// requires (e.g. a kubeconfig that is not valid YAML).
	ErrMalformedPayload = errors.New("secretbroker: malformed secret payload")

	// ErrNoKey: CLOOP_SECRET_KEY is unset, so payloads can be neither
	// sealed nor opened.
	ErrNoKey = errors.New("secretbroker: CLOOP_SECRET_KEY is not set")
	// ErrSealFailed: encryption or decryption failed (wrong key, or a
	// corrupt/tampered envelope — AES-GCM cannot tell you which).
	ErrSealFailed = errors.New("secretbroker: seal/unseal failed")

	// Sealing-key registry errors (Task 20181).
	//
	// These are separate from ErrSealFailed because each calls for a
	// different operator response, and a hub that reports only "decryption
	// failed" makes an operator guess between "the key is gone", "the
	// passphrase is wrong" and "the ciphertext is corrupt" during an
	// incident. They are what makes a read against a retired key fail
	// *loudly* rather than merely fail.

	// ErrKeyRetired: the material names a KEK whose salt was destroyed. The
	// material is unrecoverable and the credential must be re-minted.
	ErrKeyRetired = errors.New("secretbroker: sealing key retired")
	// ErrKeyUnavailable: the KEK exists but cannot be derived from the
	// current CLOOP_SECRET_KEY. The material is intact; the passphrase is
	// wrong.
	ErrKeyUnavailable = errors.New("secretbroker: sealing key unavailable")
	// ErrKeyUnknown: the material names a KEK this hub has no record of —
	// a database from another hub, or a partially restored backup.
	ErrKeyUnknown = errors.New("secretbroker: unknown sealing key")
	// ErrKeyInUse: the KEK cannot be retired because sealed material still
	// references it, or because it is the primary.
	ErrKeyInUse = errors.New("secretbroker: sealing key still in use")
	// ErrRotationFailed: a rotation could not rewrap every row. Rotation is
	// resumable, so this means "run it again", not "start over".
	ErrRotationFailed = errors.New("secretbroker: key rotation incomplete")
)
