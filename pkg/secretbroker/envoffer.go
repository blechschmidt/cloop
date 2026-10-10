package secretbroker

import (
	"fmt"
	"sort"
	"time"
)

// Previewing an environment by name (Task 20379).
//
// The hub refuses to dispatch a sandboxed harness that would reach `claude`
// with no login, and to know that before anything starts it has to answer the
// question a lease answers a moment too late: which variables would this run's
// environment carry? Leasing to find out is not an option. A lease writes audit
// rows for a run that may never exist, and for a GitHub App grant it mints a
// live installation token at GitHub.
//
// So this file answers it by name. EnvOffers walks the grants exactly as
// LeaseFor does and reports, per env grant, the keys its material would hold;
// EnvKeyNamesFor does the same for one secret a viewer may see, which is how the
// hub lists the secrets that could fill the gap. Both open the payload — the
// names are inside the ciphertext — and both return names only. No value
// leaves this package through either, and the decoded payload is dropped as
// soon as its keys are read.

// EnvOffer is what one env grant would contribute, by name, to the environment
// of a lease for some requester.
type EnvOffer struct {
	// Grant is the grant, revoked or not; Active says whether a lease issued
	// now would use it. Expired grants are included so a caller can say which
	// credential lapsed rather than only that none is left.
	Grant Grant
	// Secret is the env secret the grant points at. It carries no plaintext,
	// by construction (see Secret).
	Secret Secret
	// Keys are the variable names the grant's material would hold, sorted:
	// the payload's own keys, narrowed by the grant's env_keys allowlist and
	// by what can be encoded as K=V. The same rule envMaterial applies.
	Keys []string
	// Err is why the keys could not be read — the payload would not open, or
	// the secret is gone. A lease would deny this grant for the same reason.
	Err error
}

// Active reports whether a lease issued at now would deliver this offer.
func (o EnvOffer) Active(now time.Time) bool {
	return o.Err == nil && len(o.Keys) > 0 && o.Grant.Active(now)
}

// EnvOffers previews the environment a lease for r would carry, grant by grant.
//
// Every grant whose subject matches r and which has not been revoked is
// reported, whatever its expiry; a revoked grant is a decision someone made and
// is left out. Only grants over env secrets are considered: no other kind puts
// a credential the hub controls into a variable by name.
//
// It mirrors LeaseFor's matching — the requester's project is normalised the
// same way and Subject.Matches decides — and deliberately ignores r.Withhold,
// because deciding what to withhold is the caller's use for this preview.
//
// It writes no audit row and mints nothing. What it returns is names, so the
// preview discloses to its caller exactly what a lease's own summary row would
// have recorded ("env keys: …"), and nothing a lease would have kept back.
func (b *Broker) EnvOffers(r Requester) ([]EnvOffer, error) {
	r.ProjectID = NormalizeProjectID(r.ProjectID)
	grants, err := b.store.ListGrants()
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	type secretKeys struct {
		sec  Secret
		keys []string
		err  error
	}
	read := map[string]secretKeys{}
	var out []EnvOffer
	for _, g := range grants {
		if !g.RevokedAt.IsZero() || !g.Subject.Matches(r) {
			continue
		}
		sk, seen := read[g.SecretID]
		if !seen {
			sec, gerr := b.store.GetSecret(g.SecretID)
			switch {
			case gerr != nil:
				if _, why, gone := b.deletedSecretRefusal(g); gone {
					sk = secretKeys{err: fmt.Errorf("%w: grant %s spent a secret that no longer exists: %s",
						ErrSecretDeleted, g.ID, why)}
					break
				}
				sk = secretKeys{err: fmt.Errorf("%w: grant %s points at missing secret %s", ErrSecretNotFound, g.ID, g.SecretID)}
			case sec.Kind != KindEnv:
				sk = secretKeys{sec: sec}
			default:
				keys, kerr := b.envKeyNames(sec)
				sk = secretKeys{sec: sec, keys: keys, err: kerr}
			}
			read[g.SecretID] = sk
		}
		if sk.err == nil && sk.sec.Kind != KindEnv {
			continue
		}
		offer := EnvOffer{Grant: g, Secret: sk.sec, Err: sk.err}
		for _, k := range sk.keys {
			if deliverableEnvKey(g.Constraints, k) {
				offer.Keys = append(offer.Keys, k)
			}
		}
		out = append(out, offer)
	}
	return out, nil
}

// EnvKeyNamesFor returns the variable names an env secret defines, for a viewer
// who may see that secret.
//
// A secret v may not see reports ErrSecretNotFound, as DescribeSecretFor does,
// so the names of somebody else's personal secret are not an oracle for its
// existence. A secret of another kind reports ErrInvalidKind.
func (b *Broker) EnvKeyNamesFor(ref string, v Viewer) ([]string, error) {
	sec, err := b.DescribeSecretFor(ref, v)
	if err != nil {
		return nil, err
	}
	if sec.Kind != KindEnv {
		return nil, fmt.Errorf("%w: %s is a %s secret, not env", ErrInvalidKind, sec.Name, sec.Kind)
	}
	return b.envKeyNames(sec)
}

// envKeyNames opens an env secret and keeps only its keys.
//
// The payload is decoded by jsonUnmarshalEnv, the function envMaterial uses, so
// a preview and a lease cannot disagree about which keys a payload defines — a
// JSON object with a non-string value, for one, is the bare-value shape to
// both. Keys K=V cannot carry are dropped, as envMaterial drops them.
func (b *Broker) envKeyNames(sec Secret) ([]string, error) {
	plaintext, err := b.seal.OpenEnvelope(AADFor(SetSecrets, sec.ID), sec.Envelope())
	if err != nil {
		return nil, fmt.Errorf("%w: open payload for %s: %w", ErrSealFailed, sec.Name, err)
	}
	defer zero(plaintext)
	env := jsonUnmarshalEnv(plaintext, sec.Name)
	keys := make([]string, 0, len(env))
	for k := range env {
		if validateEnvKey(k) == nil {
			keys = append(keys, k)
		}
	}
	// The values are Go strings and cannot be zeroed; dropping the only
	// reference now leaves them to the collector, which is the same treatment
	// a lease's own material gets once it has been rendered.
	clear(env)
	sort.Strings(keys)
	return keys, nil
}

// deliverableEnvKey is envMaterial's rule for one key: the grant permits it,
// and it can be written into a K=V environment block without corrupting it.
func deliverableEnvKey(c Constraints, k string) bool {
	return c.AllowsEnvKey(k) && validateEnvKey(k) == nil
}

// LeaseHorizon reports the grant whose expiry would end a lease for r: of the
// grants a lease would consider — matching r, neither revoked nor expired, not
// withheld by r.Withhold — the one that expires first. ok is false when none of
// them expires at all.
//
// A lease is issued only until its earliest grant ends (leaseDeadline), and
// Extend refuses it once any of its grants lapses, so every credential in it
// shares that end, whatever its own grant says. A preview that judged each
// credential by its own grant alone would promise a run a Claude login that
// a five-minute GitHub grant beside it was about to take away.
//
// Like EnvOffers it writes no audit row and opens no payload. It is a bound
// rather than a forecast: a grant the lease would go on to deny (a GitHub App
// GitHub refuses, a kubeconfig that minimises to nothing) is counted here and
// would not shorten the real lease.
func (b *Broker) LeaseHorizon(r Requester) (first Grant, ok bool, err error) {
	r.ProjectID = NormalizeProjectID(r.ProjectID)
	grants, err := b.store.ListGrants()
	if err != nil {
		return Grant{}, false, fmt.Errorf("list grants: %w", err)
	}
	now := b.now()
	for _, g := range grants {
		if !g.Subject.Matches(r) || !g.Active(now) || g.ExpiresAt.IsZero() {
			continue
		}
		if _, withheld := r.Withhold[g.ID]; withheld {
			continue
		}
		if !ok || g.ExpiresAt.Before(first.ExpiresAt) {
			first, ok = g, true
		}
	}
	return first, ok, nil
}
