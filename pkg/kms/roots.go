package kms

// From the secrets section to the keyring's roots (Task 20433).
//
// The keyring opens with a current root and, during a change of root, a
// previous one; config/secrets.go says which configuration names which. This
// file builds them: a KMS block becomes a Provider, the root key a passphrase
// root, and the combination is checked for the one ambiguity the two sources
// can produce between them — a previous root named twice.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// Roots are the keyring's roots, and the providers behind any that are KMSs.
type Roots struct {
	Current  secretbroker.Root
	Previous secretbroker.Root
	// Providers are the KMSs among them, current first.
	Providers []Provider
}

// Close releases every provider.
func (r Roots) Close() {
	for _, p := range r.Providers {
		_ = p.Close()
	}
}

// UsesKMS reports whether either root is a KMS.
func (r Roots) UsesKMS() bool { return len(r.Providers) > 0 }

// Resolve builds the keyring's roots from the secrets section and the root key
// pkg/rootkey resolved. It connects to nothing; AwaitReady does.
func Resolve(sc config.SecretsConfig, keys rootkey.Roots) (Roots, error) {
	if err := config.ValidateSecrets(sc); err != nil {
		return Roots{}, err
	}
	var out Roots
	fail := func(err error) (Roots, error) {
		out.Close()
		return Roots{}, err
	}

	if sc.KMS.Configured() {
		p, err := Open(sc.KMS)
		if err != nil {
			return fail(fmt.Errorf("secrets.kms: %w", err))
		}
		out.Providers = append(out.Providers, p)
		out.Current = secretbroker.KMSRoot(p)
	} else {
		// Unset is the zero Root, which OpenKeyring answers with ErrNoKey:
		// the documented degraded mode of a hub with no key at all.
		out.Current = secretbroker.PassphraseRoot(keys.Current.Value)
	}

	switch {
	case sc.KMSPrevious.Configured():
		if keys.Previous.Set() {
			return fail(fmt.Errorf("%s (%s) and secrets.kms_previous both name a previous root; a change of "+
				"root moves from one root to one other — finish one change first", rootkey.EnvPrevious,
				keys.Previous.Describe()))
		}
		p, err := Open(sc.KMSPrevious)
		if err != nil {
			return fail(fmt.Errorf("secrets.kms_previous: %w", err))
		}
		out.Providers = append(out.Providers, p)
		out.Previous = secretbroker.KMSRoot(p)

	case strings.TrimSpace(sc.PreviousRoot) == config.PreviousRootPassphrase:
		if keys.Previous.Set() {
			return fail(fmt.Errorf("secrets.previous_root: passphrase and %s (%s) both name a previous root; "+
				"finish changing %s before moving onto a KMS", rootkey.EnvPrevious, keys.Previous.Describe(),
				rootkey.EnvKey))
		}
		if !keys.Current.Set() {
			return fail(fmt.Errorf("secrets.previous_root: passphrase names %s as the root secrets.kms is "+
				"replacing, and it is not configured here (%s, %s, or the credential %s)", rootkey.EnvKey,
				rootkey.EnvKeyFile, rootkey.EnvKey, rootkey.Credential))
		}
		out.Previous = secretbroker.PassphraseRoot(keys.Current.Value)

	case keys.Previous.Set():
		if out.Current.IsKMS() {
			return fail(fmt.Errorf("%s is set (%s), which changes %s, and the store's current root is "+
				"secrets.kms: the passphrase a KMS is replacing is named with secrets.previous_root: passphrase "+
				"— remove %s", rootkey.EnvPrevious, keys.Previous.Describe(), rootkey.EnvKey, rootkey.EnvPrevious))
		}
		out.Previous = secretbroker.PassphraseRoot(keys.Previous.Value)
	}
	return out, nil
}

// Resolver returns a secretbroker.RootResolver for a command's secrets
// section: the roots are built on first use, once, so a command that never
// opens the store never builds a KMS client, let alone calls one.
func Resolver(sc config.SecretsConfig) secretbroker.RootResolver {
	var (
		once  sync.Once
		roots Roots
		err   error
	)
	return func() (secretbroker.Root, secretbroker.Root, error) {
		once.Do(func() {
			keys, kerr := rootkey.Resolve()
			if kerr != nil {
				err = fmt.Errorf("%w: %v", secretbroker.ErrRootConfig, kerr)
				return
			}
			roots, err = Resolve(sc, keys)
		})
		if err != nil {
			return secretbroker.Root{}, secretbroker.Root{}, err
		}
		return roots.Current, roots.Previous, nil
	}
}

// AwaitReady waits until every provider answers Status healthy, for at most
// timeout, polling with a short backoff, and returns the statuses. It returns
// the last failure when the time runs out, naming the KMS and why — which is
// what `cloop ui` refuses to start with. A timeout of zero asks once.
//
// logf, when not nil, is told what is being waited for, at most every few
// seconds, so a hub whose plugin sidecar is still starting says so.
func AwaitReady(ctx context.Context, providers []Provider, timeout time.Duration,
	logf func(format string, args ...any)) ([]Status, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	deadline := time.Now().Add(timeout)
	statuses := make([]Status, len(providers))
	for i, p := range providers {
		backoff := 200 * time.Millisecond
		lastLog := time.Time{}
		for {
			st, err := p.Status(ctx)
			if err == nil {
				statuses[i] = st
				break
			}
			remaining := time.Until(deadline)
			if remaining <= 0 || ctx.Err() != nil {
				return statuses, fmt.Errorf("%s (%s): %w", p.Describe(), p.Name(), err)
			}
			if logf != nil && time.Since(lastLog) > 5*time.Second {
				logf("waiting for %s: %v", p.Describe(), err)
				lastLog = time.Now()
			}
			// Never past the deadline, and one last attempt at it: a plugin
			// that comes up in the last second of the wait is still found.
			wait := backoff
			if wait > remaining {
				wait = remaining
			}
			select {
			case <-ctx.Done():
				return statuses, fmt.Errorf("%s (%s): %w", p.Describe(), p.Name(), ctx.Err())
			case <-time.After(wait):
			}
			if backoff < 2*time.Second {
				backoff *= 2
			}
		}
	}
	return statuses, nil
}

// Unreachable reports whether err says a KMS could not be reached or did not
// answer — the KMS may be fine and merely absent — rather than that it
// answered and refused.
func Unreachable(err error) bool { return errors.Is(err, secretbroker.ErrKMSUnavailable) }
