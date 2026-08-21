package secretbroker

import (
	"context"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/secret"
)

// LegacyImportResult reports what a legacy import did.
type LegacyImportResult struct {
	// Imported names the secrets newly minted into the broker.
	Imported []string
	// Skipped names entries already present (the import is idempotent).
	Skipped []string
}

// ImportLegacySecrets copies every entry from the flat pkg/secret store into
// the broker as an unscoped `env` secret with a matching wildcard grant.
//
// "Unscoped" is the whole point and is deliberate. The entries being
// imported were, until this moment, delivered to every workload with no
// scoping at all; narrowing them during a migration would break running
// projects at a moment nobody chose, and would do it silently — the workload
// would simply stop seeing a variable it depends on. So the import preserves
// existing reach exactly, with SubjectAny and no expiry, and leaves
// tightening to an operator who can then do it one grant at a time and watch
// what breaks. Every imported grant is audited, so "which of my secrets are
// still wide open" is a query rather than an archaeology exercise.
//
// It is idempotent: an entry whose name already exists in the broker is
// skipped, so this can run on every broker construction.
//
// A missing or unreadable legacy store is not an error — most installs will
// not have one.
func ImportLegacySecrets(ctx context.Context, b *Broker, workDir, actor string) (LegacyImportResult, error) {
	var res LegacyImportResult
	if b == nil {
		return res, fmt.Errorf("%w: nil broker", ErrInvalidSecret)
	}

	store, err := secret.Open(workDir)
	if err != nil {
		// No passphrase, no file, or a corrupt one. There is nothing to
		// import and nothing the caller can do about it here; the existing
		// `cloop secret` commands surface the real error.
		return res, nil
	}
	keys := store.Keys()
	if len(keys) == 0 {
		return res, nil
	}

	existing, err := b.ListSecrets()
	if err != nil {
		return res, err
	}
	known := make(map[string]bool, len(existing))
	for _, s := range existing {
		known[s.Name] = true
	}

	for _, key := range keys {
		name := legacyName(key)
		if known[name] {
			res.Skipped = append(res.Skipped, key)
			continue
		}
		value, ok := store.Get(key)
		if !ok {
			continue
		}

		// Store as a single-key JSON object so the delivered variable keeps
		// the operator's original name even where legacyName had to
		// sanitise it for the broker's stricter name charset.
		payload := []byte(fmt.Sprintf("{%q:%q}", key, value))
		s, mintErr := b.Mint(ctx, MintRequest{
			Name:    name,
			Kind:    KindEnv,
			Payload: payload,
			Metadata: map[string]string{
				"imported_from": "pkg/secret",
				"env_key":       key,
			},
			Actor: actor,
		})
		if mintErr != nil {
			return res, fmt.Errorf("import legacy secret %q: %w", key, mintErr)
		}

		if _, grantErr := b.Grant(ctx, GrantRequest{
			SecretRef:   s.ID,
			Subject:     Subject{Type: SubjectAny},
			Constraints: Constraints{EnvKeys: []string{key}},
			Scope:       "legacy-import",
			NoExpiry:    true,
			Actor:       actor,
		}); grantErr != nil {
			return res, fmt.Errorf("grant legacy secret %q: %w", key, grantErr)
		}

		known[name] = true
		res.Imported = append(res.Imported, key)
	}
	return res, nil
}

// legacyName maps a flat-store key onto the broker's name charset. Legacy
// keys are environment variable names, so the mapping is nearly always the
// identity; anything outside the charset becomes '-' so two distinct keys
// cannot silently collapse onto the same name without the operator noticing
// a duplicate-name error at import time.
func legacyName(key string) string {
	var b strings.Builder
	for _, r := range key {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := b.String()
	if out == "" {
		return "legacy-secret"
	}
	if len(out) > 128 {
		out = out[:128]
	}
	return out
}
