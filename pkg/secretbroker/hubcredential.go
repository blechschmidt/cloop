package secretbroker

// The credentials the hub presents as itself (Task 20426).
//
// Everything else in this package delivers a credential to a workload, through
// a grant, a lease and the constraints both carry. A few credentials are not
// for a workload at all: the hub holds them to talk to something on its own
// behalf. The first are an audit sink's — the token a Splunk HTTP Event
// Collector demands, the private key of the client certificate a syslog
// receiver asks for — and keeping them in the secret store rather than in
// config.yaml is the point: the file is read by every command, copied into
// backups and diffed in reviews, while a stored secret is sealed under the
// hub's root key and audited where it is minted, granted and deleted.
//
// What the hub may open this way is deliberately narrow. An env secret, whose
// payload is a value or a set of named values and nothing the broker would
// otherwise rewrite before delivery; and a registry secret in the Docker
// configuration form, the logins a Kubernetes executor resolves image tags
// with (Task 20457), each of which names the registry it is for. Only a shared
// one: a personal secret belongs to the person who stored it, and the hub
// presenting it to a collector or a registry on the organisation's behalf would
// be spending it for them — the one act the ownership model forbids even an
// administrator.

import (
	"fmt"
	"sort"
	"strings"
)

// HubCredential opens a shared env secret the hub presents as itself.
//
// ref is "name" for a secret holding one value — a bare value, or an env
// object with one key — or "name#KEY" for one key of an object holding
// several. The caller owns the returned bytes and should zero them once the
// credential is in use.
func (b *Broker) HubCredential(ref string) ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("%w: no broker", ErrSecretNotFound)
	}
	name, key, keyed := strings.Cut(strings.TrimSpace(ref), "#")
	sec, err := b.DescribeSecret(name)
	if err != nil {
		return nil, err
	}
	// Before the envelope is opened, so a refusal costs no decryption.
	if sec.Personal() {
		return nil, fmt.Errorf("%w: %s belongs to %s, and the hub presents only shared secrets as itself; "+
			"store the credential as a shared secret", ErrNotOwner, sec.Name, sec.Owner)
	}
	if sec.Kind != KindEnv {
		return nil, fmt.Errorf("%w: %s is a %s secret; a credential the hub presents is stored as an env secret "+
			"(cloop secret mint --kind env)", ErrInvalidKind, sec.Name, sec.Kind)
	}
	return b.openEnvValue(sec, key, keyed)
}

// openEnvValue opens an env secret and returns the one value ref named: the
// value under key when keyed, else the secret's only value.
func (b *Broker) openEnvValue(sec Secret, key string, keyed bool) ([]byte, error) {
	plaintext, err := b.seal.OpenEnvelope(AADFor(SetSecrets, sec.ID), sec.Envelope())
	if err != nil {
		return nil, fmt.Errorf("%w: open payload for %s: %w", ErrSealFailed, sec.Name, err)
	}
	defer zero(plaintext)
	env := jsonUnmarshalEnv(plaintext, sec.Name)
	// The values are Go strings and cannot be zeroed; dropping the map's
	// references leaves them to the collector, as envKeyNames does.
	defer clear(env)

	if keyed {
		v, ok := env[key]
		if !ok {
			return nil, fmt.Errorf("%w: %s defines no key %q", ErrSecretNotFound, sec.Name, key)
		}
		return []byte(v), nil
	}
	if len(env) != 1 {
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return nil, fmt.Errorf("%w: %s holds %d values (%s); name the one to present as %s#KEY",
			ErrInvalidSecret, sec.Name, len(env), strings.Join(keys, ", "), sec.Name)
	}
	for _, v := range env {
		return []byte(v), nil
	}
	return nil, fmt.Errorf("%w: %s is empty", ErrInvalidSecret, sec.Name)
}

// HubRegistryConfig opens a shared registry secret the hub signs in to
// registries with as itself: the logins a Kubernetes executor resolves the tags
// of the images its Pods would carry with, and fetches their signatures with
// (executors.kubernetes.registry_secret, Task 20457).
//
// It is a hub credential and not a grant for the reason the audit sink's are:
// nothing here is delivered to a workload. A registry secret granted to the
// executor instead would be — a grant to executor:<id> is leased to every run on
// it — and would put a login able to read, or push to, the operator's private
// repositories into every Pod.
//
// Only the Docker-configuration form ({"auths": {...}}, what `docker login`
// writes) is opened, because it names the registry each login is for and so
// bounds where the hub presents it. The bare user:password form names no
// registry — a grant's allowlist supplies one when it is delivered — and a hub
// resolving whatever registry a project's reference names must never be left
// to guess which of them a password belongs to. The caller owns the returned
// bytes and should zero them once parsed.
func (b *Broker) HubRegistryConfig(ref string) ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("%w: no broker", ErrSecretNotFound)
	}
	sec, err := b.DescribeSecret(strings.TrimSpace(ref))
	if err != nil {
		return nil, err
	}
	if sec.Personal() {
		return nil, fmt.Errorf("%w: %s belongs to %s, and the hub signs in to registries only with shared secrets; "+
			"store the login as a shared secret", ErrNotOwner, sec.Name, sec.Owner)
	}
	if sec.Kind != KindRegistry {
		return nil, fmt.Errorf("%w: %s is a %s secret; a registry login the hub uses is stored as a registry secret "+
			"(cloop secret mint <name> --kind registry --file config.json)", ErrInvalidKind, sec.Name, sec.Kind)
	}
	plaintext, err := b.seal.OpenEnvelope(AADFor(SetSecrets, sec.ID), sec.Envelope())
	if err != nil {
		return nil, fmt.Errorf("%w: open payload for %s: %w", ErrSealFailed, sec.Name, err)
	}
	if trimmed := strings.TrimSpace(string(plaintext)); !strings.HasPrefix(trimmed, "{") {
		zero(plaintext)
		return nil, fmt.Errorf("%w: %s holds a bare user:password, which names no registry; store the login as "+
			"the config.json `docker login` writes, whose \"auths\" name the registry each login is for",
			ErrInvalidSecret, sec.Name)
	}
	return plaintext, nil
}

// SourceCredential opens the credential a knowledge source signs in to its
// remote with (Task 20467): ref is the source's secret reference, in
// HubCredential's "name" or "name#KEY" form, and owner the source's owner —
// empty for an organisation source.
//
// The hub uses it for the source, on the hub, to list and fetch documents; it
// is never granted, leased or handed to an executor. Who the hub may sign in
// as follows the ownership model: an organisation source signs in with a
// shared secret, exactly as HubCredential allows, and a personal source with
// a personal secret its owner owns — the hub reading its owner's pages on its
// owner's behalf, which is the one way that person's credential is spent. A
// personal source never signs in with a shared secret: the person who
// connected it could then publish whatever the organisation's account reads
// into the projects they bind it to.
func (b *Broker) SourceCredential(ref, owner string) ([]byte, error) {
	sec, key, keyed, err := b.sourceSecret(ref, owner)
	if err != nil {
		return nil, err
	}
	return b.openEnvValue(sec, key, keyed)
}

// CheckSourceCredential is SourceCredential without opening anything: whether
// ref names a secret the source of that owner may sign in with. A key named
// by "name#KEY" is checked only when the value is opened, since checking it
// here would mean decrypting the secret to answer a question about its shape.
func (b *Broker) CheckSourceCredential(ref, owner string) error {
	_, _, _, err := b.sourceSecret(ref, owner)
	return err
}

// sourceSecret resolves a knowledge source's secret reference and applies the
// ownership rule SourceCredential documents.
func (b *Broker) sourceSecret(ref, owner string) (Secret, string, bool, error) {
	if b == nil {
		return Secret{}, "", false, fmt.Errorf("%w: no broker", ErrSecretNotFound)
	}
	name, key, keyed := strings.Cut(strings.TrimSpace(ref), "#")
	if name == "" || (keyed && key == "") {
		return Secret{}, "", false, fmt.Errorf("%w: a secret reference is a name, or name#KEY", ErrInvalidSecret)
	}
	sec, err := b.DescribeSecret(name)
	if err != nil {
		return Secret{}, "", false, err
	}
	owner = NormalizeOwner(owner)
	switch {
	case owner == "" && sec.Personal():
		return Secret{}, "", false, fmt.Errorf("%w: %s belongs to %s, and an organisation source signs in only "+
			"with shared secrets", ErrNotOwner, sec.Name, sec.Owner)
	case owner != "" && !sec.Personal():
		return Secret{}, "", false, fmt.Errorf("%w: %s is a shared secret, and a personal source signs in only "+
			"with its owner's own secrets", ErrNotOwner, sec.Name)
	case owner != "" && !sec.SpendableBy(Viewer{Identity: owner}):
		// Named as not found: someone else's personal secret is not one this
		// owner may learn exists.
		return Secret{}, "", false, fmt.Errorf("%w: %q", ErrSecretNotFound, name)
	}
	if sec.Kind != KindEnv {
		return Secret{}, "", false, fmt.Errorf("%w: %s is a %s secret; a source signs in with an env secret "+
			"(cloop secret mint --kind env)", ErrInvalidKind, sec.Name, sec.Kind)
	}
	return sec, key, keyed, nil
}
