package cmd

// The hub's key-management service at startup (Task 20433).
//
// A hub whose secrets section names a KMS reaches it before it serves anything:
// it builds the providers, waits up to secrets.kms.startup_timeout for each to
// answer healthy — a plugin sidecar starting beside the hub needs a few
// seconds — and refuses to start when one does not, naming the KMS and what it
// said. It never starts on something else instead: a KMS configured and
// unreachable is an error, not a reason to seal under CLOOP_SECRET_KEY.

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/rootkey"
)

// resolveHubRoots builds this hub's roots from its secrets section and root
// key, and — when a KMS is among them — waits for it to answer. The caller
// closes what it returns.
func resolveHubRoots(ctx context.Context, cfg *config.Config, keys rootkey.Roots) (kms.Roots, error) {
	var sc config.SecretsConfig
	if cfg != nil {
		sc = cfg.Secrets
	}
	roots, err := kms.Resolve(sc, keys)
	if err != nil {
		return kms.Roots{}, fmt.Errorf("the secrets section: %w", err)
	}
	if !roots.UsesKMS() {
		return roots, nil
	}
	wait := sc.KMS.EffectiveStartupTimeout()
	if sc.KMSPrevious.Configured() && sc.KMSPrevious.EffectiveStartupTimeout() > wait {
		wait = sc.KMSPrevious.EffectiveStartupTimeout()
	}
	start := time.Now()
	statuses, err := kms.AwaitReady(ctx, roots.Providers, wait, func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "Waiting for the KMS: "+format+"\n", args...)
	})
	if err != nil {
		roots.Close()
		return kms.Roots{}, fmt.Errorf("refusing to open the secret store: the key-management service did not "+
			"answer within %s: %w — the sealing keys are held by it and open with nothing else; `cloop hub "+
			"doctor` checks it (secrets.kms)", wait.Round(time.Second), err)
	}
	for i, p := range roots.Providers {
		fmt.Printf("KMS: %s, %s, key %s (answered in %s)\n", p.Name(), p.Describe(), statuses[i].KeyID,
			time.Since(start).Round(time.Millisecond))
	}
	return roots, nil
}
