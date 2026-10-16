package kms_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/kms/kmstest"
	"github.com/blechschmidt/cloop/pkg/rootkey"
)

func keysOf(current, previous string) rootkey.Roots {
	var r rootkey.Roots
	if current != "" {
		r.Current = rootkey.Root{Value: current, Source: rootkey.SourceEnvironment, Variable: rootkey.EnvKey}
	}
	if previous != "" {
		r.Previous = rootkey.Root{Value: previous, Source: rootkey.SourceEnvironment, Variable: rootkey.EnvPrevious}
	}
	return r
}

// The secrets section and the root key decide the keyring's roots exactly as
// config/secrets.go documents, and every way the two can name a previous root
// twice is refused.
func TestResolveRoots(t *testing.T) {
	p := kmstest.StartPlugin(t)
	k := pluginConfig(p, "")
	other := pluginConfig(p, "")
	other.Name = "the-old-kms"

	cases := []struct {
		name     string
		sc       config.SecretsConfig
		keys     rootkey.Roots
		current  string // "kms", "pass", "none"
		previous string // "", "kms", "pass", "prev"
		err      string
	}{
		{name: "passphrase only", keys: keysOf("cur", ""), current: "pass"},
		{name: "a change of passphrase", keys: keysOf("cur", "old"), current: "pass", previous: "prev"},
		{name: "no key at all", current: "none"},
		{name: "kms only", sc: config.SecretsConfig{KMS: k}, keys: keysOf("cur", ""), current: "kms"},
		{name: "kms with no passphrase", sc: config.SecretsConfig{KMS: k}, current: "kms"},
		{name: "onto a kms", sc: config.SecretsConfig{KMS: k, PreviousRoot: "passphrase"}, keys: keysOf("cur", ""),
			current: "kms", previous: "pass"},
		{name: "off a kms", sc: config.SecretsConfig{KMSPrevious: k}, keys: keysOf("cur", ""), current: "pass", previous: "kms"},
		{name: "kms to kms", sc: config.SecretsConfig{KMS: k, KMSPrevious: other}, current: "kms", previous: "kms"},
		{name: "onto a kms without the passphrase", sc: config.SecretsConfig{KMS: k, PreviousRoot: "passphrase"},
			err: "not configured here"},
		{name: "onto a kms mid passphrase change", sc: config.SecretsConfig{KMS: k, PreviousRoot: "passphrase"},
			keys: keysOf("cur", "old"), err: "both name a previous root"},
		{name: "a previous passphrase beside a kms", sc: config.SecretsConfig{KMS: k}, keys: keysOf("cur", "old"),
			err: "secrets.previous_root: passphrase"},
		{name: "kms_previous mid passphrase change", sc: config.SecretsConfig{KMSPrevious: k}, keys: keysOf("cur", "old"),
			err: "both name a previous root"},
		{name: "previous_root without a kms", sc: config.SecretsConfig{PreviousRoot: "passphrase"}, keys: keysOf("cur", ""),
			err: "no secrets.kms is configured"},
		{name: "two previous roots", sc: config.SecretsConfig{KMS: k, KMSPrevious: other, PreviousRoot: "passphrase"},
			keys: keysOf("cur", ""), err: "both name a previous root"},
		{name: "two kms of one name", sc: config.SecretsConfig{KMS: k, KMSPrevious: k}, err: "both named"},
		{name: "a bad previous_root", sc: config.SecretsConfig{KMS: k, PreviousRoot: "kms"}, err: "must be"},
		{name: "settings without a provider", sc: config.SecretsConfig{KMS: config.KMSConfig{Name: "x"}},
			err: "no provider"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			roots, err := kms.Resolve(tc.sc, tc.keys)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want one saying %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer roots.Close()
			kind := func(r interface {
				IsKMS() bool
				IsZero() bool
			}) string {
				switch {
				case r.IsKMS():
					return "kms"
				case r.IsZero():
					return "none"
				}
				return "pass"
			}
			if got := kind(roots.Current); got != tc.current {
				t.Errorf("current = %s, want %s", got, tc.current)
			}
			wantPrev := tc.previous
			if wantPrev == "prev" {
				wantPrev = "pass"
				if roots.Previous.Passphrase != "old" {
					t.Errorf("previous passphrase = %q, want CLOOP_SECRET_KEY_PREVIOUS", roots.Previous.Passphrase)
				}
			}
			if wantPrev == "pass" && tc.previous == "pass" && roots.Previous.Passphrase != "cur" {
				t.Errorf("previous passphrase = %q, want CLOOP_SECRET_KEY", roots.Previous.Passphrase)
			}
			got := kind(roots.Previous)
			if got == "none" {
				got = ""
			}
			if got != wantPrev {
				t.Errorf("previous = %q, want %q", got, wantPrev)
			}
		})
	}
}

// AwaitReady waits out a plugin that is still starting, and refuses with the
// KMS's own reason when it never answers.
func TestAwaitReady(t *testing.T) {
	p := kmstest.StartPlugin(t)
	prov := openPlugin(t, p, "200ms")
	p.Stop()
	go func() {
		time.Sleep(400 * time.Millisecond)
		_ = p.Restart()
	}()
	var logged []string
	sts, err := kms.AwaitReady(context.Background(), []kms.Provider{prov}, 10*time.Second,
		func(f string, a ...any) { logged = append(logged, f) })
	if err != nil {
		t.Fatalf("a plugin that came up within the wait: %v", err)
	}
	if len(sts) != 1 || !sts[0].Healthy || sts[0].KeyID != "key-1" {
		t.Fatalf("statuses = %+v", sts)
	}
	if len(logged) == 0 {
		t.Error("nothing said what was being waited for")
	}

	p.Stop()
	start := time.Now()
	_, err = kms.AwaitReady(context.Background(), []kms.Provider{prov}, 600*time.Millisecond, nil)
	if err == nil || !kms.Unreachable(err) || !strings.Contains(err.Error(), p.Socket()) {
		t.Fatalf("a plugin that never came up: %v", err)
	}
	if took := time.Since(start); took > 3*time.Second || took < 600*time.Millisecond {
		t.Fatalf("waiting 600ms took %s: the whole wait is used, and no more", took)
	}

	// A plugin that comes up late in the wait — after the point where the
	// next doubled backoff would overshoot it — is still found.
	go func() {
		time.Sleep(2500 * time.Millisecond)
		_ = p.Restart()
	}()
	if _, err := kms.AwaitReady(context.Background(), []kms.Provider{prov}, 3*time.Second, nil); err != nil {
		t.Fatalf("a plugin up in the last half second of the wait: %v", err)
	}
}
