package sessionstore

import (
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// TestCLISessionKindSurvivesTheStore: a terminal session written through the
// store reads back as one, with its client, and is swept on the terminal's own
// idle clock (Task 20412). A kind lost in translation would make the session
// a browser session — authenticated by cookie, idling on the browser's clock.
func TestCLISessionKindSurvivesTheStore(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, "test-passphrase")
	store, _ := newTestStore(t, t.TempDir())
	now := time.Now().UTC()

	cli := sampleRecord("cli-session", now)
	cli.Kind, cli.Client = oidcauth.SessionKindCLI, "dev-laptop"
	cli.LastSeen = now.Add(-2 * time.Hour)
	browser := sampleRecord("browser-session", now)
	browser.LastSeen = now.Add(-2 * time.Hour)
	for _, rec := range []oidcauth.SessionRecord{cli, browser} {
		if err := store.Put(rec); err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.Get("cli-session")
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsCLI() || got.Client != "dev-laptop" || got.RefreshToken == "" {
		t.Fatalf("cli session read back as %+v", got)
	}
	if b, _ := store.Get("browser-session"); b.IsCLI() || b.KindName() != "browser" {
		t.Fatalf("browser session read back as kind %q", b.KindName())
	}

	gone, err := store.DeleteExpired(oidcauth.ExpiryCutoffs{
		Absolute: now, Idle: now.Add(-8 * time.Hour), CLIIdle: now.Add(-time.Hour),
	})
	if err != nil || len(gone) != 1 || gone[0].ID != "cli-session" || !gone[0].IsCLI() {
		t.Fatalf("sweep removed %+v, %v; want the idle terminal session", gone, err)
	}
}

// TestDeviceStoreRoundTrip: the device half of the store, as oidcauth uses it.
func TestDeviceStoreRoundTrip(t *testing.T) {
	store, _ := newTestStore(t, t.TempDir())
	var ds oidcauth.DeviceStore = store
	now := time.Now().UTC().Truncate(time.Second)
	rec := oidcauth.DeviceRecord{
		DeviceHash: "dh", UserCodeHash: "uh", CredentialHash: "sh", Status: oidcauth.DeviceStatusPending,
		ClientIP: "198.51.100.20", ClientHostname: "laptop", ClientUserAgent: "cloop/test",
		CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Interval: 5 * time.Second,
	}
	if err := ds.PutDevice(rec); err != nil {
		t.Fatal(err)
	}
	if _, err := ds.GetDevice("missing"); !errors.Is(err, oidcauth.ErrDeviceNotFound) {
		t.Fatalf("missing device: %v, want oidcauth.ErrDeviceNotFound", err)
	}
	got, err := ds.GetDeviceByUserCode("uh")
	if err != nil || got.CredentialHash != "sh" || got.Interval != 5*time.Second || !got.ExpiresAt.Equal(rec.ExpiresAt) {
		t.Fatalf("by user code = %+v, %v", got, err)
	}
	after, err := ds.UpdateDevice("dh", func(d *oidcauth.DeviceRecord) (bool, error) {
		d.Status, d.Approver, d.DecidedAt = oidcauth.DeviceStatusApproved, "alice@example.com", now
		d.Interval += 5 * time.Second
		return true, nil
	})
	if err != nil || after.Status != oidcauth.DeviceStatusApproved || after.Interval != 10*time.Second {
		t.Fatalf("update = %+v, %v", after, err)
	}
	if again, _ := ds.GetDevice("dh"); again.Approver != "alice@example.com" || !again.DecidedAt.Equal(now) {
		t.Fatalf("the update did not persist: %+v", again)
	}
	if n, err := ds.CountDevicesSince(now.Add(-time.Minute)); err != nil || n != 1 {
		t.Fatalf("CountDevicesSince = %d, %v", n, err)
	}
	if gone, err := ds.DeleteDevicesBefore(now.Add(time.Hour)); err != nil || len(gone) != 1 {
		t.Fatalf("DeleteDevicesBefore = %+v, %v", gone, err)
	}
}
