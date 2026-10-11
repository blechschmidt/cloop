package statedb

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// TestDeviceAuthorizationsRoundTripAndUpdateUnderTheLock covers the device
// table's accessors (Task 20412): an insert never replaces, the user-code
// lookup finds the newest row, an update that reports no change writes
// nothing, and concurrent decisions on one row serialise — the property an
// approval racing a denial, or two polls racing the exchange, depends on.
func TestDeviceAuthorizationsRoundTripAndUpdateUnderTheLock(t *testing.T) {
	db := openTestDB(t)
	at := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	row := DeviceAuthorizationRow{
		DeviceHash: "dev1", UserCodeHash: "uc1", CredentialHash: "sess1", Status: "pending",
		ClientIP: "198.51.100.20", ClientUserAgent: "cloop/test", ClientHostname: "laptop",
		CreatedAt: at, ExpiresAt: at.Add(10 * time.Minute), IntervalSeconds: 5,
	}
	if err := db.PutDeviceAuthorization(row); err != nil {
		t.Fatalf("PutDeviceAuthorization: %v", err)
	}
	if err := db.PutDeviceAuthorization(row); err == nil {
		t.Fatal("a second insert of the same device code was accepted")
	}
	got, err := db.GetDeviceAuthorization("dev1")
	if err != nil {
		t.Fatal(err)
	}
	if got.CredentialHash != "sess1" || got.ClientHostname != "laptop" || !got.ExpiresAt.Equal(row.ExpiresAt) || got.IntervalSeconds != 5 {
		t.Fatalf("round trip = %+v", got)
	}
	if _, err := db.GetDeviceAuthorization("nope"); !errors.Is(err, ErrDeviceAuthorizationNotFound) {
		t.Fatalf("unknown code: %v", err)
	}

	// A later row drawn with the same user code wins the lookup.
	newer := row
	newer.DeviceHash, newer.CreatedAt, newer.ExpiresAt = "dev2", at.Add(time.Minute), at.Add(11*time.Minute)
	if err := db.PutDeviceAuthorization(newer); err != nil {
		t.Fatal(err)
	}
	if got, err := db.GetDeviceAuthorizationByUserCode("uc1"); err != nil || got.DeviceHash != "dev2" {
		t.Fatalf("by user code = %+v, %v; want the newest", got, err)
	}

	// No change, no write.
	if _, err := db.UpdateDeviceAuthorization("dev1", func(r *DeviceAuthorizationRow) (bool, error) {
		r.Status = "denied"
		return false, nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetDeviceAuthorization("dev1"); got.Status != "pending" {
		t.Fatalf("an update reporting no change wrote %q", got.Status)
	}

	// Ten goroutines race to decide the same code; exactly one may.
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
	)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := db.UpdateDeviceAuthorization("dev1", func(r *DeviceAuthorizationRow) (bool, error) {
				if r.Status != "pending" {
					return false, errors.New("decided")
				}
				r.Status = "approved"
				return true, nil
			})
			if err == nil {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("%d goroutines decided one code; a code is decided once", winners)
	}
	if _, err := db.UpdateDeviceAuthorization("missing", func(*DeviceAuthorizationRow) (bool, error) {
		return true, nil
	}); !errors.Is(err, ErrDeviceAuthorizationNotFound) {
		t.Fatalf("updating a missing row: %v", err)
	}

	if n, err := db.CountDeviceAuthorizations(at.Add(-time.Second)); err != nil || n != 2 {
		t.Fatalf("CountDeviceAuthorizations = %d, %v", n, err)
	}
	gone, err := db.DeleteDeviceAuthorizationsBefore(at.Add(10 * time.Minute))
	if err != nil || len(gone) != 1 || gone[0].DeviceHash != "dev1" {
		t.Fatalf("sweep = %+v, %v; want the one that expired", gone, err)
	}
	if _, err := db.GetDeviceAuthorization("dev2"); err != nil {
		t.Fatalf("the sweep removed an unexpired row: %v", err)
	}
}

// TestSessionsSweepEachKindOnItsOwnIdleClock: a terminal session idles out on
// its own, shorter clock, and a browser session beside it on the browser's.
func TestSessionsSweepEachKindOnItsOwnIdleClock(t *testing.T) {
	db := openTestDB(t)
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	put := func(id, kind string, lastSeen time.Time) {
		t.Helper()
		if err := db.PutSession(SessionRow{
			ID: id, Subject: "s", Kind: kind, Client: "laptop",
			IssuedAt: lastSeen, LastSeen: lastSeen, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	put("browser-2h", "", now.Add(-2*time.Hour))
	put("cli-2h", SessionKindCLI, now.Add(-2*time.Hour))
	put("cli-fresh", SessionKindCLI, now.Add(-time.Minute))

	got, err := db.GetSession("browser-2h")
	if err != nil || got.Kind != SessionKindBrowser {
		t.Fatalf("a session written without a kind reads back as %q, %v; want browser", got.Kind, err)
	}
	if got, _ := db.GetSession("cli-2h"); got.Kind != SessionKindCLI || got.Client != "laptop" {
		t.Fatalf("cli row = %+v", got)
	}

	c := SessionCutoffs{Absolute: now, Idle: now.Add(-8 * time.Hour), CLIIdle: now.Add(-time.Hour)}
	if n, err := db.CountLiveSessions(c); err != nil || n != 2 {
		t.Fatalf("CountLiveSessions = %d, %v; want the browser and the fresh terminal", n, err)
	}
	gone, err := db.DeleteExpiredSessions(c)
	if err != nil || len(gone) != 1 || gone[0].ID != "cli-2h" {
		t.Fatalf("sweep removed %+v, %v; want only the idle terminal", gone, err)
	}
}
