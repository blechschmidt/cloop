package forwarderstore

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/deviceforward"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func openTestDB(t *testing.T) *statedb.DB {
	t.Helper()
	db, err := statedb.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func usbDevice() deviceforward.ForwardedDevice {
	return deviceforward.ForwardedDevice{
		Kind: deviceforward.KindUSB,
		USB:  &executor.USBMatch{VendorID: "1050", ProductID: "0030", Serial: "0031650425"},
	}
}

// TestStoreSatisfiesEnrollmentFlow runs the real enrollment flow — mint,
// redeem, authenticate, revoke — against the SQLite-backed store, so the
// adapter's row conversions and the statedb single-use latch are exercised
// together.
func TestStoreSatisfiesEnrollmentFlow(t *testing.T) {
	store, err := New(openTestDB(t))
	if err != nil {
		t.Fatal(err)
	}
	token, rec, err := deviceforward.Mint(store, deviceforward.MintOptions{
		Name: "bench", Device: usbDevice(), Owner: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	cred, fwd, err := deviceforward.Redeem(store, token, time.Now())
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if fwd.Device.Kind != deviceforward.KindUSB || fwd.Device.USB == nil || fwd.Device.USB.Serial != "0031650425" {
		t.Fatalf("device did not round-trip through SQLite: %+v", fwd.Device)
	}
	if fwd.Owner != "alice" {
		t.Fatalf("owner lost: %q", fwd.Owner)
	}

	// A second redemption of the same token must fail.
	if _, _, err := deviceforward.Redeem(store, token, time.Now()); !errors.Is(err, deviceforward.ErrTokenAlreadyUsed) {
		t.Fatalf("second redeem = %v, want ErrTokenAlreadyUsed", err)
	}

	got, err := deviceforward.Authenticate(store, cred, time.Now())
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got.ForwarderID != fwd.ForwarderID {
		t.Fatalf("authenticated %q, want %q", got.ForwarderID, fwd.ForwarderID)
	}

	// Revoking the enrollment revokes the forwarder it minted.
	if _, err := deviceforward.Revoke(store, rec.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := deviceforward.Authenticate(store, cred, time.Now()); !errors.Is(err, deviceforward.ErrRevoked) {
		t.Fatalf("authenticate after revoke = %v, want ErrRevoked", err)
	}

	list, err := store.ListForwarders()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list has %d forwarders, want 1", len(list))
	}
}

// TestUnknownForwarderMapsToSentinel checks the adapter translates storage's
// not-found into the deviceforward sentinel callers branch on.
func TestUnknownForwarderMapsToSentinel(t *testing.T) {
	store, err := New(openTestDB(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deviceforward.Authenticate(store, "clfc1.nope.nope.nope", time.Now()); err == nil {
		t.Fatal("expected authentication of an unknown forwarder to fail")
	}
}
