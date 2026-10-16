package deviceforward

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func testDevice() ForwardedDevice {
	return ForwardedDevice{Kind: KindUSB, USB: &executor.USBMatch{VendorID: "1050", ProductID: "0030"}}
}

func TestMintRedeemAuthenticate(t *testing.T) {
	store := newMemStore()
	token, rec, err := Mint(store, MintOptions{Name: "bench", Device: testDevice()})
	if err != nil {
		t.Fatal(err)
	}
	cred, fwd, err := Redeem(store, token, time.Now())
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if fwd.Name != "bench" || fwd.Device.Kind != KindUSB {
		t.Fatalf("forwarder record wrong: %+v", fwd)
	}
	if fwd.EnrollmentID != rec.ID {
		t.Fatalf("forwarder not linked to enrollment")
	}
	got, err := Authenticate(store, cred, time.Now())
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got.ForwarderID != fwd.ForwarderID {
		t.Fatalf("authenticated wrong forwarder")
	}
}

func TestRedeemIsSingleUse(t *testing.T) {
	store := newMemStore()
	token, _, _ := Mint(store, MintOptions{Name: "x", Device: testDevice()})
	const racers = 16
	var wg sync.WaitGroup
	wins := make(chan bool, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := Redeem(store, token, time.Now())
			wins <- err == nil
		}()
	}
	wg.Wait()
	close(wins)
	won := 0
	for w := range wins {
		if w {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("expected exactly one redemption to win, got %d", won)
	}
}

func TestRedeemRejectsExpiredAndRevoked(t *testing.T) {
	store := newMemStore()
	tok, rec, _ := Mint(store, MintOptions{Name: "x", Device: testDevice(), TTL: time.Minute})
	if _, _, err := Redeem(store, tok, rec.ExpiresAt.Add(time.Second)); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired: %v", err)
	}

	tok2, _, _ := Mint(store, MintOptions{Name: "y", Device: testDevice()})
	id, _, _ := decodeToken(enrollTokenPrefix, tok2)
	_ = store.RevokeEnrollment(id, time.Now())
	if _, _, err := Redeem(store, tok2, time.Now()); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked: %v", err)
	}
}

func TestRevokeEnrollmentRevokesForwarder(t *testing.T) {
	store := newMemStore()
	tok, rec, _ := Mint(store, MintOptions{Name: "x", Device: testDevice()})
	cred, fwd, _ := Redeem(store, tok, time.Now())
	kind, err := Revoke(store, rec.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if kind != "enrollment+forwarder" {
		t.Fatalf("kind = %q", kind)
	}
	if _, err := Authenticate(store, cred, time.Now()); !errors.Is(err, ErrRevoked) {
		t.Fatalf("credential should be revoked: %v", err)
	}
	_ = fwd
}

func TestAuthenticateRejectsForeignToken(t *testing.T) {
	store := newMemStore()
	// A well-formed credential string for an id that was never issued.
	if _, err := Authenticate(store, encodeToken(credentialPrefix, "nope", "secret"), time.Now()); err == nil {
		t.Fatal("expected authentication to fail for an unknown forwarder")
	}
	// A token with a broken MAC.
	if _, err := Authenticate(store, credentialPrefix+".a.b.deadbeef", time.Now()); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("broken MAC: %v", err)
	}
}

func TestBundleRoundTrip(t *testing.T) {
	store := newMemStore()
	enc, rec, err := MintBundle(store, MintOptions{
		Name: "bench", Device: testDevice(), Server: "wss://hub/api/forwarders/connect", Pin: "sha256:abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodeBundle(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if b.Server != "wss://hub/api/forwarders/connect" || b.Pin != "sha256:abc" || b.EnrollmentID != rec.ID {
		t.Fatalf("bundle fields wrong: %+v", b)
	}
	if b.Device.Kind != KindUSB {
		t.Fatalf("bundle device not carried")
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestMintRejectsBadDevice(t *testing.T) {
	store := newMemStore()
	if _, _, err := Mint(store, MintOptions{Name: "x", Device: ForwardedDevice{Kind: KindUSB}}); err == nil {
		t.Fatal("a usb forwarder with no USB match must be refused")
	}
	if _, _, err := Mint(store, MintOptions{Name: "x", Device: ForwardedDevice{Kind: "bogus"}}); err == nil {
		t.Fatal("an unknown device kind must be refused")
	}
}
