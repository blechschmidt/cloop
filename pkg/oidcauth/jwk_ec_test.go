package oidcauth

// The EC branch of parseJWK stopped using elliptic.Curve.IsOnCurve and
// ecdsa.PublicKey's raw X and Y fields in Task 20411, when staticcheck's SA1019
// began gating CI. Parsing a signing key is the one place an identity provider's
// published material becomes something this hub trusts, so the replacement must
// accept and refuse exactly what the old check did — no more, no less.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
)

// ecTestKey generates a P-256 key and returns its 32-byte coordinates, read
// through the encoding rather than the deprecated fields. want, if not nil, is a
// predicate the coordinates must satisfy, for the encodings a random key rarely
// produces.
func ecTestKey(t *testing.T, want func(x, y []byte) bool) (*ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	for i := 0; i < 1<<14; i++ {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := priv.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		x, y := raw[1:33], raw[33:65]
		if want == nil || want(x, y) {
			return priv, x, y
		}
	}
	t.Fatal("no key with the wanted coordinates in 16384 tries")
	return nil, nil, nil
}

func ecJWKOf(x, y []byte) jwk {
	return jwk{Kty: "EC", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(x), Y: base64.RawURLEncoding.EncodeToString(y)}
}

// A key parses to the same public key in every width the parser has accepted:
// the RFC's 32 bytes, a coordinate whose leading zero byte an issuer dropped,
// and one padded with extra zeros. And the parsed key verifies its signatures.
func TestParseJWKECKeyInEveryAcceptedWidth(t *testing.T) {
	short := func(x, _ []byte) bool { return x[0] == 0 }
	for name, tc := range map[string]struct {
		want   func(x, y []byte) bool
		encode func(x, y []byte) ([]byte, []byte)
	}{
		"32-byte coordinates": {nil, func(x, y []byte) ([]byte, []byte) { return x, y }},
		"x without its leading zero byte": {short, func(x, y []byte) ([]byte, []byte) {
			return bytes.TrimLeft(x, "\x00"), y
		}},
		"y padded to 34 bytes": {nil, func(x, y []byte) ([]byte, []byte) {
			return x, append([]byte{0, 0}, y...)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			priv, x, y := ecTestKey(t, tc.want)
			got, err := parseJWK(ecJWKOf(tc.encode(x, y)))
			if err != nil {
				t.Fatalf("parseJWK refused a valid key: %v", err)
			}
			pub, ok := got.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("parseJWK returned %T, want *ecdsa.PublicKey", got)
			}
			if !pub.Equal(&priv.PublicKey) {
				t.Fatal("parseJWK returned a different key")
			}
			digest := sha256.Sum256([]byte("header.payload"))
			sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			if !ecdsa.VerifyASN1(pub, digest[:], sig) {
				t.Fatal("the parsed key does not verify its own signature")
			}
		})
	}
}

// The replacement agrees with the check it replaced on every input, valid or
// not: the same points re-encoded, points nudged off the curve, coordinates
// too wide for it, and degenerate ones.
func TestParseJWKECAgreesWithTheCheckItReplaced(t *testing.T) {
	oldAccepts := func(x, y []byte) bool {
		//nolint:staticcheck // SA1019: IsOnCurve is the check p256PublicKey replaced, kept here as its oracle.
		return elliptic.P256().IsOnCurve(new(big.Int).SetBytes(x), new(big.Int).SetBytes(y))
	}
	p := elliptic.P256().Params().P
	inc := func(b []byte) []byte { return new(big.Int).Add(new(big.Int).SetBytes(b), big.NewInt(1)).Bytes() }
	neg := func(b []byte) []byte { return new(big.Int).Sub(p, new(big.Int).SetBytes(b)).Bytes() }
	ff := bytes.Repeat([]byte{0xff}, 32)

	accepted, refused := 0, 0
	for i := 0; i < 64; i++ {
		_, x, y := ecTestKey(t, nil)
		for name, c := range map[string][2][]byte{
			"the point":              {x, y},
			"its negation":           {x, neg(y)},
			"x padded with a zero":   {append([]byte{0}, x...), y},
			"y off by one":           {x, inc(y)},
			"x off by one":           {inc(x), y},
			"coordinates swapped":    {y, x},
			"x with a byte appended": {append(append([]byte{}, x...), 1), y},
			"x one byte too wide":    {append([]byte{1}, x...), y},
			"x all ones":             {ff, y},
			"x empty":                {nil, y},
			"y empty":                {x, nil},
			"both empty":             {nil, nil},
		} {
			want := oldAccepts(c[0], c[1])
			_, err := parseJWK(ecJWKOf(c[0], c[1]))
			if got := err == nil; got != want {
				t.Fatalf("%s: the old check said accept=%v, parseJWK says accept=%v (err %v)", name, want, got, err)
			}
			if want {
				accepted++
				continue
			}
			refused++
			if err.Error() != "jwk EC point is not on P-256" {
				t.Errorf("%s: refusal reads %q, want %q as before", name, err, "jwk EC point is not on P-256")
			}
		}
	}
	if accepted == 0 || refused == 0 {
		t.Fatalf("the cases exercised only one verdict (%d accepted, %d refused)", accepted, refused)
	}
}
