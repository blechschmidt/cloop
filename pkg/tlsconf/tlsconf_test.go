package tlsconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Protocol parameters
// ---------------------------------------------------------------------------

func TestParseMinVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    uint16
		wantErr bool
	}{
		{"", tls.VersionTLS12, false},
		{"1.2", tls.VersionTLS12, false},
		{"tls1.2", tls.VersionTLS12, false},
		{"TLS1.2", tls.VersionTLS12, false},
		{"1.3", tls.VersionTLS13, false},
		{"tls1.3", tls.VersionTLS13, false},
		{" 1.3 ", tls.VersionTLS13, false},
		// The whole point of this function: obsolete versions are rejected at
		// startup, not accepted with a warning nobody reads.
		{"1.0", 0, true},
		{"1.1", 0, true},
		{"tls1.0", 0, true},
		{"2.0", 0, true},
		{"garbage", 0, true},
	}
	for _, c := range cases {
		got, err := ParseMinVersion(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseMinVersion(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseMinVersion(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseMinVersion(%q) = %#x, want %#x", c.in, got, c.want)
		}
	}
}

// TestCipherSuitesAreModern asserts the offered TLS 1.2 suites are all AEAD
// with forward secrecy. Go still supports CBC and static-RSA suites for
// compatibility, and a config that quietly picks them up is the difference
// between "we do TLS" and "we do TLS that survives a scan".
func TestCipherSuitesAreModern(t *testing.T) {
	t.Parallel()
	byID := make(map[uint16]*tls.CipherSuite)
	for _, cs := range tls.CipherSuites() {
		byID[cs.ID] = cs
	}
	for _, id := range CipherSuites() {
		cs, ok := byID[id]
		if !ok {
			// tls.CipherSuites() lists only the suites Go considers secure;
			// tls.InsecureCipherSuites() has the rest. Absence here means we
			// listed one from the insecure set.
			t.Errorf("cipher suite %#x is not in tls.CipherSuites() (Go classifies it as insecure)", id)
			continue
		}
		name := cs.Name
		if !strings.Contains(name, "ECDHE") {
			t.Errorf("%s has no forward secrecy", name)
		}
		if !strings.Contains(name, "GCM") && !strings.Contains(name, "CHACHA20") {
			t.Errorf("%s is not an AEAD suite", name)
		}
		if strings.Contains(name, "CBC") || strings.Contains(name, "RC4") || strings.Contains(name, "3DES") {
			t.Errorf("%s uses a broken construction", name)
		}
	}
}

func TestServerConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	if _, err := GenerateSelfSigned(cert, key, SelfSignedOptions{}); err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	cfg, err := ServerConfig(cert, key, "")
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS 1.2", cfg.MinVersion)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates = %d, want 1", len(cfg.Certificates))
	}
	if len(cfg.CipherSuites) == 0 {
		t.Error("CipherSuites is empty; the modern list was not applied")
	}
	// A server tls.Config must never carry InsecureSkipVerify: on a server it
	// governs client-certificate verification, and silently disabling that is
	// how an mTLS deployment ends up not doing mTLS.
	if cfg.InsecureSkipVerify {
		t.Error("ServerConfig set InsecureSkipVerify")
	}

	if _, err := ServerConfig(cert, "", ""); err == nil {
		t.Error("ServerConfig with no key: want error, got nil")
	}
	if _, err := ServerConfig("", key, ""); err == nil {
		t.Error("ServerConfig with no certificate: want error, got nil")
	}
	if _, err := ServerConfig(cert, key, "1.0"); err == nil {
		t.Error("ServerConfig with TLS 1.0: want error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Self-signed generation
// ---------------------------------------------------------------------------

func TestGenerateSelfSigned(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "sub", "cert.pem")
	keyPath := filepath.Join(dir, "sub", "key.pem")

	pin, err := GenerateSelfSigned(certPath, keyPath, SelfSignedOptions{
		Hosts:    []string{"hub.test", "127.0.0.1"},
		ValidFor: 48 * time.Hour,
	})
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	if !strings.HasPrefix(pin, PinPrefix) {
		t.Errorf("pin %q has no %q prefix", pin, PinPrefix)
	}

	// The key must be owner-only from the moment it exists. A key that is
	// briefly 0644 is a key an attacker with a loop can read.
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("stat key: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != KeyFileMode {
			t.Errorf("key mode = %#o, want %#o", perm, KeyFileMode)
		}
		if warn := CheckKeyPermissions(keyPath); warn != "" {
			t.Errorf("CheckKeyPermissions flagged a freshly written key: %s", warn)
		}
	}

	// The pin the command printed must be the pin of the certificate on disk,
	// or every operator who copies it is pinning to nothing.
	fromFile, err := PinFromCertFile(certPath)
	if err != nil {
		t.Fatalf("PinFromCertFile: %v", err)
	}
	if fromFile != pin {
		t.Errorf("PinFromCertFile = %s, returned pin = %s", fromFile, pin)
	}

	// The pair must actually load together.
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("generated pair does not load: %v", err)
	}

	leaf := parseCertFile(t, certPath)
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "hub.test" {
		t.Errorf("DNSNames = %v, want [hub.test]", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("IPAddresses = %v, want [127.0.0.1]", leaf.IPAddresses)
	}
	if !leaf.IsCA {
		t.Error("self-signed leaf is not marked as a CA; Go will refuse it even as an explicit root")
	}
	// IsCA is unavoidable (Go's verifier refuses a non-CA parent even for a
	// self-signed root), which makes the constraints load-bearing: an operator
	// who installs this into the system trust store instead of passing
	// --ca-file would otherwise have handed the hub's serving key the power to
	// mint a trusted certificate for any domain.
	if leaf.MaxPathLen != 0 || !leaf.MaxPathLenZero {
		t.Error("the generated CA can sign further CAs (MaxPathLen is not 0)")
	}
	if len(leaf.PermittedDNSDomains) == 0 {
		t.Error("the generated CA has no DNS name constraints")
	}
	found := false
	for _, got := range leaf.PermittedDNSDomains {
		if got == "hub.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("PermittedDNSDomains = %v, missing \"hub.test\"", leaf.PermittedDNSDomains)
	}
	if len(leaf.PermittedIPRanges) != 1 || leaf.PermittedIPRanges[0].IP.String() != "127.0.0.1" {
		t.Errorf("PermittedIPRanges = %v, want a single /32 for 127.0.0.1", leaf.PermittedIPRanges)
	}
}

// TestGenerateSelfSignedKeysAreDistinct guards the property the whole pinning
// scheme rests on: two invocations must not produce the same key. A generator
// seeded deterministically would make every cloop deployment pin-compatible
// with every other, which is indistinguishable from no pinning at all.
func TestGenerateSelfSignedKeysAreDistinct(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pinA, err := GenerateSelfSigned(filepath.Join(dir, "a.pem"), filepath.Join(dir, "a.key"), SelfSignedOptions{})
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	pinB, err := GenerateSelfSigned(filepath.Join(dir, "b.pem"), filepath.Join(dir, "b.key"), SelfSignedOptions{})
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if pinA == pinB {
		t.Fatalf("two generated certificates share the pin %s", pinA)
	}
}

// ---------------------------------------------------------------------------
// Pin parsing and matching
// ---------------------------------------------------------------------------

func TestParsePin(t *testing.T) {
	t.Parallel()
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}
	std := base64.StdEncoding.EncodeToString(digest)
	url := base64.URLEncoding.EncodeToString(digest)
	rawStd := base64.RawStdEncoding.EncodeToString(digest)

	// Every encoding a pin plausibly arrives in — through a shell, a YAML
	// file, a QR code — must parse to the same digest, or an operator who
	// pasted a valid pin gets told it is malformed.
	for _, in := range []string{
		PinPrefix + std, std, PinPrefix + url, PinPrefix + rawStd,
		"  " + PinPrefix + std + "  ", "SHA256:" + std,
	} {
		got, err := ParsePin(in)
		if err != nil {
			t.Errorf("ParsePin(%q): %v", in, err)
			continue
		}
		if string(got) != string(digest) {
			t.Errorf("ParsePin(%q) returned the wrong digest", in)
		}
	}

	for _, bad := range []string{
		"", "   ", "not-base64!!!",
		"sha1:" + std, // wrong algorithm
		PinPrefix + base64.StdEncoding.EncodeToString(digest[:16]), // too short
	} {
		if _, err := ParsePin(bad); err == nil {
			t.Errorf("ParsePin(%q): want error, got nil", bad)
		} else if !errors.Is(err, ErrNoPin) {
			t.Errorf("ParsePin(%q) error = %v, want ErrNoPin", bad, err)
		}
	}
}

func TestParsePinSet(t *testing.T) {
	t.Parallel()
	a := FingerprintSPKI([]byte("key-a"))
	b := FingerprintSPKI([]byte("key-b"))

	empty, err := ParsePinSet("")
	if err != nil {
		t.Fatalf("ParsePinSet(\"\"): %v", err)
	}
	if !empty.Empty() {
		t.Error("empty input should produce a disabled pin set")
	}
	if empty.VerifyPeerCertificate() != nil {
		t.Error("a disabled pin set must not install a verify callback")
	}

	for _, in := range []string{a + "," + b, a + " " + b, a + ",\n" + b} {
		set, err := ParsePinSet(in)
		if err != nil {
			t.Fatalf("ParsePinSet(%q): %v", in, err)
		}
		if set.Len() != 2 {
			t.Errorf("ParsePinSet(%q) has %d pins, want 2", in, set.Len())
		}
	}

	if _, err := ParsePinSet(a + ",garbage"); err == nil {
		t.Error("a malformed pin in the list must fail the whole set")
	}

	// An input carrying separators but no pins is a typo, not a request to
	// disable pinning. Silently returning an empty set would connect unpinned
	// while reporting "no pin" to an operator who believes they passed one.
	for _, junk := range []string{",", ",,,", " , ", ",\n,"} {
		if set, err := ParsePinSet(junk); err == nil {
			t.Errorf("ParsePinSet(%q) = %d pins, nil error — want an error, "+
				"not a silently disabled pin set", junk, set.Len())
		}
	}

	// Whitespace-only is the one input that is genuinely indistinguishable
	// from unset — a shell can produce it from an empty variable — so it means
	// "pinning disabled", exactly as "" does.
	for _, blank := range []string{" ", "\n", "\t  "} {
		set, err := ParsePinSet(blank)
		if err != nil {
			t.Errorf("ParsePinSet(%q): %v — whitespace-only should mean unset", blank, err)
		}
		if !set.Empty() {
			t.Errorf("ParsePinSet(%q) is not empty", blank)
		}
	}
}

// TestPinMatchAndMismatch is the core behavioural check: the right key is
// accepted, a different key is refused, and the refusal carries the sentinel
// so callers can tell it apart from a network fault.
func TestPinMatchAndMismatch(t *testing.T) {
	t.Parallel()
	keyA, certA := makeCert(t, "hub.test", nil)
	_, certB := makeCert(t, "hub.test", nil)

	set, err := ParsePinSet(Fingerprint(certA))
	if err != nil {
		t.Fatalf("ParsePinSet: %v", err)
	}
	if !set.Matches(certA) {
		t.Error("the pinned certificate does not match its own pin")
	}
	if set.Matches(certB) {
		t.Error("a certificate with a different key matched the pin")
	}
	if set.Matches(nil) {
		t.Error("nil certificate matched")
	}

	verify := set.VerifyPeerCertificate()
	if verify == nil {
		t.Fatal("VerifyPeerCertificate returned nil for a non-empty set")
	}
	if err := verify([][]byte{certA.Raw}, nil); err != nil {
		t.Errorf("verify(pinned cert): %v", err)
	}
	err = verify([][]byte{certB.Raw}, nil)
	if err == nil {
		t.Fatal("verify(unpinned cert) accepted it")
	}
	if !errors.Is(err, ErrPinMismatch) {
		t.Errorf("error = %v, want ErrPinMismatch", err)
	}
	if err := verify(nil, nil); err == nil {
		t.Error("verify with no certificates accepted it")
	}

	// The pin must be over the SPKI, which is exactly what makes the rotation
	// semantics below possible.
	spki, err := x509.MarshalPKIXPublicKey(&keyA.PublicKey)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	if got, want := FingerprintSPKI(spki), Fingerprint(certA); got != want {
		t.Errorf("FingerprintSPKI = %s, Fingerprint(cert) = %s", got, want)
	}
}

// TestPinSurvivesCertificateRenewal is the reason this is SPKI pinning rather
// than certificate pinning.
//
// Renewal is the routine event: a 90-day certificate is re-issued from the
// same key roughly every other month. If that changed the pin, every enrolled
// device in the fleet would refuse to reconnect on renewal day and the whole
// mechanism would be turned off within a quarter. Rotating onto a *new* key is
// the rare, deliberate event, and that one must be caught.
func TestPinSurvivesCertificateRenewal(t *testing.T) {
	t.Parallel()
	key, original := makeCert(t, "hub.test", nil)

	set, err := ParsePinSet(Fingerprint(original))
	if err != nil {
		t.Fatalf("ParsePinSet: %v", err)
	}

	// Renewed: same key, new serial, new validity window, different subject.
	renewed := reissue(t, key, "hub.test (renewed)")
	if renewed.SerialNumber.Cmp(original.SerialNumber) == 0 {
		t.Fatal("test bug: the renewed certificate is byte-identical")
	}
	if !set.Matches(renewed) {
		t.Error("a certificate renewed from the same key broke the pin — " +
			"every enrolled device would refuse to reconnect on renewal day")
	}

	// Rotated: a genuinely new key. This is the case pinning exists to catch,
	// and it is also what an impersonating server looks like.
	_, rotated := makeCert(t, "hub.test", nil)
	if set.Matches(rotated) {
		t.Fatal("a certificate on a NEW key matched the old pin — pinning is not detecting key rotation")
	}

	// Staged rotation: publishing both pins lets the fleet cross over without
	// a flag day, and both keys are accepted meanwhile.
	staged, err := ParsePinSet(Fingerprint(original) + "," + Fingerprint(rotated))
	if err != nil {
		t.Fatalf("ParsePinSet(staged): %v", err)
	}
	if !staged.Matches(original) || !staged.Matches(rotated) {
		t.Error("a two-pin set must accept both keys during a staged rotation")
	}
	_, stranger := makeCert(t, "hub.test", nil)
	if staged.Matches(stranger) {
		t.Error("a two-pin set accepted a third, unlisted key")
	}
}

func TestPinFromCertFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, leaf := makeCert(t, "leaf.test", nil)
	_, intermediate := makeCert(t, "ca.test", nil)

	// fullchain.pem ordering: leaf first, then intermediates. Pinning must
	// follow the leaf, since that is the certificate the peer authenticates
	// with and the one tls.LoadX509KeyPair will serve.
	chain := filepath.Join(dir, "fullchain.pem")
	var buf strings.Builder
	buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate.Raw}))
	if err := os.WriteFile(chain, []byte(buf.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := PinFromCertFile(chain)
	if err != nil {
		t.Fatalf("PinFromCertFile: %v", err)
	}
	if want := Fingerprint(leaf); got != want {
		t.Errorf("PinFromCertFile = %s, want the leaf's pin %s", got, want)
	}

	if _, err := PinFromCertFile(filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("missing file: want error")
	}
	notPEM := filepath.Join(dir, "notpem.pem")
	if err := os.WriteFile(notPEM, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := PinFromCertFile(notPEM); err == nil {
		t.Error("non-PEM file: want error")
	}
}

// ---------------------------------------------------------------------------
// Client config
// ---------------------------------------------------------------------------

// TestClientConfigNeverSkipsVerification is the invariant that makes pinning
// meaningful: it is layered on top of chain verification, never a substitute
// for it. If InsecureSkipVerify were set, VerifyPeerCertificate would become
// the *only* check, and a pin over a self-signed certificate an attacker
// generated would pass every other test in this file.
func TestClientConfigNeverSkipsVerification(t *testing.T) {
	t.Parallel()
	_, cert := makeCert(t, "hub.test", nil)
	pins, err := ParsePinSet(Fingerprint(cert))
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []ClientOptions{
		{},
		{Pins: pins},
		{MinVersion: tls.VersionTLS13},
		{ServerName: "hub.test"},
	} {
		cfg, err := ClientConfig(opts)
		if err != nil {
			t.Fatalf("ClientConfig(%+v): %v", opts, err)
		}
		if cfg.InsecureSkipVerify {
			t.Fatalf("ClientConfig(%+v) set InsecureSkipVerify", opts)
		}
		if cfg.MinVersion < tls.VersionTLS12 {
			t.Errorf("MinVersion = %#x, below the TLS 1.2 floor", cfg.MinVersion)
		}
	}
}

func TestClientConfigRootCAFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, cert := makeCert(t, "hub.test", nil)
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := ClientConfig(ClientOptions{RootCAFile: caPath})
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs is nil after loading a CA bundle")
	}

	if _, err := ClientConfig(ClientOptions{RootCAFile: filepath.Join(dir, "nope.pem")}); err == nil {
		t.Error("missing CA file: want error")
	}
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ClientConfig(ClientOptions{RootCAFile: junk}); err == nil {
		t.Error("CA file with no certificates: want error")
	}
}

// ---------------------------------------------------------------------------
// Endpoint policy
// ---------------------------------------------------------------------------

// TestCheckEndpointPlaintextPolicy pins the rule that an unattended agent
// never sends a credential in the clear to a host it does not control.
func TestCheckEndpointPlaintextPolicy(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		url           string
		allowInsecure bool
		wantErr       bool
		wantWarn      bool
	}{
		{"tls to public host", "wss://hub.example.com/connect", false, false, false},
		{"https to public host", "https://hub.example.com/connect", false, false, false},
		{"plaintext to public host is refused", "ws://hub.example.com/connect", false, true, false},
		{"http to public host is refused", "http://hub.example.com/connect", false, true, false},
		{"plaintext to public IP is refused", "ws://93.184.216.34/connect", false, true, false},
		{"plaintext to loopback name is fine", "ws://localhost:8080/connect", false, false, false},
		{"plaintext to 127.0.0.1 is fine", "ws://127.0.0.1:8080/connect", false, false, false},
		{"plaintext to ::1 is fine", "ws://[::1]:8080/connect", false, false, false},
		{"override allows it but warns", "ws://hub.example.com/connect", true, false, true},
		{"override is not needed for TLS", "wss://hub.example.com/connect", true, false, false},
		{"empty", "", false, true, false},
		{"no host", "wss://", false, true, false},
		{"unknown scheme", "ftp://hub.example.com/", false, true, false},
		// A scheme-less string is a plausible typo, and treating it as a
		// relative URL with no host would be a confusing way to fail.
		{"no scheme", "hub.example.com/connect", false, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, warn, err := CheckEndpoint(c.url, c.allowInsecure)
			if c.wantErr {
				if err == nil {
					t.Fatalf("CheckEndpoint(%q, %v): want error, got nil", c.url, c.allowInsecure)
				}
				return
			}
			if err != nil {
				t.Fatalf("CheckEndpoint(%q, %v): %v", c.url, c.allowInsecure, err)
			}
			if c.wantWarn && warn == "" {
				t.Error("expected a loud warning for an insecure override, got none")
			}
			if !c.wantWarn && warn != "" {
				t.Errorf("unexpected warning: %s", warn)
			}
		})
	}
}

// TestCheckEndpointRefusalIsTyped lets callers distinguish "you configured
// plaintext" from "that URL is malformed" — different operator actions.
func TestCheckEndpointRefusalIsTyped(t *testing.T) {
	t.Parallel()
	_, _, err := CheckEndpoint("ws://hub.example.com/connect", false)
	if !errors.Is(err, ErrInsecureTransport) {
		t.Errorf("error = %v, want ErrInsecureTransport", err)
	}
	_, _, err = CheckEndpoint("ftp://hub.example.com/", false)
	if !errors.Is(err, ErrEndpointInvalid) {
		t.Errorf("error = %v, want ErrEndpointInvalid", err)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	t.Parallel()
	for _, h := range []string{"localhost", "LOCALHOST", "127.0.0.1", "127.1.2.3", "::1", "[::1]", "app.localhost"} {
		if !IsLoopbackHost(h) {
			t.Errorf("IsLoopbackHost(%q) = false, want true", h)
		}
	}
	// The near-misses matter: a prefix or suffix match would accept
	// "localhost.evil.com", which resolves to whatever the attacker wants.
	for _, h := range []string{
		"hub.example.com", "localhost.evil.com", "notlocalhost", "0.0.0.0",
		"10.0.0.1", "93.184.216.34", "", "1270.0.0.1",
		// Only one balanced bracket pair is stripped: strings.Trim would also
		// accept these, none of which are addresses.
		"[[::1]]", "]::1[", "[::1",
	} {
		if IsLoopbackHost(h) {
			t.Errorf("IsLoopbackHost(%q) = true, want false", h)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// makeCert builds a self-signed certificate. Passing a key reuses it, which is
// how the renewal case is simulated.
func makeCert(t *testing.T, cn string, key *ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return key, cert
}

// reissue models a CA renewal: same key, everything else new.
func reissue(t *testing.T, key *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	_, cert := makeCert(t, cn, key)
	return cert
}

func parseCertFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s is not PEM", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return cert
}
