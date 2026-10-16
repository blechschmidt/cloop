package kms_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/kms"
	"github.com/blechschmidt/cloop/pkg/kms/kmstest"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// pluginConfig is a secrets.kms block pointing at p.
func pluginConfig(p *kmstest.Plugin, timeout string) config.KMSConfig {
	return config.KMSConfig{
		Provider: config.KMSProviderKMSv2,
		Timeout:  timeout,
		KMSv2:    config.KMSv2Config{Endpoint: p.Endpoint()},
	}
}

func openPlugin(t *testing.T, p *kmstest.Plugin, timeout string) kms.Provider {
	t.Helper()
	prov, err := kms.Open(pluginConfig(p, timeout))
	if err != nil {
		t.Fatalf("open provider: %v", err)
	}
	t.Cleanup(func() { _ = prov.Close() })
	return prov
}

// The client speaks the KMS v2 protocol to a server built on the protocol's
// own generated stubs: what it wraps unwraps, under the key the plugin
// reports, with the annotations the plugin returned given back.
func TestKMSv2RoundTrip(t *testing.T) {
	p := kmstest.StartPlugin(t)
	prov := openPlugin(t, p, "")
	ctx := context.Background()

	st, err := prov.Status(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !st.Healthy || st.Version != "v2" || st.KeyID != "key-1" {
		t.Fatalf("status = %+v", st)
	}

	secret := bytes.Repeat([]byte{0x5a}, 32)
	ct, err := prov.Encrypt(ctx, secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if ct.KeyID != "key-1" || len(ct.Ciphertext) == 0 || bytes.Contains(ct.Ciphertext, secret) {
		t.Fatalf("ciphertext = %+v", ct)
	}
	if string(ct.Annotations[kmstest.AnnotationKey]) != "key-1" {
		t.Fatalf("annotations not carried: %v", ct.Annotations)
	}
	got, err := prov.Decrypt(ctx, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("decrypt gave %x", got)
	}
	if !strings.HasPrefix(prov.Name(), "kmsv2:") || !strings.Contains(prov.Name(), p.Socket()) {
		t.Fatalf("default name %q does not name the socket", prov.Name())
	}
}

// A rotated plugin key: the plugin reports the new key, encrypts under it, and
// still decrypts what the old one wrapped.
func TestKMSv2RotationChangesTheReportedKey(t *testing.T) {
	p := kmstest.StartPlugin(t)
	prov := openPlugin(t, p, "")
	ctx := context.Background()
	old, err := prov.Encrypt(ctx, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	newID := p.Rotate()
	cur, err := prov.CurrentKeyID(ctx)
	if err != nil || cur != newID {
		t.Fatalf("current key = %q, %v; want %q", cur, err, newID)
	}
	fresh, err := prov.Encrypt(ctx, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil || fresh.KeyID != newID {
		t.Fatalf("encrypt after rotation: %+v, %v", fresh, err)
	}
	if _, err := prov.Decrypt(ctx, old); err != nil {
		t.Fatalf("the old version no longer decrypts: %v", err)
	}
}

// A plugin that is not running is unreachable — the error says so, wraps
// secretbroker.ErrKMSUnavailable, and is counted as such.
func TestKMSv2UnavailablePlugin(t *testing.T) {
	p := kmstest.StartPlugin(t)
	prov := openPlugin(t, p, "2s")
	p.Stop()
	_, err := prov.Status(context.Background())
	if err == nil {
		t.Fatal("status succeeded against a stopped plugin")
	}
	if !errors.Is(err, secretbroker.ErrKMSUnavailable) || !kms.Unreachable(err) {
		t.Fatalf("error does not say the KMS is unreachable: %v", err)
	}
	if !strings.Contains(err.Error(), p.Socket()) {
		t.Fatalf("error does not name the socket: %v", err)
	}
	if !strings.Contains(hubmetrics.Default.Gather(),
		`cloop_kms_requests_total{backend="kmsv2",operation="status",result="unavailable"}`) {
		t.Fatal("the failed call is not in cloop_kms_requests_total")
	}
}

// A plugin slower than the configured timeout times out, as a timeout.
func TestKMSv2SlowPluginTimesOut(t *testing.T) {
	p := kmstest.StartPlugin(t)
	prov := openPlugin(t, p, "200ms")
	p.SetDelay(2 * time.Second)
	start := time.Now()
	_, err := prov.Encrypt(context.Background(), bytes.Repeat([]byte{1}, 32))
	if err == nil {
		t.Fatal("encrypt succeeded against a plugin slower than the timeout")
	}
	if took := time.Since(start); took > 1500*time.Millisecond {
		t.Fatalf("the call took %s; the timeout is 200ms", took)
	}
	var ke *kms.Error
	if !errors.As(err, &ke) || ke.Result != kms.ResultTimeout || !kms.Unreachable(err) {
		t.Fatalf("not classified as a timeout: %v", err)
	}
	if !strings.Contains(hubmetrics.Default.Gather(),
		`cloop_kms_request_duration_seconds_count{backend="kmsv2",operation="encrypt"}`) {
		t.Fatal("the call's latency is not in cloop_kms_request_duration_seconds")
	}
}

// A plugin that answers unhealthy is as unreachable as one that does not
// answer; one that refuses is a refusal, not an outage.
func TestKMSv2HealthAndRefusals(t *testing.T) {
	p := kmstest.StartPlugin(t)
	prov := openPlugin(t, p, "")
	ctx := context.Background()

	p.SetHealthz("key vault throttled")
	_, err := prov.Status(ctx)
	if err == nil || !kms.Unreachable(err) || !strings.Contains(err.Error(), "key vault throttled") {
		t.Fatalf("unhealthy status: %v", err)
	}
	p.SetHealthz("ok")

	p.FailWith("Decrypt", codes.PermissionDenied)
	_, err = prov.Decrypt(ctx, secretbroker.KMSCiphertext{KeyID: "key-1", Ciphertext: []byte("x"),
		Annotations: map[string][]byte{kmstest.AnnotationKey: []byte("key-1")}})
	var ke *kms.Error
	if !errors.As(err, &ke) || ke.Result != kms.ResultDenied || kms.Unreachable(err) {
		t.Fatalf("a refusal is not classified denied: %v", err)
	}
}

// Another plugin's key does not unwrap this one's ciphertext, and says so as a
// refusal.
func TestKMSv2WrongKeyIsARefusal(t *testing.T) {
	a := kmstest.StartPlugin(t)
	b := kmstest.StartPlugin(t)
	ctx := context.Background()
	ct, err := openPlugin(t, a, "").Encrypt(ctx, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	_, err = openPlugin(t, b, "").Decrypt(ctx, ct)
	var ke *kms.Error
	if !errors.As(err, &ke) || ke.Result != kms.ResultInvalid || kms.Unreachable(err) {
		t.Fatalf("decrypting under another key: %v", err)
	}
}

// A socket in a directory every user on the host shares (/tmp: world-writable
// and sticky) is refused before anything is sent to it: whoever bound it first
// would be sent every key the hub wraps. A world-writable directory without
// the sticky bit — an emptyDir, shared by one Pod's containers — is accepted.
func TestKMSv2RefusesASocketAnyoneCouldHaveBound(t *testing.T) {
	p := kmstest.StartPlugin(t)
	dir := filepath.Dir(p.Socket())
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	prov := openPlugin(t, p, "2s")

	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	_, err := prov.Encrypt(context.Background(), bytes.Repeat([]byte{9}, 32))
	if err == nil || !strings.Contains(err.Error(), "every user on the host shares") {
		t.Fatalf("a shared temporary directory was not refused: %v", err)
	}
	if p.Calls("Encrypt") != 0 {
		t.Fatal("the plugin was sent the plaintext anyway")
	}

	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := prov.Encrypt(context.Background(), bytes.Repeat([]byte{9}, 32)); err != nil {
		t.Fatalf("an emptyDir-shaped directory was refused: %v", err)
	}
}

// Only a unix socket is a KMS v2 endpoint.
func TestKMSv2EndpointMustBeAUnixSocket(t *testing.T) {
	for _, ep := range []string{"tcp://127.0.0.1:9000", "unix://host/path", "relative/kms.sock", ""} {
		err := config.ValidateSecrets(config.SecretsConfig{KMS: config.KMSConfig{
			Provider: config.KMSProviderKMSv2, KMSv2: config.KMSv2Config{Endpoint: ep}}})
		if err == nil {
			t.Errorf("endpoint %q accepted", ep)
		}
	}
	for _, ep := range []string{"unix:///run/kms/kms.sock", "/run/kms/kms.sock", "unix:/run/kms/kms.sock"} {
		if err := config.ValidateSecrets(config.SecretsConfig{KMS: config.KMSConfig{
			Provider: config.KMSProviderKMSv2, KMSv2: config.KMSv2Config{Endpoint: ep}}}); err != nil {
			t.Errorf("endpoint %q refused: %v", ep, err)
		}
	}
}
