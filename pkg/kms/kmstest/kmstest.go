// Package kmstest provides in-repo stand-ins for the key-management services
// pkg/kms speaks to (Task 20433): a Kubernetes KMS v2 plugin served over a real
// unix socket with the protocol's own generated server stubs, and a Vault
// Transit server over HTTP on loopback.
//
// They are fakes of the KMS, not of the protocol: a test drives the real
// client, over the real transport, against a server that encrypts for real
// (AES-256-GCM under keys it holds and never shows) and can be made slow,
// unhealthy, unavailable, rotated or refusing. Neither keeps or logs a
// plaintext it is given, so a test scanning for leaked key material scans a
// fake that cannot be the leak.
package kmstest

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	kmsapi "k8s.io/kms/apis/v2"
)

// AnnotationKey is the annotation the fake plugin returns with every
// ciphertext, naming the key version, as real plugins do (the Azure plugin's
// version.azure.akv.io, say). Decrypt requires it back.
const AnnotationKey = "version.kmstest.cloop.dev"

// Plugin is a fake KMS v2 plugin listening on a unix socket.
type Plugin struct {
	kmsapi.UnimplementedKeyManagementServiceServer

	dir    string
	socket string
	srv    *grpc.Server

	mu      sync.Mutex
	keys    map[string]cipher.AEAD // key id -> AEAD
	order   []string
	current string
	delay   time.Duration
	healthz string
	fail    map[string]codes.Code // operation -> code every call fails with
	calls   map[string]int
	stopped bool
}

// StartPlugin starts a plugin with one key, "key-1", on a socket in a fresh
// directory only this user can write. It stops when the test ends.
func StartPlugin(t testing.TB) *Plugin {
	t.Helper()
	p, err := NewPlugin()
	if err != nil {
		t.Fatalf("kmstest: start plugin: %v", err)
	}
	t.Cleanup(func() { p.Stop(); _ = os.RemoveAll(p.dir) })
	return p
}

// NewPlugin starts a plugin the caller stops with Stop and cleans up after
// with Cleanup — for a process that runs one beside the hubs it starts.
func NewPlugin() (*Plugin, error) {
	// Short: a unix socket's path has to fit in 108 bytes, and a test's
	// TempDir is often longer than that by itself.
	dir, err := os.MkdirTemp("", "kmsp")
	if err != nil {
		return nil, err
	}
	p := &Plugin{
		dir:     dir,
		socket:  filepath.Join(dir, "kms.sock"),
		keys:    map[string]cipher.AEAD{},
		healthz: "ok",
		fail:    map[string]codes.Code{},
		calls:   map[string]int{},
	}
	if _, err := p.addKey(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	if err := p.Restart(); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return p, nil
}

// Cleanup removes the plugin's directory. Stop first.
func (p *Plugin) Cleanup() { _ = os.RemoveAll(p.dir) }

// Socket is the plugin's socket path; Endpoint the same as an endpoint URL.
func (p *Plugin) Socket() string   { return p.socket }
func (p *Plugin) Endpoint() string { return "unix://" + p.socket }

// Stop closes the socket: every call fails as a plugin that is not running.
func (p *Plugin) Stop() {
	p.mu.Lock()
	srv, stopped := p.srv, p.stopped
	p.stopped = true
	p.mu.Unlock()
	if srv != nil && !stopped {
		srv.Stop()
	}
	_ = os.Remove(p.socket)
}

// Restart serves again on the same socket, with the same keys.
func (p *Plugin) Restart() error {
	_ = os.Remove(p.socket)
	lis, err := net.Listen("unix", p.socket)
	if err != nil {
		return err
	}
	srv := grpc.NewServer()
	kmsapi.RegisterKeyManagementServiceServer(srv, p)
	p.mu.Lock()
	p.srv, p.stopped = srv, false
	p.mu.Unlock()
	go func() { _ = srv.Serve(lis) }()
	return nil
}

// Rotate adds a new key version and makes it current; old versions still
// decrypt, as a KMS's do. It returns the new key id.
func (p *Plugin) Rotate() string {
	id, err := p.addKey()
	if err != nil {
		panic(err)
	}
	return id
}

// CurrentKeyID is the key the plugin encrypts under.
func (p *Plugin) CurrentKeyID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.current
}

// SetDelay makes every call take d before answering.
func (p *Plugin) SetDelay(d time.Duration) {
	p.mu.Lock()
	p.delay = d
	p.mu.Unlock()
}

// SetHealthz sets what Status reports ("ok" when healthy).
func (p *Plugin) SetHealthz(s string) {
	p.mu.Lock()
	p.healthz = s
	p.mu.Unlock()
}

// FailWith makes every call of op ("Status", "Encrypt", "Decrypt") fail with
// code; codes.OK clears it.
func (p *Plugin) FailWith(op string, code codes.Code) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if code == codes.OK {
		delete(p.fail, op)
		return
	}
	p.fail[op] = code
}

// Calls counts the calls of op the plugin has answered or failed.
func (p *Plugin) Calls(op string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[op]
}

func (p *Plugin) addKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	id := fmt.Sprintf("key-%d", len(p.order)+1)
	p.keys[id] = aead
	p.order = append(p.order, id)
	p.current = id
	return id, nil
}

// enter counts a call, applies the delay and returns the failure set for it.
func (p *Plugin) enter(ctx context.Context, op string) error {
	p.mu.Lock()
	p.calls[op]++
	delay, code := p.delay, p.fail[op]
	p.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		}
	}
	if code != codes.OK {
		return status.Errorf(code, "kmstest: %s fails with %s", op, code)
	}
	return nil
}

// Status implements the protocol.
func (p *Plugin) Status(ctx context.Context, _ *kmsapi.StatusRequest) (*kmsapi.StatusResponse, error) {
	if err := p.enter(ctx, "Status"); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return &kmsapi.StatusResponse{Version: "v2", Healthz: p.healthz, KeyId: p.current}, nil
}

// Encrypt implements the protocol.
func (p *Plugin) Encrypt(ctx context.Context, req *kmsapi.EncryptRequest) (*kmsapi.EncryptResponse, error) {
	if err := p.enter(ctx, "Encrypt"); err != nil {
		return nil, err
	}
	if len(req.GetPlaintext()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "kmstest: empty plaintext")
	}
	p.mu.Lock()
	id := p.current
	aead := p.keys[id]
	p.mu.Unlock()
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	ct := aead.Seal(nonce, nonce, req.GetPlaintext(), []byte(id))
	return &kmsapi.EncryptResponse{
		Ciphertext:  ct,
		KeyId:       id,
		Annotations: map[string][]byte{AnnotationKey: []byte(id)},
	}, nil
}

// Decrypt implements the protocol.
func (p *Plugin) Decrypt(ctx context.Context, req *kmsapi.DecryptRequest) (*kmsapi.DecryptResponse, error) {
	if err := p.enter(ctx, "Decrypt"); err != nil {
		return nil, err
	}
	id := req.GetKeyId()
	if ann := string(req.GetAnnotations()[AnnotationKey]); ann != id {
		return nil, status.Errorf(codes.InvalidArgument, "kmstest: annotation names key %q, request %q", ann, id)
	}
	p.mu.Lock()
	aead := p.keys[id]
	p.mu.Unlock()
	if aead == nil {
		return nil, status.Errorf(codes.InvalidArgument, "kmstest: no key %q", id)
	}
	ct := req.GetCiphertext()
	if len(ct) < aead.NonceSize() {
		return nil, status.Error(codes.InvalidArgument, "kmstest: short ciphertext")
	}
	pt, err := aead.Open(nil, ct[:aead.NonceSize()], ct[aead.NonceSize():], []byte(id))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "kmstest: decryption failed")
	}
	return &kmsapi.DecryptResponse{Plaintext: pt}, nil
}
