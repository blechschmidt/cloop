package security

// Guarantee: a push through the git proxy that carries a credential its run's
// lease delivered is refused before the forge holds a complete pack — every
// credential-bearing kind the broker delivers, as delivered, base64-encoded
// and percent-encoded — and the refusal, to the sandbox and on the audit
// trail, names the grant and secret, never the value. A push carrying none is
// forwarded to the forge byte for byte (Task 20436).
//
// # Why this is a conformance test
//
// The two halves live in different packages and each is tested on its own:
// pkg/secretbroker says which values a lease delivered (CredentialValues),
// pkg/gitproxy refuses a push carrying a value it is given. The guarantee is
// their composition — a value the broker leaves out is a value no push is
// scanned for — and a later delivery that wrote a credential somewhere
// CredentialValues does not look would break it while both packages' own
// tests kept passing. So this test leases real credentials through the real
// broker and pushes each one through a real proxy at a forge that records
// whether it ever received a whole pack.

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// pushScanLease leases one credential of every kind that carries one.
func pushScanLease(t *testing.T) *secretbroker.Lease {
	t.Helper()
	b, _, _ := newBroker(t)
	ctx := context.Background()
	mint := func(name string, kind secretbroker.Kind, payload string) secretbroker.Secret {
		s, err := b.Mint(ctx, secretbroker.MintRequest{Name: name, Kind: kind, Payload: []byte(payload), Actor: "conformance"})
		if err != nil {
			t.Fatalf("mint %s: %v", name, err)
		}
		return s
	}
	grant := func(s secretbroker.Secret, c secretbroker.Constraints) {
		sub, _ := secretbroker.ParseSubject("project:/srv/app")
		if _, err := b.Grant(ctx, secretbroker.GrantRequest{SecretRef: s.ID, Subject: sub, Constraints: c,
			TTL: time.Hour, Actor: "conformance"}); err != nil {
			t.Fatalf("grant %s: %v", s.Name, err)
		}
	}
	grant(mint("svc-env", secretbroker.KindEnv, `{"SVC_API_KEY":"svc-internal-key-9f3a2c71"}`), secretbroker.Constraints{})
	grant(mint("dev-pat", secretbroker.KindGitHubPAT, "ghp_conformancePushScanToken000000001"),
		secretbroker.Constraints{Repos: []string{"acme/*"}})
	key := "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC9\n-----END PRIVATE KEY-----\n"
	grant(mint("prod-kube", secretbroker.KindKubeconfig,
		"apiVersion: v1\nkind: Config\ncurrent-context: ci\n"+
			"clusters:\n- name: c\n  cluster:\n    server: https://k8s.example.invalid\n"+
			"contexts:\n- name: ci\n  context:\n    cluster: c\n    user: u\n"+
			"users:\n- name: u\n  user:\n    token: kube-bearer-7e1d9a44c0\n"+
			"    client-key-data: "+base64.StdEncoding.EncodeToString([]byte(key))+"\n"),
		secretbroker.Constraints{Contexts: []string{"ci"},
			Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}})
	grant(mint("ghcr", secretbroker.KindRegistry,
		`{"auths":{"ghcr.io":{"auth":"`+base64.StdEncoding.EncodeToString([]byte("robot:ghcr-pass-55b0e1"))+`"}}}`),
		secretbroker.Constraints{Registries: []string{"ghcr.io"}})
	grant(mint("corp-proxy", secretbroker.KindEgressProxy, "http://svc:proxy-pass%2F81c2d@proxy.example.invalid:3128"),
		secretbroker.Constraints{Hosts: []string{"example.com"}})

	lease, err := b.LeaseFor(ctx, secretbroker.Requester{ExecutorID: "exec-1", ProjectID: "/srv/app"}, "conformance")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if len(lease.Refused) != 0 {
		t.Fatalf("the lease refused %+v", lease.Refused)
	}
	return lease
}

// recordingForge stands in for a forge's receive-pack: it records every body
// it reads to the end and every one it did not.
type recordingForge struct {
	mu         sync.Mutex
	complete   [][]byte
	incomplete int
}

func (f *recordingForge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	f.mu.Lock()
	if err != nil {
		f.incomplete++
	} else {
		f.complete = append(f.complete, body)
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/x-git-receive-pack-result")
	_, _ = io.WriteString(w, "000eunpack ok\n0000")
}

// onePack is a pack holding one blob, as git lays one out.
func onePack(content []byte) []byte {
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	_, _ = zw.Write(content)
	_ = zw.Close()
	var p bytes.Buffer
	p.WriteString("PACK")
	_ = binary.Write(&p, binary.BigEndian, uint32(2))
	_ = binary.Write(&p, binary.BigEndian, uint32(1))
	size := uint64(len(content))
	c := byte(3<<4) | byte(size&15)
	for size >>= 4; size > 0; size >>= 7 {
		p.WriteByte(c | 0x80)
		c = byte(size & 0x7f)
	}
	p.WriteByte(c)
	p.Write(z.Bytes())
	sum := sha1.Sum(p.Bytes())
	p.Write(sum[:])
	return p.Bytes()
}

func pushBody(pack []byte) []byte {
	var b bytes.Buffer
	line := strings.Repeat("0", 40) + " " + strings.Repeat("a", 40) + " refs/heads/cloop/conformance\x00report-status side-band-64k\n"
	fmt.Fprintf(&b, "%04x%s0000", len(line)+4, line)
	b.Write(pack)
	return b.Bytes()
}

func TestAPushCarryingALeasedCredentialNeverReachesTheForge(t *testing.T) {
	lease := pushScanLease(t)
	creds := lease.CredentialValues()
	var secrets []gitproxy.ScanSecret
	for _, c := range creds {
		secrets = append(secrets, gitproxy.ScanSecret{Value: c.Value, Grant: c.GrantID, Secret: c.SecretName, Field: c.Field})
	}
	// Every kind that carries a credential is in what the push is scanned
	// for: a kind missing here is a credential no push is checked for.
	kinds := map[secretbroker.Kind]bool{}
	for _, c := range creds {
		kinds[c.Kind] = true
	}
	for _, k := range []secretbroker.Kind{secretbroker.KindEnv, secretbroker.KindGitHubPAT, secretbroker.KindKubeconfig,
		secretbroker.KindRegistry, secretbroker.KindEgressProxy} {
		if !kinds[k] {
			t.Fatalf("CredentialValues names no %s credential, so no push is scanned for one", k)
		}
	}

	forge := &recordingForge{}
	forgeSrv := httptest.NewTLSServer(forge)
	defer forgeSrv.Close()
	proxySrv := httptest.NewUnstartedServer(nil)
	proxySrv.StartTLS()
	defer proxySrv.Close()
	reg, err := gitproxy.NewRegistry(proxySrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var events []gitproxy.Event
	reg.OnEvent = func(e gitproxy.Event) { mu.Lock(); events = append(events, e); mu.Unlock() }
	px, err := gitproxy.New(reg, gitproxy.Options{
		Transport: forgeSrv.Client().Transport,
		PushScan: func(*gitproxy.Session) gitproxy.PushScan {
			return gitproxy.PushScan{Mode: gitproxy.ScanValues, Secrets: secrets}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv.Config.Handler = px
	m, err := reg.Mint(gitproxy.MintRequest{
		Upstream:   forgeSrv.URL + "/acme/tool.git",
		Credential: gitproxy.Credential{Username: "x-access-token", Password: "forge-held-token-0c11"},
		Policy:     gitproxy.WriteBackPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	client := proxySrv.Client()
	push := func(pack []byte) string {
		req, _ := http.NewRequest(http.MethodPost, m.RepoURL+"/git-receive-pack", bytes.NewReader(pushBody(pack)))
		req.SetBasicAuth(m.Session.ID, m.Token)
		req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("push: %v", err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return string(out)
	}

	forms := map[string]func(string) string{
		"as delivered": func(v string) string { return v },
		"base64":       func(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) },
		"percent":      func(v string) string { return url.QueryEscape(v) },
	}
	for _, c := range creds {
		if len(c.Value) < 8 {
			continue
		}
		for name, enc := range forms {
			label := c.SecretName + " " + c.Field + " " + name
			before := len(forge.complete)
			out := push(onePack([]byte("config:\n  value: " + enc(c.Value) + "\n")))
			if !strings.Contains(out, "ng refs/heads/cloop/conformance") || !strings.Contains(out, c.GrantID) {
				t.Fatalf("%s: the push was not refused naming its grant:\n%q", label, out)
			}
			if strings.Contains(out, c.Value) || strings.Contains(out, enc(c.Value)) {
				t.Fatalf("%s: the refusal echoes the value", label)
			}
			forge.mu.Lock()
			got := len(forge.complete)
			forge.mu.Unlock()
			if got != before {
				t.Fatalf("%s: the forge received a complete pack", label)
			}
		}
	}

	// Every row the proxy wrote names grants and objects, never a value.
	mu.Lock()
	for _, e := range events {
		row := e.String() + strings.Join(e.Refs, ",")
		for _, f := range e.Findings {
			row += f.Path + f.Tag + f.Ref + f.Field
		}
		for _, c := range creds {
			if len(c.Value) >= 8 && strings.Contains(row, c.Value) {
				t.Fatalf("an audit row carries %s's value: %s", c.SecretName, e.String())
			}
		}
	}
	refused := 0
	for _, e := range events {
		if e.Kind == gitproxy.EventPushSecretRefused {
			refused++
		}
	}
	mu.Unlock()
	if refused == 0 {
		t.Fatal("no push_secret_refused row was written")
	}

	// The control: a push carrying nothing the run holds reaches the forge
	// exactly as sent.
	clean := pushBody(onePack([]byte("nothing to see: " + hex.EncodeToString([]byte("plain content")) + "\n")))
	req, _ := http.NewRequest(http.MethodPost, m.RepoURL+"/git-receive-pack", bytes.NewReader(clean))
	req.SetBasicAuth(m.Session.ID, m.Token)
	req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	forge.mu.Lock()
	defer forge.mu.Unlock()
	if len(forge.complete) != 1 || !bytes.Equal(forge.complete[0], clean) {
		t.Fatalf("the clean push reached the forge %d times, as sent: %v", len(forge.complete),
			len(forge.complete) == 1 && bytes.Equal(forge.complete[0], clean))
	}
}
