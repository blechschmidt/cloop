package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/exposure"
)

// TestUIBindAddressMatrix runs `cloop ui`'s own request builder through the
// bind decision for every case Task 20393 names: {open, static token, SSO}
// against {default, explicit loopback, explicit non-loopback with and without
// ui.allow_unauthenticated_network}, each explicit address given once by
// --listen and once by ui.listen.
func TestUIBindAddressMatrix(t *testing.T) {
	prevListen, prevPort, prevCert := uiListen, uiPort, uiTLSCert
	t.Cleanup(func() { uiListen, uiPort, uiTLSCert = prevListen, prevPort, prevCert })
	uiPort, uiTLSCert = 8080, ""

	type hubAuth struct {
		name  string
		token string
		sso   bool
	}
	auths := []hubAuth{{name: "open"}, {name: "static token", token: "s3cret"}, {name: "SSO", sso: true}}
	listens := []struct {
		name, addr string
		ack        bool
		beyond     bool
	}{
		{name: "default"},
		{name: "explicit loopback", addr: "127.0.0.1"},
		{name: "non-loopback, acknowledged", addr: "0.0.0.0", ack: true, beyond: true},
		{name: "non-loopback, unacknowledged", addr: "0.0.0.0", beyond: true},
		{name: "one interface, unacknowledged", addr: "198.51.100.7", beyond: true},
	}
	for _, a := range auths {
		for _, l := range listens {
			for _, via := range []string{"--listen", "ui.listen"} {
				if l.addr == "" && via == "ui.listen" {
					continue // the default has no source
				}
				t.Run(a.name+"/"+l.name+"/"+via, func(t *testing.T) {
					cfg := &config.Config{}
					cfg.UI.OIDC.Enabled = a.sso
					cfg.UI.AllowUnauthenticatedNetwork = l.ack
					uiListen = ""
					if via == "--listen" {
						uiListen = l.addr
					} else {
						cfg.UI.Listen = l.addr
					}
					plan, err := exposure.Decide(uiListenRequest(cfg, a.token))

					open := a.token == "" && !a.sso
					if open && l.beyond && !l.ack {
						if !errors.Is(err, exposure.ErrOpenToNetwork) {
							t.Fatalf("got %v, %v; want the refusal", plan, err)
						}
						if !strings.Contains(err.Error(), "("+via+")") {
							t.Errorf("the refusal does not name %s: %v", via, err)
						}
						return
					}
					if err != nil {
						t.Fatalf("Decide: %v", err)
					}
					var want string
					switch {
					case l.addr == "" && open:
						want = "127.0.0.1:8080"
					case l.addr == "":
						want = "*:8080"
					case l.addr == "0.0.0.0":
						want = "*:8080"
					default:
						want = l.addr + ":8080"
					}
					if plan.String() != want {
						t.Errorf("binds %s, want %s", plan, want)
					}
				})
			}
		}
	}
}

// TestUIListenFlagBeatsConfig: --listen overrides ui.listen, the way every
// other flag overrides its key, so an operator can pin one start to loopback
// without editing a shared file.
func TestUIListenFlagBeatsConfig(t *testing.T) {
	prevListen, prevPort := uiListen, uiPort
	t.Cleanup(func() { uiListen, uiPort = prevListen, prevPort })
	uiPort = 8081

	cfg := &config.Config{}
	cfg.UI.OIDC.Enabled = true
	cfg.UI.Listen = "0.0.0.0"
	cfg.UI.ExternalURL = "https://hub.example.com:8888"

	uiListen = "127.0.0.1"
	req := uiListenRequest(cfg, "")
	if req.Listen != "127.0.0.1" || req.Source != "--listen" {
		t.Fatalf("request = %+v, want --listen 127.0.0.1", req)
	}
	plan, err := exposure.Decide(req)
	if err != nil || plan.String() != "127.0.0.1:8081" {
		t.Fatalf("plan = %v, %v", plan, err)
	}

	uiListen = ""
	req = uiListenRequest(cfg, "")
	if req.Listen != "0.0.0.0" || req.Source != "ui.listen" || !req.SSO {
		t.Fatalf("request = %+v, want ui.listen 0.0.0.0 with SSO", req)
	}
	plan, err = exposure.Decide(req)
	if err != nil {
		t.Fatal(err)
	}
	// The :8081 hub on aiden.blechschmidt.io, as configured: SSO, plaintext,
	// every interface, an https external URL in front.
	if !plan.PlaintextBehindHTTPS() {
		t.Errorf("an SSO hub serving plaintext on %s behind %s is not flagged", plan, cfg.UI.ExternalURL)
	}
}

// TestUIListenRequestReadsTheTokenItIsGiven: the static token counts as a
// browser credential whether it came from --token or CLOOP_UI_TOKEN — the
// caller resolves both into one string.
func TestUIListenRequestReadsTheTokenItIsGiven(t *testing.T) {
	prevListen := uiListen
	t.Cleanup(func() { uiListen = prevListen })
	uiListen = "0.0.0.0"
	if _, err := exposure.Decide(uiListenRequest(nil, "")); !errors.Is(err, exposure.ErrOpenToNetwork) {
		t.Errorf("no config, no token, --listen 0.0.0.0: %v, want the refusal", err)
	}
	if plan, err := exposure.Decide(uiListenRequest(nil, "tok")); err != nil || plan.Scope != exposure.ScopeEvery {
		t.Errorf("with a token: %v, %v; want every interface", plan, err)
	}
}
