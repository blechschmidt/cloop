package gitproxy

import (
	"net"
	"strings"
	"testing"
)

// TestAdvertisedBaseURL pins what a hub points sandboxes at. It moved here
// from pkg/ui with the function, so `cloop hub doctor` reports the base the
// hub actually advertises rather than its own reading of the config.
func TestAdvertisedBaseURL(t *testing.T) {
	tests := []struct {
		name      string
		advertise string
		addr      net.Addr
		want      string
		wantErr   bool
	}{
		{
			name: "advertised url wins",
			// The bound address is right only when the sandbox shares the
			// hub's network namespace; everything else must be told.
			advertise: "https://hub.internal:8443",
			addr:      &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000},
			want:      "https://hub.internal:8443",
		},
		{
			name:      "trailing slash is trimmed",
			advertise: "https://hub.internal:8443/",
			addr:      &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000},
			want:      "https://hub.internal:8443",
		},
		{
			name: "bound loopback",
			addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9000},
			want: "https://127.0.0.1:9000",
		},
		{
			// 0.0.0.0 is a bind address and never a destination, so it must
			// not be advertised as one.
			name: "unspecified bind becomes loopback",
			addr: &net.TCPAddr{IP: net.IPv4zero, Port: 9000},
			want: "https://127.0.0.1:9000",
		},
		{
			name:    "a non-TCP listener cannot be advertised",
			addr:    &net.UnixAddr{Name: "/tmp/x", Net: "unix"},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AdvertisedBaseURL(tc.advertise, tc.addr)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("AdvertisedBaseURL: %v", err)
			}
			if got != tc.want {
				t.Fatalf("AdvertisedBaseURL = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestNormalizeBaseURLRefusesWhatNoSandboxCanDial: a Host that names no host,
// or a port no client can dial, was accepted and handed to every sandbox as
// its git remote (Task 20387).
func TestNormalizeBaseURLRefusesWhatNoSandboxCanDial(t *testing.T) {
	for _, raw := range []string{"https://:8443", "https://hub.internal:0", "https://hub.internal:65536"} {
		if got, err := NormalizeBaseURL(raw); err == nil {
			t.Errorf("NormalizeBaseURL(%q) = %q, want a refusal", raw, got)
		}
	}
	for raw, want := range map[string]string{
		"https://hub.internal:65535": "https://hub.internal:65535",
		"https://[::1]:8443/":        "https://[::1]:8443",
		"https://hub.internal:":      "https://hub.internal:",
	} {
		got, err := NormalizeBaseURL(raw)
		if err != nil || got != want {
			t.Errorf("NormalizeBaseURL(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	if _, err := NewRegistry("https://:8443"); err == nil || !strings.Contains(err.Error(), "no host") {
		t.Errorf("NewRegistry does not apply the exported rule: %v", err)
	}
}
