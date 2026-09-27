package netfilter

import (
	"errors"
	"strings"
	"testing"
)

// TestExplainUnavailableNamesWhatIsMissing: the two ways an unprivileged
// process fails to reach nft(8) have different fixes, and sgx's agent was told
// to grant a capability when what it lacked was, in part, a socket family
// (Task 20352). Each case must say which.
func TestExplainUnavailableNamesWhatIsMissing(t *testing.T) {
	const netlinkRefused = "mnl.c:61: Unable to initialize Netlink socket: Address family not supported by protocol"
	for _, tc := range []struct {
		name   string
		uid    int
		holds  bool
		detail string
		want   []string
		reject []string
	}{
		{
			name: "no capability", uid: 995, holds: false, detail: netlinkRefused,
			want: []string{"needs CAP_NET_ADMIN", "does not hold", "uid 995", netlinkRefused},
		},
		{
			name: "capability but no netlink", uid: 995, holds: true, detail: netlinkRefused,
			want:   []string{"holds CAP_NET_ADMIN", "AF_NETLINK", netlinkRefused},
			reject: []string{"does not hold"},
		},
		{
			name: "capability, other failure", uid: 995, holds: true, detail: "Error: something else",
			want:   []string{"holds CAP_NET_ADMIN", "still failed"},
			reject: []string{"AF_NETLINK", "does not hold"},
		},
		{
			name: "root", uid: 0, holds: true, detail: "Error: something else",
			want: []string{"present but not usable"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := explainUnavailable(tc.uid, tc.holds, tc.detail)
			if !errors.Is(err, ErrUnavailable) {
				t.Errorf("does not wrap ErrUnavailable: %v", err)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("%q is missing from: %v", w, err)
				}
			}
			for _, r := range tc.reject {
				if strings.Contains(err.Error(), r) {
					t.Errorf("%q should not be in: %v", r, err)
				}
			}
		})
	}
}

// TestPrivilegeFailureRecognisesWhatNftPrints: a load that fails for want of
// privilege must surface as ErrUnavailable — a sandbox the operator can fix by
// granting something — not as a ruleset error. nft says "Operation not
// permitted", which the old check ("permission denied") never matched.
func TestPrivilegeFailureRecognisesWhatNftPrints(t *testing.T) {
	for detail, want := range map[string]bool{
		"Operation not permitted (you must be root)":                                  true,
		"netlink: Error: cache initialization failed: Operation not permitted":        true,
		"mnl.c:61: Unable to initialize Netlink socket: Address family not supported": true,
		"open /dev/x: permission denied":                                              true,
		"/dev/stdin:3:15-18: Error: syntax error, unexpected junk":                    false,
		"Error: Could not process rule: No such file or directory":                    false,
	} {
		if got := privilegeFailure(detail); got != want {
			t.Errorf("privilegeFailure(%q) = %t, want %t", detail, got, want)
		}
	}
}
