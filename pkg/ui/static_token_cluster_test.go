package ui

import (
	"net/http"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/statictoken"
)

// TestClusterStaticTokenRetirementReachesEveryMember: two hub processes serve
// one control plane with the same static token. Retired through A, the token
// is refused by B and the stream it opened on B closes; retired by the CLI,
// which is no member, the same — both within a bus poll. The retired set's
// periodic re-read and the streams' keepalives are an hour away throughout,
// so nothing but the bus notice can explain either (Task 20406).
func TestClusterStaticTokenRetirementReachesEveryMember(t *testing.T) {
	streamTicks(t, time.Hour)
	prev := staticTokenRefreshNS.Swap(int64(time.Hour))
	t.Cleanup(func() { staticTokenRefreshNS.Store(prev) })

	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLOOP_HOME", t.TempDir())
	dir := setupProjectDir(t, "one control plane, two hubs", nil)
	a := newClusterMemberWithToken(t, dir, staticTok20406)
	b := newClusterMemberWithToken(t, dir, staticTok20406)
	waitCluster(t, "the members to see each other", func() bool { return a.node.HasPeers() && b.node.HasPeers() })
	t.Cleanup(a.srv.closeTokenManager)
	t.Cleanup(b.srv.closeTokenManager)
	a.srv.RPS, a.srv.Burst, b.srv.RPS, b.srv.Burst = 10000, 10000, 10000, 10000

	static := bearerHeader(staticTok20406)
	for _, m := range []*clusterMember{a, b} {
		if code, _, _ := staticCall(t, m.ts.URL, http.MethodGet, "/api/state", static, ""); code != http.StatusOK {
			t.Fatalf("the static token on a member = %d before retirement", code)
		}
	}
	onB := openWSAt(t, b.ts.URL, "/api/ws", nil, static)
	onB.awaitMessage(t, "task_update")

	// 1. Retired through A: B refuses it, and closes what it opened there.
	mintAdminToken(t, a.srv)
	retireViaRoute(t, a.ts.URL, static, false)
	waitCluster(t, "B to refuse the retired token", func() bool {
		code, _, _ := staticCall(t, b.ts.URL, http.MethodGet, "/api/state", static, "")
		return code == http.StatusUnauthorized
	})
	code, body, _ := staticCall(t, b.ts.URL, http.MethodGet, "/api/state?token="+staticTok20406, nil, "")
	wantRetiredRefusal(t, "B, the ?token= form", code, body, "static-token")
	expectStaticTokenEnded(t, onB)

	// 2. Two members on a new value; the CLI retires it and announces it.
	const rotated = "static-admin-token-20406-second"
	c := newClusterMemberWithToken(t, dir, rotated)
	d := newClusterMemberWithToken(t, dir, rotated)
	waitCluster(t, "the new members to see each other", func() bool { return c.node.HasPeers() && d.node.HasPeers() })
	t.Cleanup(c.srv.closeTokenManager)
	t.Cleanup(d.srv.closeTokenManager)
	c.srv.RPS, c.srv.Burst, d.srv.RPS, d.srv.Burst = 10000, 10000, 10000, 10000
	second := bearerHeader(rotated)
	if code, _, _ := staticCall(t, d.ts.URL, http.MethodGet, "/api/state", second, ""); code != http.StatusOK {
		t.Fatalf("the new value on D = %d", code)
	}
	sseOnD := openSSEAt(t, d.ts.URL, "/api/events", nil, second)
	sseOnD.awaitMessage(t, "message")

	cli, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	fp := statictoken.Fingerprint(rotated)
	if _, written, err := cli.RetireStaticToken(statedb.RetiredStaticTokenRow{
		Fingerprint: fp, RetiredBy: "cli:root", Reason: "rotating",
	}, nil); err != nil || !written {
		t.Fatalf("the CLI's retirement = %v, %v", written, err)
	}
	if err := AnnounceStaticTokenRetired(cli, "cli-20406", fp); err != nil {
		t.Fatal(err)
	}
	expectStaticTokenEnded(t, sseOnD)
	code, body, _ = staticCall(t, d.ts.URL, http.MethodGet, "/api/state", second, "")
	wantRetiredRefusal(t, "D after the CLI's announcement", code, body, "cli:root")
	code, body, _ = staticCall(t, c.ts.URL, http.MethodGet, "/api/state", second, "")
	wantRetiredRefusal(t, "C after the CLI's announcement", code, body, "cli:root")
}
