package ui

import (
	"net/http"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/sessionstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestClusterCredentialEndingsCloseStreamsOnEveryMember: a stream is held by
// whichever member the load balancer handed it to, and a revocation is made
// on whichever member — or shell — the operator reached. The member holding
// the stream closes it within a bus poll: a session revoked on the other
// member, a session and a token revoked by the CLI, which is no member at all,
// and a token revoked through the other member's token manager. The
// keepalives are an hour away throughout, so nothing but the bus can explain
// a close.
func TestClusterCredentialEndingsCloseStreamsOnEveryMember(t *testing.T) {
	streamTicks(t, time.Hour)
	dir, a, b := clusterPair(t)
	idp := newUIFakeIdP(t)
	clk := &clusterRenewClock{}
	// Every sign-in begins and completes on A; the streams live on B.
	withClusterOIDC(t, a, idp, a.ts.URL, clk)
	withClusterOIDC(t, b, idp, a.ts.URL, clk)
	signIn := func(email, sub string) *http.Client {
		t.Helper()
		idp.email, idp.sub = email, sub
		c := jarClient(t)
		req, _ := http.NewRequest(http.MethodGet, a.ts.URL+"/", nil)
		req.Header.Set("Accept", "text/html")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("sign in: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("sign-in chain ended with %d at %s", resp.StatusCode, resp.Request.URL)
		}
		return c
	}
	expectEnded := func(ls *liveStream, reason string) {
		t.Helper()
		got := ls.awaitEnd(t, 5*time.Second)
		if got.told["reason"] != reason {
			t.Fatalf("the %s stream on B ended telling %v (close %d %q), want reason %q",
				ls.kind, got.told, got.closeCode, got.closeReason, reason)
		}
	}

	// 1. A session revoked on A closes its socket on B, and B stops
	//    honouring the cookie at once rather than when its cache ages out.
	alice := signIn(aliceEmail, "sub-alice")
	aliceHash := sessionHashFromJar(t, alice, a.ts.URL)
	onB := openWSAt(t, b.ts.URL, "/api/ws", alice, nil)
	onB.awaitMessage(t, "task_update")
	if ok, err := a.srv.OIDC.RevokeSession(aliceHash, "security@example.com", ""); err != nil || !ok {
		t.Fatalf("RevokeSession on A = %v, %v", ok, err)
	}
	expectEnded(onB, streamEndSession)
	resp, err := alice.Get(b.ts.URL + "/api/me")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("B answered the revoked session's request with %d, want 401", resp.StatusCode)
	}

	// 2. The CLI deletes a session row and announces it; B closes the
	//    event stream the session opened there.
	bob := signIn(bobEmail, "sub-bob")
	bobHash := sessionHashFromJar(t, bob, a.ts.URL)
	sseOnB := openSSEAt(t, b.ts.URL, "/api/events", bob, nil)
	sseOnB.awaitMessage(t, "message")
	cli, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	sessions, err := sessionstore.New(cli)
	if err != nil {
		t.Fatal(err)
	}
	if existed, err := sessions.Delete(bobHash); err != nil || !existed {
		t.Fatalf("the CLI's delete = %v, %v", existed, err)
	}
	if err := AnnounceSessionsEnded(cli, "cli-20398", []string{bobHash}, false); err != nil {
		t.Fatal(err)
	}
	expectEnded(sseOnB, streamEndSession)

	// 3. A token revoked by the CLI, and 4. one revoked through A.
	mgrA, err := a.srv.tokenManager()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.srv.closeTokenManager)
	t.Cleanup(b.srv.closeTokenManager)
	mint := func(name string) apitoken.Minted {
		t.Helper()
		m, err := mgrA.Mint(apitoken.MintOptions{Name: name, Roles: []string{"viewer"}, CreatedBy: "root"})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	byCLI, throughA := mint("revoked-by-cli"), mint("revoked-through-a")
	cliStream := openWSAt(t, b.ts.URL, "/api/ws?scope=global", nil, bearerHeader(byCLI.Plaintext))
	aStream := openSSEAt(t, b.ts.URL, "/api/projects/events", nil, bearerHeader(throughA.Plaintext))
	aStream.awaitMessage(t, "projects")
	waitCluster(t, "B to hold both token streams", func() bool {
		n := 0
		for _, c := range b.srv.openStreamCredentials() {
			if c.tokenID == byCLI.Token.ID || c.tokenID == throughA.Token.ID {
				n++
			}
		}
		return n == 2
	})

	if err := cli.RevokeAPIToken(byCLI.Token.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := AnnounceTokensRevoked(cli, "cli-20398", []string{byCLI.Token.ID}); err != nil {
		t.Fatal(err)
	}
	expectEnded(cliStream, streamEndToken)

	if err := mgrA.Revoke(throughA.Token.ID); err != nil {
		t.Fatal(err)
	}
	expectEnded(aStream, streamEndToken)
}
