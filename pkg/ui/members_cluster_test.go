package ui

import (
	"os"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/projectmember"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestClusterMembershipChangesReachEveryMember: a membership written through
// one hub process takes effect on the others at once — through the bus, not
// at their next TTL — and a removed member's stream on another process is
// closed. The same holds for a change made by `cloop project members`, which
// is no member at all.
func TestClusterMembershipChangesReachEveryMember(t *testing.T) {
	dir, a, b := clusterPair(t)
	auth, err := oidcauth.New(oidcauth.Config{Enabled: true, Issuer: "https://idp.example.com",
		ClientID: "c", ClientSecret: "s", RedirectURL: "https://hub.example.com/auth/callback"})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []*clusterMember{a, b} {
		m.srv.OIDC = auth
		// An hour: within this test only the bus can make B see A's write.
		m.srv.members.opts = []projectmember.Option{projectmember.WithTTL(time.Hour)}
		if _, err := m.srv.OpenMemberStore(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(m.srv.closeMemberStore)
	}
	project := setupProjectDir(t, "shared across members", nil)
	registerOwned(t, project, aliceEmail)

	// Bob's stream on B, registered the way handleWS registers one.
	hc := &hubClient{ch: make(chan wsMessage, 64), resync: make(chan struct{}, 1),
		kick: make(chan string, 1), id: "bob-on-b", user: &oidcauth.Identity{Sub: "sub-bob", Email: bobEmail}}
	b.srv.hubMu.Lock()
	b.srv.hubClients[project] = map[*hubClient]struct{}{hc: {}}
	b.srv.hubMu.Unlock()

	// Granted on A, as the REST handler does it: write, then announce.
	if _, _, err := a.srv.memberStore().Grant(projectMember(project, bobEmail, authz.RoleViewer), nil); err != nil {
		t.Fatal(err)
	}
	a.srv.announceMembershipChange(project)
	waitCluster(t, "B to see A's grant", func() bool {
		_, ok := b.srv.memberStore().RoleFor(project, bobEmail)
		return ok
	})
	select {
	case reason := <-hc.kick:
		t.Fatalf("B closed a member's stream on a grant: %s", reason)
	default:
	}

	// Revoked on A: B drops it and closes bob's stream there.
	if _, err := a.srv.memberStore().Revoke(project, bobEmail, nil); err != nil {
		t.Fatal(err)
	}
	a.srv.announceMembershipChange(project)
	select {
	case <-hc.kick:
	case <-time.After(5 * time.Second):
		t.Fatal("B did not close the removed member's stream")
	}
	if _, ok := b.srv.memberStore().RoleFor(project, bobEmail); ok {
		t.Fatal("B still grants a membership A revoked")
	}
	b.srv.hubMu.Lock()
	_, still := b.srv.hubClients[project][hc]
	b.srv.hubMu.Unlock()
	if still {
		t.Error("the closed stream is still in B's room")
	}

	// The CLI writes the table and announces from outside the cluster.
	cli, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, _, err := cli.PutProjectMember(statedb.ProjectMemberRow{ProjectPath: project, IdentityKey: carolEmail, Role: "operator"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := AnnounceMembershipChange(cli, "cli-"+itoa(os.Getpid()%10000), project); err != nil {
		t.Fatal(err)
	}
	for _, m := range []*clusterMember{a, b} {
		waitCluster(t, "a member to see the CLI's grant", func() bool {
			role, ok := m.srv.memberStore().RoleFor(project, carolEmail)
			return ok && role == authz.RoleOperator
		})
	}
}
