package ui

import (
	"os"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/hubteam"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/projectmember"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestClusterTeamChangesReachEveryMember (Task 20478): somebody taken off a
// team on one hub process loses the team's projects on the others at once —
// through the bus, not at their next TTL — and their stream there is closed.
// A change made by `cloop hub team`, which is no member at all, lands the same
// way.
func TestClusterTeamChangesReachEveryMember(t *testing.T) {
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
		m.srv.teams.opts = []hubteam.Option{hubteam.WithTTL(time.Hour)}
		if _, err := m.srv.OpenMemberStore(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(m.srv.closeMemberStore)
		if _, err := m.srv.OpenTeamStore(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(m.srv.closeTeamStore)
	}
	project := setupProjectDir(t, "shared with a team", nil)
	registerOwned(t, project, aliceEmail)

	// The team, bob on it, and the project shared with it — all through A.
	if _, err := a.srv.teamStore().Create(hubteam.Team{Slug: "payments"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.srv.teamStore().AddMember("payments", bobEmail, "root", nil); err != nil {
		t.Fatal(err)
	}
	a.srv.announceTeamsChange("payments")
	if _, _, err := a.srv.memberStore().Grant(projectMember(project, "team:payments", authz.RoleViewer), nil); err != nil {
		t.Fatal(err)
	}
	a.srv.announceMembershipChange(project)
	bob := &oidcauth.Identity{Sub: "sub-bob", Email: bobEmail}
	entry, _ := b.srv.registeredEntry(project)
	waitCluster(t, "B to see bob reach the project through the team", func() bool {
		return b.srv.identityCanSeeEntry(bob, entry)
	})

	// Bob's stream on B, registered the way handleWS registers one.
	hc := &hubClient{ch: make(chan wsMessage, 64), resync: make(chan struct{}, 1),
		kick: make(chan streamEnd, 1), id: "bob-on-b", user: bob}
	b.srv.hubMu.Lock()
	b.srv.hubClients[project] = map[*hubClient]struct{}{hc: {}}
	b.srv.hubMu.Unlock()

	// Off the team on A: B closes bob's stream there.
	if _, err := a.srv.teamStore().RemoveMember("payments", bobEmail, nil); err != nil {
		t.Fatal(err)
	}
	a.srv.announceTeamsChange("payments")
	select {
	case <-hc.kick:
	case <-time.After(5 * time.Second):
		t.Fatal("B did not close the stream of somebody taken off the team")
	}
	if b.srv.identityCanSeeEntry(bob, entry) {
		t.Fatal("B still shows the project to somebody A took off its team")
	}

	// The CLI adds carol from outside the cluster.
	cli, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, _, err := cli.AddTeamMember(statedb.TeamMemberRow{TeamSlug: "payments", IdentityKey: carolEmail}, nil); err != nil {
		t.Fatal(err)
	}
	if err := AnnounceTeamsChange(cli, "cli-"+itoa(os.Getpid()%10000), "payments"); err != nil {
		t.Fatal(err)
	}
	carol := &oidcauth.Identity{Sub: "sub-carol", Email: carolEmail}
	for _, m := range []*clusterMember{a, b} {
		waitCluster(t, "a member to see the CLI's team change", func() bool {
			return m.srv.identityCanSeeEntry(carol, entry)
		})
	}
}
