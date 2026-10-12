package statedb

import (
	"sync"
	"testing"
	"time"
)

// TestClaimProjectPathRefusesOverlaps: a claim is refused while a live claim
// is the same path, inside it or above it, and granted for a sibling that
// merely shares a prefix (Task 20418).
func TestClaimProjectPathRefusesOverlaps(t *testing.T) {
	db := openTestDB(t)
	if held, err := db.ClaimProjectPath(ProjectClaim{Path: "/srv/p", ClaimedBy: "alice"}, nil); err != nil || held != nil {
		t.Fatalf("first claim: %v %v", held, err)
	}
	for _, path := range []string{"/srv/p", "/srv/p/sub", "/srv"} {
		held, err := db.ClaimProjectPath(ProjectClaim{Path: path, ClaimedBy: "bob"}, nil)
		if err != nil || held == nil || held.Path != "/srv/p" || held.ClaimedBy != "alice" {
			t.Fatalf("claim %s = %+v %v, want refused, held by alice's /srv/p", path, held, err)
		}
	}
	if held, err := db.ClaimProjectPath(ProjectClaim{Path: "/srv/p2", ClaimedBy: "bob"}, nil); err != nil || held != nil {
		t.Fatalf("a sibling sharing the prefix was refused: %v %v", held, err)
	}
}

// TestClaimProjectPathTakesOverAStaleClaim: a claim the caller judges stale
// stops holding its path — the same path is taken over in place, and one
// inside it is dropped.
func TestClaimProjectPathTakesOverAStaleClaim(t *testing.T) {
	db := openTestDB(t)
	old := time.Now().Add(-time.Hour)
	for _, path := range []string{"/srv/a/inner", "/srv/b"} {
		if held, err := db.ClaimProjectPath(ProjectClaim{Path: path, ClaimedBy: "dead", ClaimedAt: old}, nil); err != nil || held != nil {
			t.Fatalf("seed %s: %v %v", path, held, err)
		}
	}
	stale := func(c ProjectClaim) bool { return c.ClaimedBy == "dead" }

	if held, err := db.ClaimProjectPath(ProjectClaim{Path: "/srv/a", ClaimedBy: "carol"}, stale); err != nil || held != nil {
		t.Fatalf("claiming above a stale claim: %v %v", held, err)
	}
	if _, ok, _ := db.ProjectClaimAt("/srv/a/inner"); ok {
		t.Fatal("the stale claim inside the new one survived")
	}

	if held, err := db.ClaimProjectPath(ProjectClaim{Path: "/srv/b", ClaimedBy: "carol", Owner: "carol@example.com"}, stale); err != nil || held != nil {
		t.Fatalf("taking over a stale claim: %v %v", held, err)
	}
	got, ok, err := db.ProjectClaimAt("/srv/b")
	if err != nil || !ok || got.ClaimedBy != "carol" || got.Owner != "carol@example.com" || got.State != ProjectClaimCreating ||
		time.Since(got.ClaimedAt) > time.Minute {
		t.Fatalf("the claim after the takeover = %+v %v %v", got, ok, err)
	}
	// A live claim is not taken over.
	if held, err := db.ClaimProjectPath(ProjectClaim{Path: "/srv/b", ClaimedBy: "dave"}, stale); err != nil || held == nil || held.ClaimedBy != "carol" {
		t.Fatalf("a live claim was taken over: %+v %v", held, err)
	}
}

func TestProjectClaimLifecycle(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.ClaimProjectPath(ProjectClaim{Path: "/srv/root/x", ClaimedBy: "alice"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteProjectClaim("/srv/root/x", true, "/srv/root"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := db.ProjectClaimAt("/srv/root/x")
	if err != nil || !ok || got.State != ProjectClaimCreated || !got.HubMade || got.Root != "/srv/root" || got.UpdatedAt.IsZero() {
		t.Fatalf("completed claim = %+v %v %v", got, ok, err)
	}
	if err := db.CompleteProjectClaim("/srv/nothing", false, ""); err == nil {
		t.Fatal("completing a claim nobody made succeeded")
	}
	if err := db.ReleaseProjectClaim("/srv/root/x"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db.ProjectClaimAt("/srv/root/x"); ok {
		t.Fatal("the claim survived its release")
	}
	if held, err := db.ClaimProjectPath(ProjectClaim{Path: "/srv/root/x"}, nil); err != nil || held != nil {
		t.Fatalf("a released path could not be claimed again: %v %v", held, err)
	}
}

// TestConcurrentClaimsOfOnePath: one of many concurrent claims of a path wins.
func TestConcurrentClaimsOfOnePath(t *testing.T) {
	db := openTestDB(t)
	const n = 16
	var wg sync.WaitGroup
	won := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := "/srv/race"
			if i%2 == 1 {
				path = "/srv/race/child"
			}
			held, err := db.ClaimProjectPath(ProjectClaim{Path: path}, nil)
			if err != nil {
				t.Error(err)
				return
			}
			if held == nil {
				won <- path
			}
		}(i)
	}
	wg.Wait()
	close(won)
	var winners []string
	for p := range won {
		winners = append(winners, p)
	}
	if len(winners) != 1 {
		t.Fatalf("%d claims of one tree won: %v", len(winners), winners)
	}
}
