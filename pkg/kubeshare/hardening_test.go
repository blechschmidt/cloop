package kubeshare

// hardening_test.go: a share's metadata is its uploader's to write, and revoke
// and renew run with somebody else's credentials (Task 20420). Revoke deletes
// only what the share created, as read back from the cluster; renew acts only
// on the share's own cluster and ServiceAccount; and a pushed token goes only
// to the server that minted it.

import (
	"context"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	shareID = "3f9c2a1b"
	shareSA = "cloop-aks-dev-" + shareID
	alice   = "alice@example.com"
	mallory = "mallory@example.com"
)

// plant creates an object in the fake cluster as an administrator would,
// outside any share, and returns its path.
func plant(t *testing.T, c *Client, o Object, labels, annotations map[string]any) {
	t.Helper()
	meta := map[string]any{"name": o.Name}
	if o.Namespace != "" {
		meta["namespace"] = o.Namespace
	}
	if labels != nil {
		meta["labels"] = labels
	}
	if annotations != nil {
		meta["annotations"] = annotations
	}
	if err := c.Create(context.Background(), Manifest{Object: o, Collection: CollectionPath(o),
		Body: map[string]any{"metadata": meta}}); err != nil {
		t.Fatalf("plant %s: %v", o, err)
	}
}

func (f *fakeAPI) deletes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.requests {
		if strings.HasPrefix(r, "DELETE ") {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeAPI) has(o Object) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.objects[ObjectPath(o)]
	return ok
}

func labelled(id string) map[string]any { return map[string]any{LabelShare: id} }
func ownedBy(who string) map[string]any { return map[string]any{AnnotationOwner: who} }

// TestRevokeDeletesNothingTheShareDidNotCreate is the reported attack: a share
// whose metadata lists cluster-admin's binding, a pre-existing object with the
// share's own name, and objects labelled for it by someone else. An
// administrator revoking it deletes none of them.
func TestRevokeDeletesNothingTheShareDidNotCreate(t *testing.T) {
	api := newFakeAPI(t)
	admin, _ := NewClient(api.rest("cluster-admin"))
	defer admin.Close()

	clusterAdmin := Object{Kind: "ClusterRoleBinding", Name: "cluster-admin"}
	sameName := Object{Kind: "RoleBinding", Namespace: "team-a", Name: shareSA}
	decoy := Object{Kind: "RoleBinding", Namespace: "team-a", Name: "decoy"}
	otherShare := Object{Kind: "RoleBinding", Namespace: "team-a", Name: "other"}
	sa := Object{Kind: "ServiceAccount", Namespace: "home", Name: shareSA}
	systemSA := Object{Kind: "ServiceAccount", Namespace: "kube-system", Name: "default"}
	plant(t, admin, clusterAdmin, nil, nil)
	plant(t, admin, sameName, nil, nil)
	plant(t, admin, decoy, labelled(shareID), ownedBy(mallory))
	plant(t, admin, otherShare, labelled("deadbeef"), ownedBy(alice))
	plant(t, admin, sa, labelled(shareID), ownedBy(mallory))
	plant(t, admin, systemSA, nil, nil)
	before := api.count()

	crafted := Share{
		ID: shareID, Namespace: "home", ServiceAccount: shareSA, Namespaces: []string{"team-a"},
		Owner: alice, Renewal: RenewalManual,
		Objects: []Object{clusterAdmin, systemSA, decoy, otherShare,
			{Kind: "RoleBinding", Namespace: "kube-system", Name: "../../../clusterrolebindings/cluster-admin"},
			{Kind: "Secret", Namespace: "team-a", Name: "db"}},
	}
	res := Remove(context.Background(), admin, crafted)

	if d := api.deletes(); len(d) != 0 {
		t.Fatalf("revoke issued %d deletion(s) of objects the share did not create: %v", len(d), d)
	}
	if api.count() != before {
		t.Fatalf("objects went missing: %d before, %d after", before, api.count())
	}
	for _, o := range []Object{clusterAdmin, sameName, decoy, otherShare, sa, systemSA} {
		if !api.has(o) {
			t.Errorf("%s was deleted", o)
		}
		if _, ok := res.Refused[o]; !ok {
			t.Errorf("%s is not reported as refused: %+v", o, res.Refused)
		}
	}
	if res.Clean() {
		t.Error("a revoke whose ServiceAccount is not the share's reported itself clean")
	}
	if err := res.Failed[sa]; err == nil || !strings.Contains(err.Error(), "stay valid") {
		t.Errorf("the ServiceAccount's failure does not say its tokens live on: %v", err)
	}
	for o, why := range res.Refused {
		if o.Name == "../../../clusterrolebindings/cluster-admin" || o.Kind == "Secret" {
			if !strings.Contains(why, "not an object a share creates") {
				t.Errorf("%s: %q", o, why)
			}
		}
	}
	api.mu.Lock()
	for _, r := range api.requests {
		if strings.Contains(r, "..") || strings.Contains(r, "/secrets/") {
			t.Errorf("a request was built from a name no share creates: %s", r)
		}
	}
	api.mu.Unlock()
	if left, err := Remaining(context.Background(), admin, crafted); err != nil || len(left) != 0 {
		t.Errorf("Remaining counts objects that are not the share's: %v, %v", left, err)
	}
}

// TestRevokeDeletesTheSharesOwnObjects: what the share created — its label and
// its owner's annotation — goes; a decoy labelled for it by someone else stays.
func TestRevokeDeletesTheSharesOwnObjects(t *testing.T) {
	api := newFakeAPI(t)
	dev, _ := NewClient(api.rest("developer"))
	defer dev.Close()
	p, err := NewPlan(Request{Name: "aks-dev", ID: shareID, Namespaces: []string{"team-a", "team-b"},
		Access: AccessWrite, ServiceAccountNamespace: "home", Renewal: RenewalHub, Owner: alice}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), dev, p); err != nil {
		t.Fatal(err)
	}
	decoy := Object{Kind: "RoleBinding", Namespace: "team-b", Name: "decoy"}
	plant(t, dev, decoy, labelled(shareID), ownedBy(mallory))

	// The hub's record says alice — as her owner key, which the terminal of
	// an older cloop wrote as the email it was given.
	share := p.Share()
	share.Owner = "Alice@Example.com"
	res := Remove(context.Background(), dev, share)
	if !res.Clean() {
		t.Fatalf("Remove left %v", res.Failed)
	}
	if len(res.Removed) != 5 {
		t.Errorf("removed %v, want the share's five objects", res.Removed)
	}
	if !api.has(decoy) {
		t.Fatal("the decoy was deleted")
	}
	if _, ok := res.Refused[decoy]; !ok {
		t.Error("the decoy is not reported as refused")
	}
	if left, err := Remaining(context.Background(), dev, share); err != nil || len(left) != 0 {
		t.Errorf("Remaining = %v, %v", left, err)
	}
}

// TestRevokeDoesNotDeleteAnObjectChangedAfterItWasRead: the deletion names the
// object by uid and resourceVersion, so one relabelled, re-annotated or
// replaced between the check and the delete is refused by the API server.
func TestRevokeDoesNotDeleteAnObjectChangedAfterItWasRead(t *testing.T) {
	api := newFakeAPI(t)
	dev, _ := NewClient(api.rest("developer"))
	defer dev.Close()
	p, _ := NewPlan(Request{Name: "aks-dev", ID: shareID, Namespaces: []string{"team-a"}, Owner: alice}, now)
	if _, err := Apply(context.Background(), dev, p); err != nil {
		t.Fatal(err)
	}
	api.onGet = func(path string, obj map[string]any) {
		obj["metadata"].(map[string]any)["resourceVersion"] = "changed-under-you"
	}
	sa := Object{Kind: "ServiceAccount", Namespace: "team-a", Name: p.ServiceAccount}
	res := Remove(context.Background(), dev, p.Share())
	if err := res.Failed[sa]; err == nil || !strings.Contains(err.Error(), "changed after it was checked") {
		t.Fatalf("Failed[%s] = %v", sa, err)
	}
	if !api.has(sa) {
		t.Fatal("an object that changed after it was read was deleted")
	}
}

func TestOwnerMatches(t *testing.T) {
	for _, tc := range []struct {
		annotation, owner string
		want              bool
	}{
		{"alice@example.com", "alice@example.com", true},
		{"Alice@Example.com", "alice@example.com", true},
		{"sub:abc", "sub:abc", true},
		{"abc", "sub:abc", true}, // an older terminal wrote the bare subject
		{"ABC", "sub:abc", false},
		{"mallory@example.com", "alice@example.com", false},
		{"", "alice@example.com", false},
		{"alice@example.com", "", false},
		{"", "", true}, // a hub with no identity provider
	} {
		if got := OwnerMatches(tc.annotation, tc.owner); got != tc.want {
			t.Errorf("OwnerMatches(%q, %q) = %v, want %v", tc.annotation, tc.owner, got, tc.want)
		}
	}
}

func TestObjectValid(t *testing.T) {
	for _, tc := range []struct {
		o    Object
		want bool
	}{
		{Object{Kind: "ServiceAccount", Namespace: "home", Name: shareSA}, true},
		{Object{Kind: "ClusterRoleBinding", Name: shareSA}, true},
		{Object{Kind: "ClusterRoleBinding", Namespace: "home", Name: shareSA}, false},
		{Object{Kind: "RoleBinding", Name: shareSA}, false},
		{Object{Kind: "RoleBinding", Namespace: "a", Name: "x/../y"}, false},
		{Object{Kind: "RoleBinding", Namespace: "a/b", Name: "x"}, false},
		{Object{Kind: "Secret", Namespace: "a", Name: "x"}, false},
		{Object{Kind: "Role", Namespace: "a", Name: "X"}, false},
	} {
		if got := tc.o.Valid(); got != tc.want {
			t.Errorf("%+v.Valid() = %v, want %v", tc.o, got, tc.want)
		}
	}
}

func TestSameClusterRefusesAnotherServerOrCA(t *testing.T) {
	ca := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	share := Share{Server: "https://aks-dev.example.com:443", CAFingerprint: CAFingerprint(ca)}
	if err := share.SameCluster("HTTPS://AKS-dev.example.com:443/", ca); err != nil {
		t.Errorf("the same server, spelled differently: %v", err)
	}
	if err := share.SameCluster("https://prod.example.com:443", ca); err == nil ||
		!strings.Contains(err.Error(), "--context") {
		t.Errorf("another server: %v", err)
	}
	if err := share.SameCluster("https://aks-dev.example.com:443", []byte("another CA")); err == nil ||
		!strings.Contains(err.Error(), "another CA") {
		t.Errorf("another CA: %v", err)
	}
	if err := share.SameCluster("https://aks-dev.example.com:443", nil); err == nil {
		t.Error("a context trusting the system roots matched a share pinned to its own CA")
	}
	if err := (Share{Server: share.Server, CAFingerprint: CANone}).SameCluster(share.Server, nil); err != nil {
		t.Errorf("both on the system roots: %v", err)
	}
	if err := (Share{Server: share.Server}).SameCluster(share.Server, ca); err == nil ||
		!strings.Contains(err.Error(), "share the cluster again") {
		t.Errorf("a share with no recorded CA: %v", err)
	}
}

func TestVerifyServiceAccountRefusesAServiceAccountTheShareDidNotCreate(t *testing.T) {
	api := newFakeAPI(t)
	admin, _ := NewClient(api.rest("cluster-admin"))
	defer admin.Close()
	plant(t, admin, Object{Kind: "ServiceAccount", Namespace: "kube-system", Name: "default"}, nil, nil)
	plant(t, admin, Object{Kind: "ServiceAccount", Namespace: "home", Name: shareSA}, labelled(shareID), ownedBy(mallory))
	plant(t, admin, Object{Kind: "ServiceAccount", Namespace: "own", Name: shareSA}, labelled(shareID), ownedBy(alice))

	gets := func() int {
		api.mu.Lock()
		defer api.mu.Unlock()
		n := 0
		for _, r := range api.requests {
			if strings.HasPrefix(r, "GET ") {
				n++
			}
		}
		return n
	}
	before := gets()
	err := VerifyServiceAccount(context.Background(), admin,
		Share{ID: shareID, Namespace: "kube-system", ServiceAccount: "default", Owner: alice})
	if err == nil || !strings.Contains(err.Error(), "not one a share with id") {
		t.Fatalf("kube-system/default: %v", err)
	}
	if gets() != before {
		t.Error("the cluster was asked about a ServiceAccount no share creates")
	}
	if err := VerifyServiceAccount(context.Background(), admin,
		Share{ID: shareID, Namespace: "home", ServiceAccount: shareSA, Owner: alice}); err == nil ||
		!strings.Contains(err.Error(), mallory) {
		t.Fatalf("another owner's ServiceAccount: %v", err)
	}
	if err := VerifyServiceAccount(context.Background(), admin,
		Share{ID: shareID, Namespace: "own", ServiceAccount: shareSA, Owner: alice}); err != nil {
		t.Fatalf("the share's own ServiceAccount: %v", err)
	}
}

// TestAdoptSendsATokenOnlyToTheServerThatMintedIt: the confirmation goes to
// the server the stored kubeconfig names, which the share's uploader chose; a
// token minted anywhere else never leaves the hub.
func TestAdoptSendsATokenOnlyToTheServerThatMintedIt(t *testing.T) {
	stored := newFakeAPI(t) // the server the share's kubeconfig names
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: stored.srv.Certificate().Raw})
	first := jwt("home", shareSA, now, now.Add(time.Hour))
	doc, err := RenderKubeconfig(KubeconfigParams{Name: "aks-dev", Server: stored.srv.URL, CAData: pemCA,
		Namespace: "home", Token: first})
	if err != nil {
		t.Fatal(err)
	}
	pushed := jwt("home", shareSA, now, now.Add(2*time.Hour))
	stored.whoami = "system:serviceaccount:home:" + shareSA

	for _, tc := range []struct {
		name   string
		origin Origin
	}{
		{"no origin", Origin{}},
		{"another server", Origin{Server: "https://real-cluster.example.com:6443", CAFingerprint: CAFingerprint(pemCA)}},
		{"another CA", Origin{Server: stored.srv.URL, CAFingerprint: CAFingerprint([]byte("x"))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stored.mu.Lock()
			stored.requests = nil
			stored.mu.Unlock()
			if _, err := Adopt(context.Background(), doc, pushed, tc.origin, now); !errors.Is(err, ErrWrongServer) {
				t.Fatalf("err = %v, want ErrWrongServer", err)
			}
			stored.mu.Lock()
			defer stored.mu.Unlock()
			if len(stored.requests) != 0 {
				t.Fatalf("the token was sent to the stored server: %v", stored.requests)
			}
		})
	}
	if _, err := Adopt(context.Background(), doc, pushed,
		Origin{Server: stored.srv.URL + "/", CAFingerprint: CAFingerprint(pemCA)}, now); err != nil {
		t.Fatalf("the server that minted it: %v", err)
	}
}

func TestParseClaimsRefusesNamesTheAPIServerCouldNotIssue(t *testing.T) {
	for _, tc := range []struct{ ns, name string }{
		{"a/../../apis", "x"},
		{"kube-system", "admin/token?x="},
		{"Kube-System", "admin"},
		{"kube-system", "Admin"},
		{"kube-system", strings.Repeat("a", 254)},
	} {
		if _, err := ParseClaims(jwt(tc.ns, tc.name, now, now.Add(time.Hour))); !errors.Is(err, ErrNotServiceAccountToken) {
			t.Errorf("namespace %q, name %q: err = %v", tc.ns, tc.name, err)
		}
	}
	if _, err := ParseClaims(jwt("home", shareSA, now, now.Add(time.Hour))); err != nil {
		t.Errorf("a share's own token: %v", err)
	}
}

func TestIsShareServiceAccount(t *testing.T) {
	for _, tc := range []struct {
		name, id string
		want     bool
	}{
		{shareSA, shareID, true},
		{"cloop-share-" + shareID, shareID, true},
		{"default", shareID, false},
		{"cloop-" + shareID, shareID, false},
		{shareSA, "deadbeef", false},
		{"admin-" + shareID, shareID, false},
		{"cloop-a.b-" + shareID, shareID, false},
		{shareSA, "", false},
	} {
		if got := IsShareServiceAccount(tc.name, tc.id); got != tc.want {
			t.Errorf("IsShareServiceAccount(%q, %q) = %v, want %v", tc.name, tc.id, got, tc.want)
		}
	}
}

// TestExpectedObjectsAreThePlansObjects: what the hub records for a share is
// exactly what its plan created.
func TestExpectedObjectsAreThePlansObjects(t *testing.T) {
	for _, req := range []Request{
		{Name: "aks-dev", ID: shareID, Namespaces: []string{"a", "b"}, Access: AccessWrite, ServiceAccountNamespace: "home", Renewal: RenewalHub},
		{Name: "aks-dev", ID: shareID, Namespaces: []string{"a"}},
		{Name: "aks-dev", ID: shareID, ClusterWide: true, ServiceAccountNamespace: "home"},
	} {
		p, err := NewPlan(req, now)
		if err != nil {
			t.Fatal(err)
		}
		share, _ := FromMetadata(p.Share().Metadata())
		if got, want := FormatObjects(share.ExpectedObjects()), FormatObjects(p.Objects()); got != want {
			t.Errorf("ExpectedObjects = %s, want %s", got, want)
		}
	}
}
