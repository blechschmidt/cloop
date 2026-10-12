package kubeshare

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

var now = time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)

// jwt builds an unsigned token with a ServiceAccount's claims. The signature
// is never checked by this package (see token.go), so a placeholder is enough.
func jwt(ns, name string, iat, exp time.Time) string {
	payload, _ := json.Marshal(map[string]any{
		"sub": "system:serviceaccount:" + ns + ":" + name,
		"iat": iat.Unix(), "exp": exp.Unix(),
		"kubernetes.io": map[string]any{
			"namespace": ns, "serviceaccount": map[string]any{"name": name, "uid": "uid-" + name},
		},
	})
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + enc.EncodeToString(payload) + ".c2ln"
}

// ── the plan ────────────────────────────────────────────────────────────────

func TestPlanDefaultsAndRefusals(t *testing.T) {
	read, err := NewPlan(Request{Name: "aks-dev", Namespaces: []string{"team-a", " team-b", "team-a"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if read.Access != AccessRead || read.ServiceAccountNamespace != "team-a" || read.TTL != DefaultTTL ||
		read.Renewal != RenewalManual || len(read.Namespaces) != 2 {
		t.Errorf("read defaults = access %s, sa ns %s, ttl %s, renewal %s, namespaces %v",
			read.Access, read.ServiceAccountNamespace, read.TTL, read.Renewal, read.Namespaces)
	}
	if !strings.HasPrefix(read.ServiceAccount, "cloop-aks-dev-") || len(read.ID) != 8 {
		t.Errorf("service account %q, id %q", read.ServiceAccount, read.ID)
	}

	for _, tc := range []struct {
		name string
		req  Request
		want string
	}{
		{"write needs a separate home", Request{Name: "x", Namespaces: []string{"a"}, Access: AccessWrite}, "needs --sa-namespace"},
		{"write may not live where it writes", Request{Name: "x", Namespaces: []string{"a", "b"}, Access: AccessWrite,
			ServiceAccountNamespace: "b"}, "one of the namespaces this share writes"},
		{"cluster-wide write", Request{Name: "x", ClusterWide: true, Access: AccessWrite, ServiceAccountNamespace: "s"}, "cluster-wide write access is refused"},
		{"cluster-wide and namespaces", Request{Name: "x", ClusterWide: true, Namespaces: []string{"a"}}, "drop --namespaces"},
		{"cluster-wide needs a home", Request{Name: "x", ClusterWide: true}, "--cluster-wide needs --sa-namespace"},
		{"no namespaces", Request{Name: "x"}, "name the namespaces"},
		{"a glob", Request{Name: "x", Namespaces: []string{"team-*"}}, "patterns are not accepted"},
		{"not a namespace", Request{Name: "x", Namespaces: []string{"Team_A"}}, "not a namespace name"},
		{"too short", Request{Name: "x", Namespaces: []string{"a"}, TTL: 5 * time.Minute}, "between 10m0s"},
		{"too long", Request{Name: "x", Namespaces: []string{"a"}, TTL: 30 * 24 * time.Hour}, "and 7d"},
		{"bad access", Request{Name: "x", Namespaces: []string{"a"}, Access: "admin"}, "want read or write"},
		{"bad secret name", Request{Name: "has space", Namespaces: []string{"a"}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPlan(tc.req, now)
			if err == nil {
				t.Fatal("NewPlan accepted it")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}

	ok, err := NewPlan(Request{Name: "deploy", Namespaces: []string{"a", "b"}, Access: AccessWrite,
		ServiceAccountNamespace: "cloop-shares", Renewal: RenewalHub, TTL: time.Hour}, now)
	if err != nil {
		t.Fatalf("write with a separate home: %v", err)
	}
	if ok.ServiceAccountNamespace != "cloop-shares" {
		t.Errorf("sa ns = %s", ok.ServiceAccountNamespace)
	}
}

func TestPlanNamesFitAsDNSLabels(t *testing.T) {
	p, err := NewPlan(Request{Name: "A_very.long-Secret_Name.for.a.cluster.that.goes.on.and.on.and.on",
		Namespaces: []string{"a"}, Renewal: RenewalHub}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range p.Objects() {
		if len(o.Name) > 63 || !dnsLabel.MatchString(o.Name) {
			t.Errorf("%s: name %q is not a DNS label", o.Kind, o.Name)
		}
	}
	if got := serviceAccountName("___", "abcd1234"); got != "cloop-share-abcd1234" {
		t.Errorf("an unsluggable name gave %q", got)
	}
}

func TestPlanObjectsAndManifests(t *testing.T) {
	p, err := NewPlan(Request{Name: "aks-dev", ID: "3f9c2a1b", Namespaces: []string{"team-a", "team-b"},
		Access: AccessWrite, ServiceAccountNamespace: "cloop-shares", Renewal: RenewalHub,
		Hub: "https://hub.example.com", Owner: "alice@example.com"}, now)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ServiceAccount cloop-shares/cloop-aks-dev-3f9c2a1b",
		"RoleBinding team-a/cloop-aks-dev-3f9c2a1b",
		"RoleBinding team-b/cloop-aks-dev-3f9c2a1b",
		"Role cloop-shares/cloop-aks-dev-3f9c2a1b-renew",
		"RoleBinding cloop-shares/cloop-aks-dev-3f9c2a1b-renew",
	}
	var got []string
	for _, o := range p.Objects() {
		got = append(got, o.String())
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("objects:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	byName := map[string]Manifest{}
	for _, m := range p.Manifests() {
		byName[m.Object.String()] = m
		meta := m.Body["metadata"].(map[string]any)
		labels := meta["labels"].(map[string]any)
		if labels[LabelShare] != "3f9c2a1b" || labels[LabelManagedBy] != "cloop" {
			t.Errorf("%s labels = %v", m.Object, labels)
		}
		ann := meta["annotations"].(map[string]any)
		if ann[AnnotationOwner] != "alice@example.com" || ann[AnnotationHub] != "https://hub.example.com" {
			t.Errorf("%s annotations = %v", m.Object, ann)
		}
		if _, executorLabel := labels["cloop.dev/managed"]; executorLabel {
			t.Errorf("%s carries the executor's label; its orphan sweep would delete the share", m.Object)
		}
	}
	sa := byName["ServiceAccount cloop-shares/cloop-aks-dev-3f9c2a1b"]
	if sa.Collection != "/api/v1/namespaces/cloop-shares/serviceaccounts" || sa.Body["automountServiceAccountToken"] != false {
		t.Errorf("service account manifest = %s %v", sa.Collection, sa.Body)
	}
	rb := byName["RoleBinding team-a/cloop-aks-dev-3f9c2a1b"]
	if ref := rb.Body["roleRef"].(map[string]any); ref["kind"] != "ClusterRole" || ref["name"] != "edit" {
		t.Errorf("write binding roleRef = %v", ref)
	}
	subj := rb.Body["subjects"].([]any)[0].(map[string]any)
	if subj["name"] != "cloop-aks-dev-3f9c2a1b" || subj["namespace"] != "cloop-shares" || subj["kind"] != "ServiceAccount" {
		t.Errorf("binding subject = %v", subj)
	}
	role := byName["Role cloop-shares/cloop-aks-dev-3f9c2a1b-renew"]
	rule := role.Body["rules"].([]any)[0].(map[string]any)
	b, _ := json.Marshal(rule)
	if string(b) != `{"apiGroups":[""],"resourceNames":["cloop-aks-dev-3f9c2a1b"],"resources":["serviceaccounts/token"],"verbs":["create"]}` {
		t.Errorf("the self-renewal rule is %s; it must create this ServiceAccount's token and nothing else", b)
	}
	renewRB := byName["RoleBinding cloop-shares/cloop-aks-dev-3f9c2a1b-renew"]
	if ref := renewRB.Body["roleRef"].(map[string]any); ref["kind"] != "Role" || ref["name"] != "cloop-aks-dev-3f9c2a1b-renew" {
		t.Errorf("renewal binding roleRef = %v", ref)
	}

	// Without hub renewal there is no self-renewal Role at all.
	manual, _ := NewPlan(Request{Name: "aks-dev", Namespaces: []string{"team-a"}}, now)
	for _, o := range manual.Objects() {
		if o.Kind == "Role" || strings.HasSuffix(o.Name, "-renew") {
			t.Errorf("a manually renewed share would create %s", o)
		}
	}
	// And only an explicit flag binds cluster-wide.
	for _, o := range manual.Objects() {
		if o.Kind == "ClusterRoleBinding" {
			t.Errorf("a namespaced share creates %s", o)
		}
	}
	cw, err := NewPlan(Request{Name: "obs", ClusterWide: true, ServiceAccountNamespace: "monitoring"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if objs := cw.Objects(); len(objs) != 2 || objs[1].Kind != "ClusterRoleBinding" {
		t.Errorf("cluster-wide objects = %v", objs)
	}
	if ref := cw.Manifests()[1].Body["roleRef"].(map[string]any); ref["name"] != "view" {
		t.Errorf("cluster-wide binds %v", ref)
	}
}

func TestShareMetadataRoundTrips(t *testing.T) {
	p, _ := NewPlan(Request{Name: "aks-dev", ID: "3f9c2a1b", Namespaces: []string{"a", "b"}, Access: AccessWrite,
		ServiceAccountNamespace: "home", Renewal: RenewalHub, Server: "https://k8s.example.com", Context: "aks"}, now)
	meta := p.Share().Metadata()
	RecordToken(meta, Claims{Namespace: "home", ServiceAccount: p.ServiceAccount,
		IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour)})
	s, ok := FromMetadata(meta)
	if !ok {
		t.Fatal("not a share")
	}
	if s.ID != "3f9c2a1b" || s.Renewal != RenewalHub || s.Access != AccessWrite || s.Namespace != "home" ||
		s.ServiceAccount != p.ServiceAccount || strings.Join(s.Namespaces, ",") != "a,b" || s.Context != "aks" ||
		len(s.Objects) != len(p.Objects()) || !s.ExpiresAt.Equal(now.Add(24*time.Hour)) {
		t.Errorf("round trip = %+v", s)
	}
	for _, k := range []string{MetaShare, MetaRenewal, MetaServiceAccount, MetaNamespaces, MetaAccess, MetaServer, MetaObjects} {
		if meta[k] == "" {
			t.Errorf("metadata lacks %s", k)
		}
	}
	// Nothing about the token itself is ever metadata: it lands in audit rows.
	for k, v := range meta {
		if strings.Contains(strings.ToLower(k), "token") || strings.Count(v, ".") == 2 && len(v) > 40 {
			t.Errorf("metadata %s=%q looks like it carries a credential", k, v)
		}
	}

	if s.Due(now.Add(11 * time.Hour)) {
		t.Error("due with more than half the lifetime left")
	}
	if !s.Due(now.Add(12 * time.Hour)) {
		t.Error("not due at half-life")
	}
	if (Share{}).Due(now) != true {
		t.Error("a share with unknown times is not due")
	}

	RecordFailure(meta, strings.Repeat("x", 500), now, false)
	if len(meta[MetaRenewError]) > maxMetaValue+3 {
		t.Errorf("a renewal error is stored unbounded: %d bytes", len(meta[MetaRenewError]))
	}
	RecordFailure(meta, "gone", now, true)
	if s, _ := FromMetadata(meta); !s.Lapsed || s.RenewError != "gone" {
		t.Errorf("failure = %+v", s)
	}
	RecordRenewal(meta, Claims{Namespace: "home", ServiceAccount: p.ServiceAccount, IssuedAt: now.Add(time.Hour),
		ExpiresAt: now.Add(25 * time.Hour)}, "hub", now.Add(time.Hour))
	s, _ = FromMetadata(meta)
	if s.Lapsed || s.RenewError != "" || s.Renewals != 1 || s.RenewedBy != "hub" || !s.RenewedAt.Equal(now.Add(time.Hour)) {
		t.Errorf("after a renewal = %+v", s)
	}
	if _, ok := FromMetadata(map[string]string{"ticket": "OPS-1"}); ok {
		t.Error("a secret without kube.share read as a share")
	}
}

// ── tokens and the stored kubeconfig ────────────────────────────────────────

func TestParseClaims(t *testing.T) {
	c, err := ParseClaims(jwt("home", "cloop-x-1", now, now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject() != "system:serviceaccount:home:cloop-x-1" || c.Lifetime() != time.Hour || c.UID != "uid-cloop-x-1" {
		t.Errorf("claims = %+v", c)
	}
	enc := base64.RawURLEncoding
	legacy, _ := json.Marshal(map[string]any{"sub": "system:serviceaccount:a:b"})
	user, _ := json.Marshal(map[string]any{"sub": "alice", "iat": 1, "exp": 2})
	for name, tok := range map[string]string{
		"not a JWT":     "opaque-token",
		"bad base64":    "a.!!!.c",
		"not JSON":      "a." + enc.EncodeToString([]byte("nope")) + ".c",
		"no expiry":     "a." + enc.EncodeToString(legacy) + ".c",
		"not an SA":     "a." + enc.EncodeToString(user) + ".c",
		"expires first": jwt("a", "b", now, now.Add(-time.Hour)),
	} {
		if _, err := ParseClaims(tok); !errors.Is(err, ErrNotServiceAccountToken) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// selfSignedPEM is a real certificate, because the hub's parser loads the CA.
func selfSignedPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kubernetes"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestRenderedKubeconfigIsWhatTheHubAccepts(t *testing.T) {
	ca := selfSignedPEM(t)
	tok := jwt("home", "sa", now, now.Add(time.Hour))
	doc, err := RenderKubeconfig(KubeconfigParams{Name: "aks-dev", Server: "https://k8s.example.com:6443",
		CAData: ca, TLSServerName: "api.internal", Namespace: "team-a", Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	for _, refused := range []string{"exec", "auth-provider", "tokenFile", "client-certificate:", "certificate-authority:"} {
		if strings.Contains(string(doc), refused) {
			t.Errorf("the stored kubeconfig mentions %q:\n%s", refused, doc)
		}
	}
	rc, err := kubernetes.ParseKubeconfig(doc, "")
	if err != nil {
		t.Fatalf("the hub's own parser refuses the kubeconfig a share stores: %v\n%s", err, doc)
	}
	if rc.BearerToken != tok || rc.Server != "https://k8s.example.com:6443" || rc.Namespace != "team-a" ||
		rc.ServerName != "api.internal" || string(rc.CAData) != string(ca) {
		t.Errorf("parsed back = %s", rc.Describe())
	}

	fresh := jwt("home", "sa", now.Add(time.Hour), now.Add(2*time.Hour))
	renewed, err := ReplaceToken(doc, fresh)
	if err != nil {
		t.Fatal(err)
	}
	rc2, err := kubernetes.ParseKubeconfig(renewed, "")
	if err != nil {
		t.Fatal(err)
	}
	if rc2.BearerToken != fresh {
		t.Error("ReplaceToken did not replace the token")
	}
	rc2.BearerToken = rc.BearerToken
	if rc2.Describe() != rc.Describe() || string(rc2.CAData) != string(rc.CAData) || rc2.ServerName != rc.ServerName {
		t.Errorf("ReplaceToken changed more than the token:\n%s\n%s", rc.Describe(), rc2.Describe())
	}
	if _, err := ReplaceToken(doc, "two words"); err == nil {
		t.Error("ReplaceToken wrote a token with whitespace")
	}
	if _, err := ReplaceToken([]byte("contexts: []\n"), fresh); err == nil {
		t.Error("ReplaceToken invented a user")
	}
}

// ── a fake API server ───────────────────────────────────────────────────────

type fakeAPI struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	requests []string
	objects  map[string]map[string]any // path -> object
	// fail makes the request whose "METHOD path" matches answer with status.
	fail map[string]int
	// token is what a TokenRequest returns; auth is the bearer the token
	// endpoint and SelfSubjectReview require, "" for any.
	token  func(ns, name string, secs int64) string
	auth   string
	whoami string
	// seq numbers objects' uids and resourceVersions; onGet runs after a
	// single object is read and the answer written.
	seq   int
	onGet func(path string, obj map[string]any)
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{t: t, objects: map[string]map[string]any{}, fail: map[string]int{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) rest(token string) *kubernetes.RESTConfig {
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	return &kubernetes.RESTConfig{Server: f.srv.URL, CAData: pemCA, BearerToken: token}
}

func (f *fakeAPI) status(w http.ResponseWriter, code int, reason, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"kind": "Status", "status": "Failure", "reason": reason, "message": msg, "code": code})
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := r.Method + " " + r.URL.Path
	f.requests = append(f.requests, key)
	if code, ok := f.fail[key]; ok {
		f.status(w, code, http.StatusText(code), "planted failure for "+key)
		return
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	switch {
	case strings.HasSuffix(r.URL.Path, "/token") && r.Method == http.MethodPost:
		if f.auth != "" && bearer != f.auth {
			f.status(w, 401, "Unauthorized", "Unauthorized")
			return
		}
		parts := strings.Split(r.URL.Path, "/")
		ns, name := parts[4], parts[6]
		var body struct {
			Spec struct {
				ExpirationSeconds int64 `json:"expirationSeconds"`
			} `json:"spec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		tok := f.token(ns, name, body.Spec.ExpirationSeconds)
		c, _ := ParseClaims(tok)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{
			"token": tok, "expirationTimestamp": c.ExpiresAt.Format(time.RFC3339)}})
	case strings.HasSuffix(r.URL.Path, "/selfsubjectreviews"):
		if f.auth != "" && bearer != f.auth {
			f.status(w, 401, "Unauthorized", "Unauthorized")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"userInfo": map[string]any{"username": f.whoami}}})
	case r.Method == http.MethodPost:
		var obj map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &obj)
		meta := obj["metadata"].(map[string]any)
		name := meta["name"].(string)
		path := r.URL.Path + "/" + name
		if _, exists := f.objects[path]; exists {
			f.status(w, 409, "AlreadyExists", name+" already exists")
			return
		}
		f.seq++
		meta["uid"] = fmt.Sprintf("uid-%d", f.seq)
		meta["resourceVersion"] = fmt.Sprint(f.seq)
		f.objects[path] = obj
		_ = json.NewEncoder(w).Encode(obj)
	case r.Method == http.MethodDelete:
		obj, ok := f.objects[r.URL.Path]
		if !ok {
			f.status(w, 404, "NotFound", "not found")
			return
		}
		var opts struct {
			Preconditions *struct {
				UID             string `json:"uid"`
				ResourceVersion string `json:"resourceVersion"`
			} `json:"preconditions"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &opts)
		if pc := opts.Preconditions; pc != nil {
			meta := obj["metadata"].(map[string]any)
			if pc.UID != meta["uid"] || pc.ResourceVersion != meta["resourceVersion"] {
				f.status(w, 409, "Conflict", "the object has been modified; precondition failed")
				return
			}
		}
		delete(f.objects, r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{"kind": "Status", "status": "Success"})
	case r.Method == http.MethodGet && r.URL.Query().Get("labelSelector") == "":
		obj, ok := f.objects[r.URL.Path]
		if !ok {
			f.status(w, 404, "NotFound", "not found")
			return
		}
		_ = json.NewEncoder(w).Encode(obj)
		// After the answer: what changes the object between a read and
		// whatever the reader does next.
		if f.onGet != nil {
			f.onGet(r.URL.Path, obj)
		}
	case r.Method == http.MethodGet && r.URL.Query().Get("labelSelector") != "":
		want := strings.TrimPrefix(r.URL.Query().Get("labelSelector"), LabelShare+"=")
		var items []any
		for path, obj := range f.objects {
			meta := obj["metadata"].(map[string]any)
			labels, _ := meta["labels"].(map[string]any)
			if strings.HasPrefix(path, r.URL.Path+"/") && labels[LabelShare] == want {
				items = append(items, map[string]any{"metadata": meta})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
	default:
		f.status(w, 404, "NotFound", "no route "+key)
	}
}

func (f *fakeAPI) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.objects)
}

func TestApplyCreatesInOrderAndRollsBackAFailure(t *testing.T) {
	api := newFakeAPI(t)
	c, err := NewClient(api.rest("developer"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p, _ := NewPlan(Request{Name: "aks-dev", ID: "3f9c2a1b", Namespaces: []string{"team-a", "team-b"},
		Access: AccessWrite, ServiceAccountNamespace: "home", Renewal: RenewalHub}, now)

	// The second shared namespace's binding is refused: the developer may not
	// grant edit there.
	api.fail["POST /apis/rbac.authorization.k8s.io/v1/namespaces/team-b/rolebindings"] = 403
	_, err = Apply(context.Background(), c, p)
	if !IsForbidden(err) || !strings.Contains(err.Error(), "may not bind ClusterRole edit") {
		t.Fatalf("err = %v, want the refused binding explained", err)
	}
	if n := api.count(); n != 0 {
		t.Fatalf("%d objects were left behind after the rollback", n)
	}

	delete(api.fail, "POST /apis/rbac.authorization.k8s.io/v1/namespaces/team-b/rolebindings")
	created, err := Apply(context.Background(), c, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 5 || created[0].Kind != "ServiceAccount" {
		t.Fatalf("created = %v", created)
	}
	// Applying again finds the objects there and adopts none of them.
	if _, err := Apply(context.Background(), c, p); !IsConflict(err) || !strings.Contains(err.Error(), "never takes over") {
		t.Fatalf("a second Apply: err = %v", err)
	}
	if api.count() != 5 {
		t.Errorf("the refused second Apply's rollback deleted the first share's objects: %d left", api.count())
	}
}

func TestMintRenewAndAdopt(t *testing.T) {
	api := newFakeAPI(t)
	minted := 0
	api.token = func(ns, name string, secs int64) string {
		minted++
		iat := now.Add(time.Duration(minted) * time.Minute)
		return jwt(ns, name, iat, iat.Add(time.Duration(secs)*time.Second))
	}
	dev, _ := NewClient(api.rest("developer"))
	defer dev.Close()
	p, _ := NewPlan(Request{Name: "aks-dev", ID: "3f9c2a1b", Namespaces: []string{"a"}, TTL: time.Hour,
		Renewal: RenewalHub}, now)
	tok, claims, err := Mint(context.Background(), dev, p)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ServiceAccount != p.ServiceAccount || claims.Lifetime() != time.Hour {
		t.Fatalf("minted %+v", claims)
	}
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.srv.Certificate().Raw})
	doc, err := RenderKubeconfig(KubeconfigParams{Name: "aks-dev", Server: api.srv.URL, CAData: pemCA,
		Namespace: "a", Token: tok.Value})
	if err != nil {
		t.Fatal(err)
	}

	// The hub renews with the share's own token, and nothing else.
	api.auth = tok.Value
	r, err := Renew(context.Background(), doc, claims.IssuedAt.Add(40*time.Minute))
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if r.Claims.Lifetime() != time.Hour || !r.Claims.IssuedAt.After(claims.IssuedAt) || r.Previous.ServiceAccount != p.ServiceAccount {
		t.Errorf("renewed %+v from %+v", r.Claims, r.Previous)
	}
	if rc, _, err := Inspect(r.Kubeconfig); err != nil || rc.BearerToken == tok.Value {
		t.Errorf("the renewed kubeconfig still holds the old token (%v)", err)
	}

	// An expired token cannot renew itself.
	if _, err := Renew(context.Background(), doc, claims.ExpiresAt); !errors.Is(err, ErrLapsed) || !Lapsed(err) {
		t.Errorf("an expired token: err = %v, want ErrLapsed", err)
	}
	// The cluster no longer accepting it (the ServiceAccount deleted) is the same.
	api.auth = "something-else"
	if _, err := Renew(context.Background(), doc, claims.IssuedAt.Add(time.Minute)); !Lapsed(err) ||
		!strings.Contains(err.Error(), "deleted") {
		t.Errorf("a token the cluster refuses: err = %v", err)
	}
	// A missing self-renewal Role is explained and is not a lapse.
	api.auth = ""
	api.fail["POST /api/v1/namespaces/a/serviceaccounts/"+p.ServiceAccount+"/token"] = 403
	if _, err := Renew(context.Background(), doc, claims.IssuedAt.Add(time.Minute)); Lapsed(err) ||
		!strings.Contains(err.Error(), "self-renewal Role") {
		t.Errorf("a refused renewal: err = %v", err)
	}
	delete(api.fail, "POST /api/v1/namespaces/a/serviceaccounts/"+p.ServiceAccount+"/token")

	// Adopt: a token its owner minted, at the share's own server, checked
	// with the cluster.
	origin := Origin{Server: api.srv.URL, CAFingerprint: CAFingerprint(pemCA)}
	pushed := jwt("a", p.ServiceAccount, now, now.Add(2*time.Hour))
	api.auth, api.whoami = pushed, "system:serviceaccount:a:"+p.ServiceAccount
	ad, err := Adopt(context.Background(), doc, pushed, origin, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Adopt: %v", err)
	}
	if !ad.Verified || ad.Claims.Lifetime() != 2*time.Hour {
		t.Errorf("adopted %+v", ad)
	}
	other := jwt("a", "someone-else", now, now.Add(time.Hour))
	if _, err := Adopt(context.Background(), doc, other, origin, now); !errors.Is(err, ErrWrongToken) {
		t.Errorf("another ServiceAccount's token: err = %v", err)
	}
	api.whoami = "system:serviceaccount:a:impostor"
	if _, err := Adopt(context.Background(), doc, pushed, origin, now); !errors.Is(err, ErrWrongToken) {
		t.Errorf("a token the cluster names differently: err = %v", err)
	}
	api.auth = "not-the-pushed-token"
	if _, err := Adopt(context.Background(), doc, pushed, origin, now); err == nil || !strings.Contains(err.Error(), "does not accept") {
		t.Errorf("a token the cluster refuses: err = %v", err)
	}
	if _, err := Adopt(context.Background(), doc, jwt("a", p.ServiceAccount, now, now.Add(30*24*time.Hour)), origin, now); err == nil {
		t.Error("a token living a month was adopted")
	}
}

func TestRemoveDeletesTheServiceAccountFirstAndSweepsTheLabel(t *testing.T) {
	api := newFakeAPI(t)
	c, _ := NewClient(api.rest("developer"))
	defer c.Close()
	p, _ := NewPlan(Request{Name: "aks-dev", ID: "3f9c2a1b", Namespaces: []string{"a", "b"}, Access: AccessWrite,
		ServiceAccountNamespace: "home", Renewal: RenewalHub}, now)
	if _, err := Apply(context.Background(), c, p); err != nil {
		t.Fatal(err)
	}
	// A stray labelled object the metadata does not list — an earlier,
	// interrupted attempt with the same id.
	stray := Manifest{Object: Object{Kind: "RoleBinding", Namespace: "b", Name: "stray"},
		Collection: "/apis/rbac.authorization.k8s.io/v1/namespaces/b/rolebindings",
		Body:       map[string]any{"metadata": map[string]any{"name": "stray", "labels": map[string]any{LabelShare: "3f9c2a1b"}}}}
	if err := c.Create(context.Background(), stray); err != nil {
		t.Fatal(err)
	}
	share := p.Share()
	// One listed object is already gone: revoke is idempotent.
	_ = c.Delete(context.Background(), Object{Kind: "RoleBinding", Namespace: "a", Name: p.ServiceAccount})

	api.mu.Lock()
	api.requests = nil
	api.mu.Unlock()
	res := Remove(context.Background(), c, share)
	if !res.Clean() {
		t.Fatalf("Remove left %v", res.Failed)
	}
	if n := api.count(); n != 0 {
		t.Fatalf("%d objects remain after Remove", n)
	}
	api.mu.Lock()
	first := ""
	for _, r := range api.requests {
		if strings.HasPrefix(r, "DELETE ") {
			first = r
			break
		}
	}
	api.mu.Unlock()
	if !strings.HasSuffix(first, "/serviceaccounts/"+p.ServiceAccount) {
		t.Errorf("the first deletion was %q; the ServiceAccount must go first, so every token dies before "+
			"anything else is touched", first)
	}
	left, err := Remaining(context.Background(), c, share)
	if err != nil || len(left) != 0 {
		t.Errorf("Remaining = %v, %v", left, err)
	}
}

func TestUploadRefusalNamesThePluginAndTheCommand(t *testing.T) {
	aks := `
apiVersion: v1
kind: Config
current-context: aks-dev
clusters:
- name: aks-dev
  cluster: {server: "https://aks-dev-dns.hcp.westeurope.azmk8s.io:443"}
contexts:
- name: aks-dev
  context: {cluster: aks-dev, user: clusterUser_rg_aks-dev, namespace: payments}
users:
- name: clusterUser_rg_aks-dev
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: kubelogin
      args: [get-token, --login, devicecode, --server-id, 6dae42f8-4368-4678-94ff-3960e28e3630]
`
	msg := UploadRefusal([]byte(aks), "aks-dev", "https://hub.example.com")
	for _, want := range []string{
		`user "clusterUser_rg_aks-dev" (context aks-dev) signs in through kubelogin (Microsoft Entra ID`,
		"never runs a credential plugin",
		"cloop remote kube share aks-dev --hub https://hub.example.com --context aks-dev --namespaces payments",
		"cloop login",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "6dae42f8") {
		t.Error("the refusal repeats the plugin's arguments")
	}

	eks := strings.NewReplacer("kubelogin", "aws", "[get-token, --login, devicecode, --server-id, 6dae42f8-4368-4678-94ff-3960e28e3630]",
		"[eks, get-token, --cluster-name, prod]", "namespace: payments", "").Replace(aks)
	if msg := UploadRefusal([]byte(eks), "eks prod", ""); !strings.Contains(msg, "aws eks get-token (Amazon EKS)") ||
		!strings.Contains(msg, "cloop remote kube share 'eks prod' --context aks-dev --namespaces <namespace>") {
		t.Errorf("EKS refusal:\n%s", msg)
	}

	gcp := `
contexts: [{name: gke, context: {cluster: c, user: u}}]
users: [{name: u, user: {auth-provider: {name: gcp}}}]
`
	if msg := UploadRefusal([]byte(gcp), "gke", ""); !strings.Contains(msg, `the "gcp" auth-provider`) {
		t.Errorf("auth-provider refusal:\n%s", msg)
	}

	static := `
contexts: [{name: kind, context: {cluster: c, user: u}}]
users: [{name: u, user: {token: abc}}, {name: unused, user: {exec: {command: kubelogin}}}]
`
	if msg := UploadRefusal([]byte(static), "kind", ""); msg != "" {
		t.Errorf("a static kubeconfig (with an unused plugin user) was refused:\n%s", msg)
	}
	if msg := UploadRefusal([]byte("{not yaml"), "x", ""); msg != "" {
		t.Errorf("unparseable input produced a plugin refusal: %s", msg)
	}
	for cmd, want := range map[string]string{
		"/usr/local/bin/gke-gcloud-auth-plugin": "Google GKE",
		"aws-iam-authenticator":                 "Amazon EKS",
		"kubectl":                               "kubectl",
		"/opt/acme/bin/sso":                     "sso",
	} {
		if got := DescribePlugin(cmd, nil); !strings.Contains(got, want) {
			t.Errorf("DescribePlugin(%s) = %q", cmd, got)
		}
	}
}

func TestExpiryReadsForAPerson(t *testing.T) {
	for d, want := range map[time.Duration]string{
		-time.Minute:                  "expired",
		30 * time.Second:              "in 30s",
		90 * time.Minute:              "in 1h30m",
		50 * time.Hour:                "in 2d2h",
		12*time.Hour + 30*time.Second: "in 12h1m",
	} {
		if got := Expiry(now.Add(d), now); !strings.Contains(got, want) {
			t.Errorf("Expiry(%s) = %q, want %q", d, got, want)
		}
	}
	if got := fmt.Sprint(Expiry(time.Time{}, now)); got != "unknown" {
		t.Errorf("zero expiry = %q", got)
	}
}
