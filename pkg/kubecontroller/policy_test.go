package kubecontroller

// policy_test.go covers what Task 20485 added for the Helm chart: a runner
// gets its ServiceAccount's token only when its pool asks for it by name, a
// runner never runs as the controller's own ServiceAccount, and a controller
// told to require digests refuses a runner image named by tag.

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// fakeJWT is a token with the given claims and no valid signature, which is
// all ServiceAccountFromToken reads.
func fakeJWT(t *testing.T, claims map[string]any, pad bool) string {
	t.Helper()
	enc := base64.RawURLEncoding
	if pad {
		enc = base64.URLEncoding
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return enc.EncodeToString([]byte(`{"alg":"RS256","kid":"k"}`)) + "." + enc.EncodeToString(body) + ".c2ln"
}

func TestServiceAccountFromTokenReadsTheSubject(t *testing.T) {
	sa, ok := ServiceAccountFromToken(fakeJWT(t, map[string]any{
		"sub": "system:serviceaccount:cloop-system:cloop-executor-controller", "aud": []string{"https://kubernetes.default.svc"}}, false))
	if !ok || sa != (ServiceAccountRef{Namespace: "cloop-system", Name: "cloop-executor-controller"}) {
		t.Fatalf("got %+v %v", sa, ok)
	}
	if sa.String() != "cloop-system/cloop-executor-controller" {
		t.Fatalf("String() = %q", sa.String())
	}
	// Padded base64 is read too.
	if sa, ok := ServiceAccountFromToken(fakeJWT(t, map[string]any{"sub": "system:serviceaccount:a:b"}, true)); !ok || sa.Name != "b" {
		t.Fatalf("padded: %+v %v", sa, ok)
	}
	for name, tok := range map[string]string{
		"a node's token":       fakeJWT(t, map[string]any{"sub": "system:node:worker-1"}, false),
		"a person's token":     fakeJWT(t, map[string]any{"sub": "alice@example.com"}, false),
		"no subject":           fakeJWT(t, map[string]any{"iss": "x"}, false),
		"a malformed subject":  fakeJWT(t, map[string]any{"sub": "system:serviceaccount:only-one"}, false),
		"an uppercase name":    fakeJWT(t, map[string]any{"sub": "system:serviceaccount:ns:Controller"}, false),
		"an opaque token":      "0123456789abcdef",
		"two segments":         "a.b",
		"a payload not base64": "a.!!!.c",
		"a payload not JSON":   "a." + base64.RawURLEncoding.EncodeToString([]byte("nope")) + ".c",
		"empty":                "",
	} {
		if sa, ok := ServiceAccountFromToken(tok); ok {
			t.Errorf("%s: read %+v from it", name, sa)
		}
	}
}

func TestATokenIsMountedOnlyWhenThePoolAsksForItByName(t *testing.T) {
	automount := func(pool *ExecutorPool) any {
		raw, err := json.Marshal(buildRunnerPod(pool, "build-abc123", "ghcr.io/blechschmidt/cloop-harness@"+fakeDigest, nil))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Spec map[string]any `json:"spec"`
		}
		_ = json.Unmarshal(raw, &doc)
		v, ok := doc.Spec["automountServiceAccountToken"]
		if !ok {
			t.Fatal("automountServiceAccountToken is left to the ServiceAccount's own setting")
		}
		return v
	}
	pool := templatePool(t)
	if got := automount(pool); got != false {
		t.Fatalf("a runner of a pool that did not ask has automountServiceAccountToken %v", got)
	}
	pool.Spec.Template.AutomountServiceAccountToken = true
	if problems := pool.Spec.Validate(); len(problems) != 0 {
		t.Fatalf("a pool asking for its named account's token is invalid: %v", problems)
	}
	if got := automount(pool); got != true {
		t.Fatalf("a runner of a pool that asked has automountServiceAccountToken %v", got)
	}
}

func TestATokenNeedsAnAccountNamedForTheRunners(t *testing.T) {
	for _, sa := range []string{"", "default"} {
		s := validSpec()
		s.Template.ServiceAccountName = sa
		s.Template.AutomountServiceAccountToken = true
		problems := strings.Join(s.Validate(), "\n")
		if !strings.Contains(problems, "spec.template.automountServiceAccountToken: needs a serviceAccountName other than default") {
			t.Errorf("serviceAccountName %q with a token: problems %q", sa, problems)
		}
	}
}

func TestPolicyProblems(t *testing.T) {
	own := &ServiceAccountRef{Namespace: "ctl", Name: "cloop-executor-controller"}
	for _, tc := range []struct {
		name     string
		opts     Options
		ns       string
		template RunnerTemplate
		want     string // "" is no problem
	}{
		{"a tag, digests not required", Options{}, "ctl", RunnerTemplate{Image: "registry.example.com/runner:1"}, ""},
		{"a tag, digests required", Options{RequireImageDigest: true}, "ctl",
			RunnerTemplate{Image: "registry.example.com/runner:1"}, "spec.template.image: \"registry.example.com/runner:1\" is not pinned by digest"},
		{"no tag at all, digests required", Options{RequireImageDigest: true}, "ctl",
			RunnerTemplate{Image: "registry.example.com/runner"}, "is not pinned by digest"},
		{"a digest, digests required", Options{RequireImageDigest: true}, "ctl",
			RunnerTemplate{Image: "registry.example.com/runner@" + fakeDigest}, ""},
		{"a tag and a digest, digests required", Options{RequireImageDigest: true}, "ctl",
			RunnerTemplate{Image: "registry.example.com/runner:1@" + fakeDigest}, ""},
		{"cloop's own default, digests required", Options{RequireImageDigest: true}, "ctl", RunnerTemplate{}, ""},
		// Resolved at the registry and verified like the default.
		{"cloop's own image by tag, digests required", Options{RequireImageDigest: true}, "ctl",
			RunnerTemplate{Image: DefaultRunnerImage()}, ""},
		{"its name on another registry, digests required", Options{RequireImageDigest: true}, "ctl",
			RunnerTemplate{Image: "registry.example.com/blechschmidt/cloop-harness:1"}, "is not pinned by digest"},
		{"the controller's own account", Options{ServiceAccount: own}, "ctl",
			RunnerTemplate{ServiceAccountName: "cloop-executor-controller"}, "is the controller's own ServiceAccount"},
		{"its name in another namespace", Options{ServiceAccount: own}, "other",
			RunnerTemplate{ServiceAccountName: "cloop-executor-controller"}, ""},
		{"another account", Options{ServiceAccount: own}, "ctl", RunnerTemplate{ServiceAccountName: "runner"}, ""},
		{"no account known", Options{}, "ctl", RunnerTemplate{ServiceAccountName: "cloop-executor-controller"}, ""},
		// A controller running as the namespace's default: a template naming
		// no account would run its runners as it too.
		{"no account, the controller as default", Options{ServiceAccount: &ServiceAccountRef{Namespace: "ctl", Name: "default"}},
			"ctl", RunnerTemplate{}, "\"default\" is the controller's own ServiceAccount"},
		{"no account, the controller as another", Options{ServiceAccount: own}, "ctl", RunnerTemplate{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Controller{opts: tc.opts}
			spec := validSpec()
			spec.Template = tc.template
			got := strings.Join(c.policyProblems(&ExecutorPool{Metadata: ObjectMeta{Name: "p", Namespace: tc.ns}, Spec: spec}), "\n")
			switch {
			case tc.want == "" && got != "":
				t.Fatalf("problems %q, want none", got)
			case tc.want != "" && !strings.Contains(got, tc.want):
				t.Fatalf("problems %q, want %q", got, tc.want)
			}
		})
	}
}

// A pool whose runners would run as the controller's own ServiceAccount, or
// from a tag on a controller that requires digests, shows Invalid and starts
// nothing; fixed, it serves.
func TestAPoolTheControllersPolicyRefusesIsInvalid(t *testing.T) {
	r := newRig(t)
	r.hub.setDemand(1)
	spec := r.spec()
	spec.Template.ServiceAccountName = "cloop-executor-controller"
	spec.Template.Image = "registry.example.com/runner:1"
	r.pool("build", spec)
	r.start(func(o *Options) {
		o.ServiceAccount = &ServiceAccountRef{Namespace: testNS, Name: "cloop-executor-controller"}
		o.RequireImageDigest = true
	})
	r.eventually("Invalid=True naming both", func() bool {
		c := r.condition("build", ConditionInvalid)
		return c.Status == ConditionTrue && strings.Contains(c.Message, "controller's own ServiceAccount") &&
			strings.Contains(c.Message, "is not pinned by digest")
	})
	r.never("a runner for a refused pool", 500*time.Millisecond, func() bool { return len(r.pods()) > 0 })

	spec.Template.ServiceAccountName = "cloop-runner"
	spec.Template.Image = "registry.example.com/runner@" + fakeDigest
	r.pool("build", spec)
	r.eventually("valid and serving", func() bool {
		return r.condition("build", ConditionInvalid).Status == ConditionFalse && len(r.runnerSecrets()) == 1
	})
}
