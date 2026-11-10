package kubecontroller

// rbac_test.go holds the controller's API calls to RequiredRules: it drives a
// controller through everything it does — leader election, scale-up, a
// finished runner, scale-down, the orphan sweep, Events and status — records
// every call the fake API server saw, and checks each against the rules, and
// each rule against the calls.

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// callRule maps a call to the (group, resource, verb) RBAC sees.
func callRule(c fakeCall) (group, resource, verb string, ok bool) {
	parts := strings.Split(strings.Trim(c.Path, "/"), "/")
	var rest []string
	switch {
	case len(parts) >= 2 && parts[0] == "api":
		rest = parts[2:]
	case len(parts) >= 3 && parts[0] == "apis":
		group, rest = parts[1], parts[3:]
	default:
		return "", "", "", false
	}
	if len(rest) >= 2 && rest[0] == "namespaces" {
		rest = rest[2:]
	}
	if len(rest) == 0 {
		return "", "", "", false
	}
	resource = rest[0]
	named := len(rest) >= 2
	if len(rest) >= 3 {
		resource += "/" + rest[2]
	}
	q, _ := url.ParseQuery(c.Query)
	switch c.Method {
	case "GET":
		switch {
		case named:
			verb = "get"
		case q.Get("watch") == "true":
			verb = "watch"
		default:
			verb = "list"
		}
	case "POST":
		verb = "create"
	case "PUT":
		verb = "update"
	case "PATCH":
		verb = "patch"
	case "DELETE":
		verb = "delete"
	}
	return group, resource, verb, true
}

func TestEveryAPICallIsCoveredByRequiredRulesAndEveryRuleIsUsed(t *testing.T) {
	r := newRig(t)
	ctrl := true
	r.k8s.apply("secrets", testNS, Secret{Metadata: ObjectMeta{Name: "stale", Labels: map[string]string{
		LabelManagedBy: ManagedBy}, CreationTimestamp: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		OwnerReferences: []OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: "stale", UID: "gone", Controller: &ctrl}}}})
	r.hub.setDemand(2)
	// With runner volumes (Task 20484): claims created, claimed and released
	// by patch, and one deleted when the pool shrinks.
	spec := r.spec()
	spec.MaxRunners = 2
	spec.Persistence = &Persistence{Enabled: true, Size: "5Gi"}
	r.pool("build", spec)
	rc := r.start(func(o *Options) {
		o.LeaderElection = &LeaderElection{Namespace: testNS, Name: "lease", Identity: "me",
			LeaseDuration: 1500 * time.Millisecond, RenewDeadline: time.Second, RetryPeriod: 200 * time.Millisecond}
	})
	r.eventually("the stale Secret swept", func() bool { return !contains(r.runnerSecrets(), "stale") })
	r.eventually("two runners with their Secrets", func() bool {
		ps := r.pods()
		return len(ps) == 2 && r.enrollmentOf(ps[0]) != "" && r.enrollmentOf(ps[1]) != ""
	})
	pods := r.pods()
	for _, p := range pods {
		r.hub.enroll(r.enrollmentOf(p), time.Now().Add(-time.Hour))
	}
	r.hub.setDemand(0)
	r.eventually("both retired", func() bool { return len(r.hub.retiredIDs()) == 2 })
	for _, p := range pods {
		r.k8s.setPodPhase(testNS, p, PodSucceeded, 0, "")
	}
	r.eventually("both collected", func() bool { return len(r.pods()) == 0 })
	r.eventually("both volumes released", func() bool {
		for _, c := range r.claims() {
			if r.claim(c).Metadata.Annotations[AnnotationClaimedBy] != "" {
				return false
			}
		}
		return len(r.claims()) == 2
	})
	spec.MaxRunners = 1
	r.pool("build", spec)
	r.eventually("the volume past maxClaims deleted", func() bool { return len(r.claims()) == 1 })
	// Renew the lease a few times, then let it go on shutdown.
	time.Sleep(500 * time.Millisecond)
	rc.stop(t)

	type grv struct{ g, r, v string }
	allowed := map[grv]bool{}
	for _, rule := range RequiredRules() {
		for _, g := range rule.APIGroups {
			for _, res := range rule.Resources {
				for _, v := range rule.Verbs {
					allowed[grv{g, res, v}] = true
				}
			}
		}
	}
	used := map[grv]bool{}
	for _, c := range r.k8s.callLog() {
		g, res, v, ok := callRule(c)
		if !ok {
			t.Errorf("a call outside the API: %s %s", c.Method, c.Path)
			continue
		}
		k := grv{g, res, v}
		if !allowed[k] {
			t.Errorf("%s %s?%s needs %s %q %s, which RequiredRules does not grant", c.Method, c.Path, c.Query, v, res, g)
		}
		used[k] = true
	}
	for k := range allowed {
		if !used[k] {
			t.Errorf("RequiredRules grants %s %q in %q, and nothing called it", k.v, k.r, k.g)
		}
	}
}
