package kubernetes

// preflight.go answers "why did nothing happen when I bound a project to this
// executor?" before the operator has to ask it.
//
// Configuring a Kubernetes backend touches a secret grant, a kubeconfig, TLS
// trust, an API server, RBAC, a namespace, an image and a Pod Security
// policy. When any one of them is wrong the symptom is the same — a run that
// produces no output — so the value of this file is entirely in separating
// those layers and naming the one that broke.
//
// The checks run in dependency order and stop being meaningful once an
// earlier one fails, which is why a fatal finding short-circuits the rest
// rather than producing a cascade of confusing follow-on errors.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Preflight check levels, matching the container driver's vocabulary so
// `cloop executor test` renders both the same way.
const (
	// LevelOK: the check passed.
	LevelOK = "ok"
	// LevelWarn: usable, but with a caveat the operator should know about.
	LevelWarn = "warn"
	// LevelFail: workloads will not run until this is fixed.
	LevelFail = "fail"
)

// Finding is one preflight observation.
type Finding struct {
	Name    string `json:"name"`
	Level   string `json:"level"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

// PreflightReport is the result of checking an executor's environment.
type PreflightReport struct {
	ExecutorID string    `json:"executor_id"`
	Server     string    `json:"server,omitempty"`
	Namespace  string    `json:"namespace,omitempty"`
	Image      string    `json:"image,omitempty"`
	Findings   []Finding `json:"findings"`
}

// OK reports whether nothing fatal was found.
func (r PreflightReport) OK() bool {
	for _, f := range r.Findings {
		if f.Level == LevelFail {
			return false
		}
	}
	return true
}

// Err returns an error summarising the fatal findings, or nil when none.
func (r PreflightReport) Err() error {
	var msgs []string
	for _, f := range r.Findings {
		if f.Level != LevelFail {
			continue
		}
		m := f.Name + ": " + f.Message
		if f.Fix != "" {
			m += " (fix: " + f.Fix + ")"
		}
		msgs = append(msgs, m)
	}
	if len(msgs) == 0 {
		return nil
	}
	return fmt.Errorf("kubernetes executor preflight failed: %s", strings.Join(msgs, "; "))
}

// Preflight checks everything between this control plane and a running Pod.
func (e *Executor) Preflight(ctx context.Context) PreflightReport {
	if ctx == nil {
		ctx = context.Background()
	}
	report := PreflightReport{ExecutorID: e.id, Image: e.opts.Image}
	add := func(name, level, msg, fix string) {
		report.Findings = append(report.Findings, Finding{Name: name, Level: level, Message: msg, Fix: fix})
	}

	// --- 1. image ---------------------------------------------------------
	// Checked first because it needs no cluster and is the most common
	// oversight: unlike the container driver there is no host binary to
	// bind-mount, so an image without cloop in it can never work.
	if warnings := ImageWarnings(e.opts.Image); len(warnings) > 0 {
		for _, w := range warnings {
			add("image", LevelWarn, w,
				"set executors.kubernetes.image to a digest-pinned image containing the cloop binary")
		}
	} else {
		add("image", LevelOK, fmt.Sprintf("image %s is digest-pinned", e.opts.Image), "")
	}

	// --- 2. credentials ---------------------------------------------------
	if e.opts.Credentials == nil {
		add("credentials", LevelFail,
			"no credential source is configured",
			"this build registered the executor without a secret broker; set CLOOP_SECRET_KEY and restart")
		return report
	}
	acquireCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	creds, err := e.opts.Credentials.Acquire(acquireCtx, "")
	cancel()
	if err != nil {
		level, fix := LevelFail, fmt.Sprintf(
			"mint a kubeconfig secret and grant it: cloop secret mint --kind kubeconfig --file ~/.kube/config --name %s-kubeconfig "+
				"&& cloop secret grant %s-kubeconfig --to executor:%s --namespaces %s",
			e.id, e.id, e.id, orNone(e.opts.Namespace))
		if errors.Is(err, ErrNoKubeconfigGrant) {
			add("credentials", level, "the broker issued no kubeconfig for this executor", fix)
		} else {
			add("credentials", level, err.Error(), fix)
		}
		return report
	}
	defer e.opts.Credentials.Release(creds.LeaseID)

	report.Server = creds.Rest.Server
	add("credentials", LevelOK,
		fmt.Sprintf("leased %s (%s), expires in %s",
			orNone(creds.SecretName), creds.Rest.Describe(),
			time.Until(creds.ExpiresAt).Round(time.Second)),
		"")
	if creds.Rest.Insecure {
		add("tls", LevelWarn,
			"the kubeconfig sets insecure-skip-tls-verify, so the API server's identity is not checked",
			"embed the cluster CA as certificate-authority-data in the brokered kubeconfig")
	} else {
		add("tls", LevelOK, "the API server certificate is verified against the kubeconfig CA", "")
	}

	cli, err := newClient(creds.Rest, requestTimeout)
	if err != nil {
		add("client", LevelFail, err.Error(), "fix the kubeconfig delivered by the grant")
		return report
	}
	defer cli.close()

	// --- 3. reachability --------------------------------------------------
	verCtx, cancelVer := context.WithTimeout(ctx, requestTimeout)
	version, err := cli.serverVersion(verCtx)
	cancelVer()
	if err != nil {
		add("api", LevelFail,
			fmt.Sprintf("cannot reach %s: %v", creds.Rest.Server, err),
			"check network reachability and that the kubeconfig's server URL is correct from this host")
		return report
	}
	add("api", LevelOK, fmt.Sprintf("%s is responding (%s)", creds.Rest.Server, version), "")

	// --- 4. namespace and RBAC -------------------------------------------
	namespace := e.namespaceFor(creds)
	report.Namespace = namespace
	if e.opts.Namespace == "" {
		add("namespace", LevelWarn,
			fmt.Sprintf("namespace %q was inferred from the grant or kubeconfig, not configured", namespace),
			"set executors.kubernetes.namespace so the blast radius is explicit in config")
	}

	// Listing Pods with the driver's own selector proves three things at
	// once: the namespace exists, the credential can read Pods in it, and
	// the label selector is accepted. It is also the exact call
	// ReconcileOrphans makes, so a working preflight means a working sweep.
	listCtx, cancelList := context.WithTimeout(ctx, requestTimeout)
	list, err := cli.listPods(listCtx, namespace, executorLabelSelector(e.id))
	cancelList()
	if err != nil {
		ae, isAPI := asAPIError(err)
		switch {
		case isAPI && ae.Code == http.StatusNotFound:
			add("namespace", LevelFail,
				fmt.Sprintf("namespace %q does not exist", namespace),
				fmt.Sprintf("kubectl create namespace %s", namespace))
		case isAPI && ae.Code == http.StatusForbidden:
			add("rbac", LevelFail,
				fmt.Sprintf("the leased identity may not list Pods in %q: %s", namespace, ae.Message),
				rbacFix(namespace, e.opts.EgressFilter.Enabled))
		default:
			add("namespace", LevelFail, err.Error(), rbacFix(namespace, e.opts.EgressFilter.Enabled))
		}
		return report
	}
	add("rbac", LevelOK,
		fmt.Sprintf("Pods in %q are readable (%d cloop Pod(s) currently present)", namespace, len(list.Items)),
		"")

	// --- 5. confinement summary ------------------------------------------
	add("confinement", LevelOK,
		"Pods run non-root with a read-only root filesystem, all capabilities dropped, "+
			"seccomp RuntimeDefault and no ServiceAccount token mounted", "")
	if e.opts.CPULimit == "" && e.opts.MemoryLimit == "" {
		add("limits", LevelWarn,
			"no cpu_limit or memory_limit is configured, so a workload is bounded only by the namespace LimitRange",
			"set executors.kubernetes.cpu_limit and memory_limit")
	} else {
		add("limits", LevelOK,
			fmt.Sprintf("cpu_limit=%s memory_limit=%s", orNone(e.opts.CPULimit), orNone(e.opts.MemoryLimit)), "")
	}

	// --- 5a. egress -------------------------------------------------------
	//
	// Two different honest answers, depending on configuration, and the
	// difference matters more than either message: with no filter configured
	// this driver genuinely does not restrict egress, and with one configured
	// the restriction is only as real as the executor's RBAC and the cluster's
	// CNI. Both are checked here rather than assumed, because "the operator
	// enabled the filter" and "the filter is enforced" are separated by two
	// things cloop does not control.
	if !e.opts.EgressFilter.Enabled {
		add("egress", LevelWarn,
			"Pods join the cluster network with unrestricted egress; cloop does not filter it",
			fmt.Sprintf("apply a default-deny NetworkPolicy to namespace %q and allow only what the harness needs", namespace))
	} else {
		// The same call the sweep makes, for the same reason the Pod list above
		// is the one ReconcileOrphans makes: a preflight that passes has proved
		// the credential can actually reach the endpoint, rather than proving
		// that the config file parses.
		npCtx, cancelNP := context.WithTimeout(ctx, requestTimeout)
		policies, nperr := cli.listNetworkPolicies(npCtx, namespace, executorLabelSelector(e.id))
		cancelNP()
		switch ae, isAPI := asAPIError(nperr); {
		case nperr == nil:
			add("egress", LevelOK,
				fmt.Sprintf("egress is filtered by a per-Pod NetworkPolicy (%s), and the leased identity "+
					"can manage NetworkPolicies in %q (%d cloop policy/policies currently present)",
					e.opts.EgressFilter.Describe(), namespace, len(policies.Items)),
				"")
		case isAPI && ae.Code == http.StatusForbidden:
			add("egress", LevelFail,
				fmt.Sprintf("the egress filter is enabled but the leased identity may not manage "+
					"NetworkPolicies in %q: %s — every Start will be refused rather than run a Pod "+
					"with unfiltered egress", namespace, ae.Message),
				"add `- apiGroups: [\"networking.k8s.io\"] resources: [\"networkpolicies\"] "+
					"verbs: [\"create\", \"delete\", \"list\"]` to the executor's Role")
		default:
			add("egress", LevelFail,
				fmt.Sprintf("the egress filter is enabled but its NetworkPolicies cannot be listed in %q: %v",
					namespace, nperr),
				"check that the cluster serves networking.k8s.io/v1 and that the executor's Role covers "+
					"networkpolicies: [create delete list]")
		}

		// Stated separately, and always, because it is the one part of this
		// that cloop cannot check. Creating the object proves the API server
		// stored it, not that anything enforces it: a NetworkPolicy is inert
		// unless the cluster's CNI implements it, and flannel — still a common
		// default — does not. The API server accepts the object regardless and
		// reports nothing, so a cluster with the wrong CNI looks exactly like a
		// working one from here.
		add("egress-enforcement", LevelWarn,
			"a NetworkPolicy is enforced by the cluster's CNI, not by cloop, and cloop cannot tell "+
				"from the API whether yours implements one (flannel does not; Calico, Cilium, "+
				"Antrea and most managed CNIs do)",
			"confirm your CNI supports NetworkPolicy, then verify from inside a sandbox that a denied "+
				"destination actually times out")
	}

	// --- 6. workspace -----------------------------------------------------
	//
	// This check exists because the failure it heads off is silent. A project
	// bound to this executor with a private repository and no credential
	// source does not error at bind time, at placement time, or at Start: the
	// Pod is created, the init container runs, git asks for a password nobody
	// supplies, and the operator sees a run that failed for reasons the run's
	// own output cannot explain.
	if e.opts.Workspace == nil {
		add("workspace", LevelWarn,
			"this executor provisions a git workspace with an init container, but no workspace "+
				"credential source is wired, so only public repositories can be fetched",
			fmt.Sprintf("mint and grant a GitHub PAT: cloop secret mint --kind github-pat --name %s-git "+
				"&& cloop secret grant %s-git --to executor:%s --repos owner/name", e.id, e.id, e.id))
	} else {
		add("workspace", LevelOK,
			fmt.Sprintf("git workspaces are fetched by an init container in the same image, with a "+
				"brokered credential delivered through a short-lived Secret in %q that is deleted as "+
				"soon as the fetch finishes", namespace),
			"")
	}

	return report
}

// rbacFix is the Role the executor's identity needs, as something an operator
// can paste. Naming the exact verbs is the difference between a two-minute
// fix and an afternoon.
//
// egress adds the networkpolicies rule. It is conditional because the rule is:
// an executor that does not filter egress creates no NetworkPolicies and should
// not be told to grant itself authority over them.
func rbacFix(namespace string, egress bool) string {
	rules := "pods: [create get list watch delete], pods/log: [get] and secrets: [create delete]"
	if egress {
		rules = "pods: [create get list watch delete], pods/log: [get], secrets: [create delete] and " +
			"networking.k8s.io networkpolicies: [create delete list]"
	}
	return fmt.Sprintf("grant a Role in %q with %s, then bind it to the ServiceAccount whose token "+
		"the kubeconfig carries", namespace, rules)
}
