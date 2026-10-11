package secretbroker

// kubemulti.go lets one lease carry more than one kubeconfig grant (Task
// 20413). It is githubmulti.go's counterpart for Kubernetes.
//
// Every kubeconfig material renders one document under the fixed name
// "kubeconfig" and points KUBECONFIG at it, and every document the Kubernetes
// monitor issues names its cluster, user and context "cloop"
// (pkg/kubeguard/kubeconfig.go). A lease holding two kubeconfig grants — two
// clusters, one cluster granted twice with different namespaces or verbs, or an
// edited assignment whose predecessor is not revoked yet — therefore rendered
// two files at one path. A delivered lease was refused outright ("secret_files[N]
// repeats path …/kubeconfig") on containers, edge agents and Pods; a
// hub-materialised one wrote one document over the other. CLOOP_K8S_NAMESPACE,
// CLOOP_K8S_ALLOWED_NAMESPACES, CLOOP_K8S_VERBS and the monitor's session
// variable collided the same way, whichever material rendered last speaking for
// every grant.
//
// # One merged document, not a file per grant
//
// coalesceKubeconfig writes every grant's clusters, users and contexts into one
// document. The alternative, a file per grant listed in KUBECONFIG with ':',
// would keep each credential in a file of its own, but KUBECONFIG would stop
// being a path, and two things this system depends on read it as one:
//
//   - client-go and kubectl merge a ':' list; much else does not. A program
//     that hands $KUBECONFIG to clientcmd.BuildConfigFromFlags, a script that
//     opens it, an agent that cats it, and the hub doctor's own smoke workload,
//     which tests it with [ -f "$KUBECONFIG" ], would each look for one file
//     named after the whole list.
//   - an edge agent places a lease's files in a directory of its own and
//     rewrites every variable naming the declared one by its leading directory
//     (executor.Spec.RelocateSecrets). A list would have its first entry moved
//     and the rest left naming a directory that does not exist on the device,
//     on every agent already deployed, and kubectl skips a missing file without
//     a word: a device would quietly lose every cluster but the first.
//
// One document also states current-context outright, where a list leaves it to
// kubectl's rule that the first file to set it wins.
//
// # Names
//
// Each grant's cluster, user and context are renamed after its secret: the name
// sanitised to lower-case letters, digits and '-', so a context can be typed on
// a command line, listed in a comma-separated variable and quoted in a prompt
// without escaping, and suffixed -2, -3 … when another grant took it first. The
// same cluster granted twice renders "prod" and "prod-2". A grant whose document
// has several contexts (an unmonitored kubeconfig with more than one allowed
// context) keeps them apart by their own names, sanitised the same way:
// "corp-staging", "corp-production".
//
// Grants are taken narrowest first, as gitMaterialOrder takes GitHub grants:
// every namespace named before some admitted by a pattern, before none named at
// all; read-only before read-write; fewer namespaces first; then by secret name
// and grant id. The first grant's own context is current-context, so a kubectl
// that names no --context reaches the narrowest grant. The order is total, so
// the names are a function of the grants alone and the same lease renders the
// same document whatever order its materials arrive in — at dispatch, or in the
// hub process that adopts the run. Nothing the monitor keeps depends on them:
// a session is minted from the grant's own minimised document, under its own
// names, before anything here renames it, and that document is what a restore
// re-derives (Task 20383).
//
// Every reference is renamed through the document it came from. A context that
// names a cluster or user its own document does not define keeps naming
// nothing, under a name reserved so that no other grant's entry can take it: a
// dangling reference that resolved to another grant's credential is the one
// failure a merge must never produce.
//
// # Withdrawing one grant
//
// The document holds every grant's entry, so who owns the file decides what
// withdrawing one grant mid-run (Task 20403) takes with it.
//
//   - A monitored grant's entry holds a session token and nothing else.
//     Withdrawing the grant closes its session, which leaves the token
//     worthless, so the document stays and every other grant keeps working:
//     exactly that grant's access goes.
//   - An unmonitored grant's entry holds the cluster credential itself, and no
//     delivery path can cut one entry out of a file a workload may already have
//     open. So the document is attributed to every unmonitored grant in it, and
//     withdrawing any of them takes the whole document: the run is without
//     Kubernetes until its next dispatch renders the grants still standing.
//     That errs toward less access.
//
// When every grant is monitored the document is attributed to the narrowest,
// whose context is current-context. Some grant has to answer for it — a
// binding naming the file is how a delivery path knows the workload needs one
// at all (executor.Spec.NeedsSecretFiles) — so withdrawing that one grant takes
// the document too, which errs toward less access; withdrawing any other takes
// exactly its own.
//
// # Environment
//
// With one kubeconfig grant nothing changes. With several, KUBECONFIG names the
// merged document; CLOOP_K8S_NAMESPACE, CLOOP_K8S_ALLOWED_NAMESPACES,
// CLOOP_K8S_VERBS and CLOOP_KUBEGUARD_SESSION describe the grant behind
// current-context, which is what a kubectl naming no context reaches; and three
// more describe them all:
//
//	CLOOP_K8S_CONTEXTS        every context, current-context first
//	CLOOP_K8S_GRANTS          one JSON object per grant, in that order
//	CLOOP_KUBEGUARD_SESSIONS  every monitored grant's session id
//
// None of them is a credential, and none is attributed to one grant: they
// describe the lease's Kubernetes access as a whole, as CLOOP_LEASE_DIR
// describes its directory, so scrubbing a withdrawn grant's variables does not
// take a description the other grants still need.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// kubeconfigFileName and kubeconfigEnvVar are what every kubeconfig material
// renders: one file, named in KUBECONFIG.
const (
	kubeconfigFileName = "kubeconfig"
	kubeconfigEnvVar   = "KUBECONFIG"
)

// The variables a lease with several kubeconfig grants adds.
const (
	// KubeContextsEnvKey lists every context of the merged kubeconfig,
	// current-context first, comma-separated.
	KubeContextsEnvKey = "CLOOP_K8S_CONTEXTS"
	// KubeGrantsEnvKey describes every kubeconfig grant as a JSON array of
	// KubeGrantDescription, in the order of KubeContextsEnvKey.
	KubeGrantsEnvKey = "CLOOP_K8S_GRANTS"
	// KubeGuardSessionsEnvKey lists every monitored grant's session id,
	// comma-separated. Not a credential, for the reason KubeGuardSessionEnvKey
	// is not.
	KubeGuardSessionsEnvKey = "CLOOP_KUBEGUARD_SESSIONS"
)

// kubeSingleGrantEnv are the variables kubeMaterial sets for its own grant. In
// a lease with several kubeconfig grants they describe the grant behind
// current-context, set for the lease rather than by any one material.
var kubeSingleGrantEnv = []string{
	"CLOOP_K8S_NAMESPACE",
	"CLOOP_K8S_ALLOWED_NAMESPACES",
	"CLOOP_K8S_VERBS",
	KubeGuardSessionEnvKey,
}

// KubeGrantDescription is one grant's entry in CLOOP_K8S_GRANTS. Exported so
// a harness written in Go, and this package's tests, decode the variable with
// the type that wrote it.
type KubeGrantDescription struct {
	// Contexts are the grant's contexts in the merged kubeconfig, its own
	// current-context first.
	Contexts []string `json:"contexts"`
	// Secret names the secret the grant spends.
	Secret string `json:"secret"`
	// Namespace is the namespace the grant pins its contexts to, as
	// CLOOP_K8S_NAMESPACE says for a single grant. Absent when the allowlist
	// names none outright.
	Namespace string `json:"namespace,omitempty"`
	// AllowedNamespaces is the grant's namespace allowlist. Absent when the
	// grant is not narrowed by namespace.
	AllowedNamespaces []string `json:"allowed_namespaces,omitempty"`
	// Verbs are the verbs the grant permits.
	Verbs []string `json:"verbs"`
	// Monitored reports whether the grant's contexts reach their cluster
	// through the Kubernetes monitor, which enforces Namespace and Verbs;
	// unmonitored, the cluster's own RBAC is all that does.
	Monitored bool `json:"monitored"`
	// Session is a monitored grant's session id.
	Session string `json:"session,omitempty"`
}

// kubeDocument returns the index of m's kubeconfig file, or -1 when m renders
// none: a material of another kind, or one held without its files, as a lease
// taken over from another hub process is.
func kubeDocument(m Material) int {
	if m.Kind != KindKubeconfig {
		return -1
	}
	for i, f := range m.Files {
		if f.EnvVar == kubeconfigEnvVar {
			return i
		}
	}
	return -1
}

// kubeBreadth ranks how much of a cluster a grant reaches by namespace: 0 when
// every namespace it allows is named, 1 when a pattern admits some, 2 when it
// is not narrowed by namespace at all.
func kubeBreadth(c Constraints) int {
	if len(c.Namespaces) == 0 {
		return 2
	}
	for _, ns := range c.Namespaces {
		if strings.ContainsAny(ns, "*?[]") {
			return 1
		}
	}
	return 0
}

// kubeMaterialOrder returns the indices of materials' kubeconfig materials,
// narrowest first. The order is total; see the file comment.
func kubeMaterialOrder(materials []Material) []int {
	var kube []int
	for i, m := range materials {
		if kubeDocument(m) >= 0 {
			kube = append(kube, i)
		}
	}
	sort.SliceStable(kube, func(a, b int) bool {
		x, y := materials[kube[a]].Constraints, materials[kube[b]].Constraints
		if bx, by := kubeBreadth(x), kubeBreadth(y); bx != by {
			return bx < by
		}
		if rx, ry := x.KubeReadOnly(), y.KubeReadOnly(); rx != ry {
			return rx
		}
		if nx, ny := len(x.Namespaces), len(y.Namespaces); nx != ny {
			return nx < ny
		}
		mx, my := materials[kube[a]], materials[kube[b]]
		if mx.SecretName != my.SecretName {
			return mx.SecretName < my.SecretName
		}
		return mx.GrantID < my.GrantID
	})
	return kube
}

// Name lengths in the merged document. 63 is a DNS label's limit: nothing
// requires it of a kubeconfig name, but it keeps one short enough to read in a
// prompt and safe in a tool that assumes it. The stem — the part a secret's
// name contributes — leaves room for a context's own name and a suffix.
const (
	maxKubeName = 63
	maxKubeStem = 40
)

// kubeNameFallback stems a grant whose secret name sanitises to nothing.
const kubeNameFallback = "kube"

// sanitizeKubeName reduces s to lower-case letters, digits and single '-', at
// most max characters, with no '-' at either end.
func sanitizeKubeName(s string, max int) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	out := b.String()
	if len(out) > max {
		out = out[:max]
	}
	return strings.Trim(out, "-")
}

// kubeNames hands out the names of one list of the merged document.
type kubeNames map[string]bool

// claim returns base, or base suffixed -2, -3 … when that is taken, and marks
// the result taken.
func (n kubeNames) claim(base string) string {
	name := base
	for i := 2; n[name]; i++ {
		suffix := fmt.Sprintf("-%d", i)
		stem := base
		if len(stem)+len(suffix) > maxKubeName {
			stem = strings.TrimRight(stem[:maxKubeName-len(suffix)], "-")
		}
		name = stem + suffix
	}
	n[name] = true
	return name
}

// entryName names one entry of a grant's document in the merged one: the
// grant's stem alone when its document has one entry in that list, the stem
// and the entry's own name when it has several.
func entryName(stem, own string, several bool) string {
	if !several {
		return stem
	}
	part := sanitizeKubeName(own, maxKubeName)
	if part == "" {
		return stem
	}
	return sanitizeKubeName(stem+"-"+part, maxKubeName)
}

// mergeKubeEntries copies src's clusters or users into dst under names derived
// from stem, and returns what each was renamed to. A name src lists twice —
// which client-go refuses to load at all — keeps its first entry; the rest
// could never be referenced, and go with their credentials.
func mergeKubeEntries(dst *[]kubeNamedEntry, src []kubeNamedEntry, stem string, taken kubeNames) map[string]string {
	renamed := make(map[string]string, len(src))
	several := len(src) > 1
	for _, e := range src {
		if _, dup := renamed[e.Name]; dup {
			continue
		}
		name := taken.claim(entryName(stem, e.Name, several))
		renamed[e.Name] = name
		e.Name = name
		*dst = append(*dst, e)
	}
	return renamed
}

// kubeMergeLists are the merged document's three name spaces.
type kubeMergeLists struct {
	clusters, users, contexts kubeNames
}

// mergeKubeDocument copies doc into merged under names derived from stem, and
// returns the names its contexts took, its own current-context first.
func mergeKubeDocument(merged *kubeConfig, doc kubeConfig, stem string, lists kubeMergeLists) []string {
	clusters := mergeKubeEntries(&merged.Clusters, doc.Clusters, stem, lists.clusters)
	users := mergeKubeEntries(&merged.Users, doc.Users, stem, lists.users)
	// A reference its own document cannot resolve is reserved under a name
	// of this grant's, so it stays unresolved here too.
	resolve := func(renamed map[string]string, taken kubeNames, ref string) string {
		if ref == "" {
			return ""
		}
		if name, ok := renamed[ref]; ok {
			return name
		}
		name := taken.claim(entryName(stem, "undefined-"+ref, true))
		renamed[ref] = name
		return name
	}

	var names []string
	current := -1
	seen := make(map[string]bool, len(doc.Contexts))
	several := len(doc.Contexts) > 1
	for _, c := range doc.Contexts {
		if seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		own := c.Name
		c.Name = lists.contexts.claim(entryName(stem, own, several))
		c.Context.Cluster = resolve(clusters, lists.clusters, c.Context.Cluster)
		c.Context.User = resolve(users, lists.users, c.Context.User)
		merged.Contexts = append(merged.Contexts, c)
		if own == doc.CurrentContext && current < 0 {
			current = len(names)
		}
		names = append(names, c.Name)
	}
	if current > 0 {
		names[0], names[current] = names[current], names[0]
	}
	return names
}

// coalesceKubeconfig returns materials with every kubeconfig grant's document
// merged into one, carried by the narrowest grant's material, and the variables
// that describe the lease's Kubernetes access as a whole. A lease with at most
// one kubeconfig material is returned unchanged, with no variables. The input
// is not modified.
func coalesceKubeconfig(materials []Material) ([]Material, map[string]string, error) {
	order := kubeMaterialOrder(materials)
	if len(order) < 2 {
		return materials, nil, nil
	}
	out := append([]Material(nil), materials...)

	merged := kubeConfig{APIVersion: "v1", Kind: "Config"}
	lists := kubeMergeLists{clusters: kubeNames{}, users: kubeNames{}, contexts: kubeNames{}}
	stems := kubeNames{}
	var (
		owners   []string
		grants   []KubeGrantDescription
		contexts []string
		sessions []string
	)
	for rank, idx := range order {
		m := out[idx]
		fi := kubeDocument(m)
		var doc kubeConfig
		if err := yaml.Unmarshal(m.Files[fi].Content, &doc); err != nil {
			return nil, nil, wrapf(ErrMalformedPayload,
				"the kubeconfig of grant %s cannot be merged with the lease's others: %v", m.GrantID, err)
		}
		if len(doc.Contexts) == 0 {
			return nil, nil, wrapf(ErrMalformedPayload,
				"the kubeconfig of grant %s names no context to merge", m.GrantID)
		}
		stem := sanitizeKubeName(m.SecretName, maxKubeStem)
		if stem == "" {
			stem = kubeNameFallback
		}
		stem = stems.claim(stem)
		names := mergeKubeDocument(&merged, doc, stem, lists)
		if rank == 0 {
			merged.CurrentContext = names[0]
		}
		contexts = append(contexts, names...)

		session := strings.TrimSpace(m.Env[KubeGuardSessionEnvKey])
		if session == "" {
			// The cluster credential itself is in the document, and goes
			// with this grant.
			owners = append(owners, m.GrantID)
		} else {
			sessions = append(sessions, session)
		}
		grants = append(grants, KubeGrantDescription{
			Contexts:          names,
			Secret:            m.SecretName,
			Namespace:         firstConcreteNamespace(m.Constraints.Namespaces),
			AllowedNamespaces: append([]string(nil), m.Constraints.Namespaces...),
			Verbs:             m.Constraints.KubeVerbs(),
			Monitored:         session != "",
			Session:           session,
		})

		// The merged document replaces the material's own, and the lease's
		// variables replace its description of itself. Copies throughout:
		// the caller's materials still back the lease, and the session
		// variable on each is how the lease's end finds that session.
		m.Files = append(m.Files[:fi:fi], m.Files[fi+1:]...)
		env := make(map[string]string, len(m.Env))
		for k, v := range m.Env {
			env[k] = v
		}
		for _, k := range kubeSingleGrantEnv {
			delete(env, k)
		}
		m.Env = env
		out[idx] = m
	}

	if len(owners) == 0 {
		// Every grant is monitored: the narrowest answers for the document.
		owners = []string{materials[order[0]].GrantID}
	}
	data, err := yaml.Marshal(merged)
	if err != nil {
		return nil, nil, wrapf(ErrMalformedPayload, "encode the merged kubeconfig: %v", err)
	}
	carrier := out[order[0]]
	carrier.Files = append(append([]File(nil), carrier.Files...), File{
		Name:    kubeconfigFileName,
		Content: data,
		Mode:    0o600,
		EnvVar:  kubeconfigEnvVar,
		shared:  true,
		owners:  owners,
	})
	out[order[0]] = carrier

	env := make(map[string]string, len(kubeSingleGrantEnv)+3)
	for _, k := range kubeSingleGrantEnv {
		if v, ok := materials[order[0]].Env[k]; ok {
			env[k] = v
		}
	}
	env[KubeContextsEnvKey] = strings.Join(contexts, ",")
	desc, err := json.Marshal(grants)
	if err != nil {
		return nil, nil, fmt.Errorf("secretbroker: describe the lease's kubeconfig grants: %w", err)
	}
	env[KubeGrantsEnvKey] = string(desc)
	if len(sessions) > 0 {
		env[KubeGuardSessionsEnvKey] = strings.Join(sessions, ",")
	}
	return out, env, nil
}

// coalesceLease makes a lease's materials renderable into one directory: the
// GitHub materials' files made distinct (githubmulti.go) and the kubeconfig
// materials' documents merged (this file). It also returns the variables that
// describe the lease's Kubernetes access as a whole, which no material sets.
//
// render and tokenFileNames both go through it, so the names a refresh
// rewrites are the names a delivery wrote.
func coalesceLease(materials []Material) ([]Material, map[string]string, error) {
	out, err := coalesceGitHub(materials)
	if err != nil {
		return nil, nil, err
	}
	return coalesceKubeconfig(out)
}
