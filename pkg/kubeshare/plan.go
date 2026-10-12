package kubeshare

// plan.go decides what a share creates in the cluster, before anything is.
//
// Two rules here are security rules rather than conveniences, and both follow
// from what Kubernetes' built-in `edit` role contains. It is not just "write
// most objects": it may create Pods and Secrets, impersonate ServiceAccounts
// and create tokens for them, all within the namespace it is bound in. So a
// ServiceAccount that can write to its own namespace can mint credentials for
// itself several ways — a Pod running as it whose logs print its token, a
// Secret of type kubernetes.io/service-account-token, a TokenRequest — and
// every one of them is a credential that never passes through the monitor and
// outlives the token the share issued.
//
//   - Write access is therefore refused when the ServiceAccount would live in
//     one of the namespaces it writes. It must live somewhere it can only be
//     renewed from.
//   - Cluster-wide write is refused outright: there is no namespace outside it.
//
// Read access binds `view`, which reads neither Secrets nor Pod logs of a Pod
// it could have started, so a read share may live in a namespace it reads.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// Request is what `cloop remote kube share` asks for.
type Request struct {
	// Name is the secret's name on the hub, and part of every object's name.
	Name string
	// ID is the share's id; empty generates one.
	ID string
	// Namespaces are where the ServiceAccount is bound.
	Namespaces []string
	// ServiceAccountNamespace is where the ServiceAccount lives. Empty means
	// the first shared namespace, for read access only.
	ServiceAccountNamespace string
	Access                  Access
	// ClusterWide binds `view` with a ClusterRoleBinding instead of one
	// RoleBinding per namespace. Read access only.
	ClusterWide bool
	TTL         time.Duration
	Renewal     Renewal
	// Hub and Owner annotate the objects, so whoever finds them in the
	// cluster can tell where they came from and whose they are.
	Hub   string
	Owner string
	// Context is the developer's kubeconfig context, recorded for renew and
	// revoke.
	Context string
	// Server is the API server the stored kubeconfig names.
	Server string
}

// Plan is a validated request with every name decided.
type Plan struct {
	Request
	// ServiceAccount is the ServiceAccount's name.
	ServiceAccount string
	created        time.Time
}

// dnsLabel is RFC 1123's label: what a namespace and most object names must be.
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// dnsSubdomain is RFC 1123's subdomain: what a ServiceAccount's name must be.
var dnsSubdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

// shareIDPattern is what NewID produces, and all a share id may be.
var shareIDPattern = regexp.MustCompile(`^[a-z0-9]{4,16}$`)

// ValidShareID reports whether s can be a share's id.
func ValidShareID(s string) bool { return shareIDPattern.MatchString(s) }

// ValidNamespace reports whether s can name a namespace.
func ValidNamespace(s string) bool { return len(s) <= 63 && dnsLabel.MatchString(s) }

// ValidServiceAccountName reports whether s can name a ServiceAccount — and so
// one of a share's objects, which are all named after it.
func ValidServiceAccountName(s string) bool { return len(s) <= 253 && dnsSubdomain.MatchString(s) }

// IsShareServiceAccount reports whether name is the ServiceAccount a share
// with this id creates: "cloop-<name>-<id>", as serviceAccountName builds it.
// The hub holds a share to it (Task 20420), so a share's token — whose claims
// nobody verified — cannot point renew at some other ServiceAccount.
func IsShareServiceAccount(name, id string) bool {
	return id != "" && len(name) <= 63-len("-renew") && dnsLabel.MatchString(name) &&
		strings.HasPrefix(name, "cloop-") && strings.HasSuffix(name, "-"+id) && len(name) > len("cloop-")+len(id)+1
}

// NewPlan validates req and decides every name.
func NewPlan(req Request, now time.Time) (*Plan, error) {
	req.Name = strings.TrimSpace(req.Name)
	if err := secretbroker.ValidateName(req.Name); err != nil {
		return nil, err
	}
	var err error
	if req.Access, err = ParseAccess(string(req.Access)); err != nil {
		return nil, err
	}
	switch req.Renewal {
	case RenewalHub, RenewalManual:
	case "":
		req.Renewal = RenewalManual
	default:
		return nil, fmt.Errorf("renewal %q: want %s or %s", req.Renewal, RenewalHub, RenewalManual)
	}
	if req.TTL == 0 {
		req.TTL = DefaultTTL
	}
	if req.TTL < MinTTL || req.TTL > MaxTTL {
		return nil, fmt.Errorf("--ttl %s: a share's token lives between %s (the shortest the TokenRequest "+
			"API issues) and %s", req.TTL, MinTTL, shortDuration(MaxTTL))
	}

	seen := map[string]bool{}
	var namespaces []string
	for _, ns := range req.Namespaces {
		ns = strings.TrimSpace(ns)
		if ns == "" || seen[ns] {
			continue
		}
		if strings.ContainsAny(ns, "*?[]") {
			return nil, fmt.Errorf("namespace %q: a share binds named namespaces, one RoleBinding each, so "+
				"patterns are not accepted", ns)
		}
		if !ValidNamespace(ns) {
			return nil, fmt.Errorf("%q is not a namespace name (lowercase letters, digits and '-', at most 63)", ns)
		}
		seen[ns] = true
		namespaces = append(namespaces, ns)
	}
	req.Namespaces = namespaces

	switch {
	case req.ClusterWide && len(namespaces) > 0:
		return nil, fmt.Errorf("--cluster-wide shares every namespace; drop --namespaces, or drop " +
			"--cluster-wide to share only those")
	case req.ClusterWide && req.Access == AccessWrite:
		return nil, fmt.Errorf("cluster-wide write access is refused: `edit` everywhere includes the " +
			"ServiceAccount's own namespace, where it could create Pods and Secrets that hand a workload its " +
			"credential outside the monitor. Share write access per namespace with --namespaces")
	case !req.ClusterWide && len(namespaces) == 0:
		return nil, fmt.Errorf("name the namespaces to share with --namespaces a,b (or --cluster-wide for " +
			"read access to every namespace)")
	}

	saNS := strings.TrimSpace(req.ServiceAccountNamespace)
	if saNS == "" {
		switch {
		case req.Access == AccessWrite:
			return nil, fmt.Errorf("write access needs --sa-namespace: the ServiceAccount must live in a "+
				"namespace it cannot write, or a workload could mint its credential there (with `edit` it "+
				"may create Pods and Secrets in %s). Name one you control that is not among %s",
				strings.Join(namespaces, ", "), strings.Join(namespaces, ", "))
		case req.ClusterWide:
			return nil, fmt.Errorf("--cluster-wide needs --sa-namespace to say where the ServiceAccount lives")
		default:
			saNS = namespaces[0]
		}
	}
	if !ValidNamespace(saNS) {
		return nil, fmt.Errorf("--sa-namespace %q is not a namespace name", saNS)
	}
	if req.Access == AccessWrite && seen[saNS] {
		return nil, fmt.Errorf("--sa-namespace %s is one of the namespaces this share writes: with `edit` "+
			"there a workload could create a Pod running as the ServiceAccount, or a token Secret for it, and "+
			"take its credential outside the monitor. Put the ServiceAccount in a namespace it only renews from",
			saNS)
	}
	req.ServiceAccountNamespace = saNS

	if req.ID == "" {
		if req.ID, err = NewID(); err != nil {
			return nil, err
		}
	}
	if !shareIDPattern.MatchString(req.ID) {
		return nil, fmt.Errorf("share id %q is not 4-16 lowercase letters and digits", req.ID)
	}
	return &Plan{Request: req, ServiceAccount: serviceAccountName(req.Name, req.ID), created: now.UTC()}, nil
}

// NewID returns a fresh share id.
func NewID() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("share id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// serviceAccountName is "cloop-<name>-<id>", the name squeezed into a DNS label
// with room left for the renewal Role's "-renew".
func serviceAccountName(name, id string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		default:
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	slug := strings.Trim(b.String(), "-")
	const budget = 63 - len("-renew")
	room := budget - len("cloop-") - 1 - len(id)
	if len(slug) > room {
		slug = strings.TrimRight(slug[:room], "-")
	}
	if slug == "" {
		slug = "share"
	}
	return "cloop-" + slug + "-" + id
}

// RenewRoleName is the self-renewal Role's name, and its binding's.
func (p *Plan) RenewRoleName() string { return p.ServiceAccount + "-renew" }

// Objects lists what the plan creates, in creation order: the ServiceAccount
// first, so every binding names something that exists.
func (p *Plan) Objects() []Object {
	return planObjects(p.ServiceAccountNamespace, p.ServiceAccount, p.ClusterWide, p.Namespaces, p.Renewal)
}

// planObjects is the one definition of what a share creates, shared by a plan
// and by a share read back from the hub (Share.ExpectedObjects).
func planObjects(saNamespace, sa string, clusterWide bool, namespaces []string, renewal Renewal) []Object {
	out := []Object{{Kind: "ServiceAccount", Namespace: saNamespace, Name: sa}}
	if clusterWide {
		out = append(out, Object{Kind: "ClusterRoleBinding", Name: sa})
	}
	for _, ns := range namespaces {
		out = append(out, Object{Kind: "RoleBinding", Namespace: ns, Name: sa})
	}
	if renewal == RenewalHub {
		out = append(out,
			Object{Kind: "Role", Namespace: saNamespace, Name: sa + "-renew"},
			Object{Kind: "RoleBinding", Namespace: saNamespace, Name: sa + "-renew"})
	}
	return out
}

// Share is the plan as the hub's metadata will describe it.
func (p *Plan) Share() Share {
	return Share{
		ID: p.ID, Renewal: p.Renewal, Namespace: p.ServiceAccountNamespace,
		ServiceAccount: p.ServiceAccount, Namespaces: append([]string(nil), p.Namespaces...),
		ClusterWide: p.ClusterWide, Access: p.Access, Server: p.Server, Context: p.Context,
		Objects: p.Objects(), Owner: p.Owner,
	}
}

// Manifest is one object to create: where to POST it and what to send.
type Manifest struct {
	Object
	// Collection is the API path the object is created under.
	Collection string
	// Body is the object.
	Body map[string]any
}

// Manifests renders every object in creation order.
func (p *Plan) Manifests() []Manifest {
	var out []Manifest
	for _, o := range p.Objects() {
		out = append(out, Manifest{Object: o, Collection: CollectionPath(o), Body: p.body(o)})
	}
	return out
}

// meta is the metadata every object carries.
func (p *Plan) meta(o Object) map[string]any {
	m := map[string]any{
		"name":   o.Name,
		"labels": map[string]any{LabelShare: p.ID, LabelManagedBy: managedByValue},
		"annotations": map[string]any{
			AnnotationName:    p.Name,
			AnnotationAccess:  string(p.Access),
			AnnotationCreated: p.created.Format(time.RFC3339),
		},
	}
	ann := m["annotations"].(map[string]any)
	if p.Hub != "" {
		ann[AnnotationHub] = p.Hub
	}
	if p.Owner != "" {
		ann[AnnotationOwner] = p.Owner
	}
	if o.Namespace != "" {
		m["namespace"] = o.Namespace
	}
	return m
}

func (p *Plan) subject() []any {
	return []any{map[string]any{
		"kind": "ServiceAccount", "name": p.ServiceAccount, "namespace": p.ServiceAccountNamespace,
	}}
}

func (p *Plan) body(o Object) map[string]any {
	switch {
	case o.Kind == "ServiceAccount":
		// No token is mounted into a Pod that names it: nothing should ever
		// run as this ServiceAccount, and a mounted token would be one more
		// copy of its credential.
		return map[string]any{
			"apiVersion": "v1", "kind": "ServiceAccount", "metadata": p.meta(o),
			"automountServiceAccountToken": false,
		}
	case o.Kind == "ClusterRoleBinding":
		return map[string]any{
			"apiVersion": rbacAPIVersion, "kind": "ClusterRoleBinding", "metadata": p.meta(o),
			"roleRef":  map[string]any{"apiGroup": rbacGroup, "kind": "ClusterRole", "name": p.Access.ClusterRole()},
			"subjects": p.subject(),
		}
	case o.Kind == "Role":
		// The one permission the hub renews with: create a token for this
		// ServiceAccount and no other. The monitor refuses the subresource
		// to every sandbox, so only the hub can spend it.
		return map[string]any{
			"apiVersion": rbacAPIVersion, "kind": "Role", "metadata": p.meta(o),
			"rules": []any{map[string]any{
				"apiGroups":     []any{""},
				"resources":     []any{"serviceaccounts/token"},
				"verbs":         []any{"create"},
				"resourceNames": []any{p.ServiceAccount},
			}},
		}
	case o.Kind == "RoleBinding" && o.Name == p.RenewRoleName():
		return map[string]any{
			"apiVersion": rbacAPIVersion, "kind": "RoleBinding", "metadata": p.meta(o),
			"roleRef":  map[string]any{"apiGroup": rbacGroup, "kind": "Role", "name": p.RenewRoleName()},
			"subjects": p.subject(),
		}
	default: // a shared namespace's RoleBinding
		return map[string]any{
			"apiVersion": rbacAPIVersion, "kind": "RoleBinding", "metadata": p.meta(o),
			"roleRef":  map[string]any{"apiGroup": rbacGroup, "kind": "ClusterRole", "name": p.Access.ClusterRole()},
			"subjects": p.subject(),
		}
	}
}

// Describe renders the plan for a person, one line per decision.
func (p *Plan) Describe() []string {
	lines := []string{
		fmt.Sprintf("ServiceAccount  %s/%s (no token mounted into Pods)", p.ServiceAccountNamespace, p.ServiceAccount),
	}
	verb := "Read"
	if p.Access == AccessWrite {
		verb = "Write"
	}
	if p.ClusterWide {
		lines = append(lines, fmt.Sprintf("%-14s  every namespace (ClusterRoleBinding %s -> ClusterRole %s)",
			verb+" access", p.ServiceAccount, p.Access.ClusterRole()))
	} else {
		lines = append(lines, fmt.Sprintf("%-14s  %s (RoleBinding %s -> ClusterRole %s in each)",
			verb+" access", strings.Join(p.Namespaces, ", "), p.ServiceAccount, p.Access.ClusterRole()))
	}
	if p.Renewal == RenewalHub {
		lines = append(lines, fmt.Sprintf("Self-renewal    Role %s in %s: create serviceaccounts/token for %s only; "+
			"the hub's Kubernetes monitor refuses it to every sandbox",
			p.RenewRoleName(), p.ServiceAccountNamespace, p.ServiceAccount))
	} else {
		lines = append(lines, "Self-renewal    none: renew with `cloop remote kube renew "+p.Name+"`")
	}
	lines = append(lines, fmt.Sprintf("Token           %s, through the TokenRequest API", shortDuration(p.TTL)))
	return lines
}

// API groups and paths.
const (
	rbacGroup      = "rbac.authorization.k8s.io"
	rbacAPIVersion = rbacGroup + "/v1"
)

// CollectionPath is where an object of o's kind is created.
func CollectionPath(o Object) string {
	switch o.Kind {
	case "ServiceAccount":
		return "/api/v1/namespaces/" + o.Namespace + "/serviceaccounts"
	case "Role":
		return "/apis/" + rbacAPIVersion + "/namespaces/" + o.Namespace + "/roles"
	case "RoleBinding":
		return "/apis/" + rbacAPIVersion + "/namespaces/" + o.Namespace + "/rolebindings"
	case "ClusterRoleBinding":
		return "/apis/" + rbacAPIVersion + "/clusterrolebindings"
	}
	return ""
}

// ObjectPath is o's own path.
func ObjectPath(o Object) string {
	c := CollectionPath(o)
	if c == "" {
		return ""
	}
	return c + "/" + o.Name
}

// shortDuration renders 24h0m0s as 24h and 168h0m0s as 7d.
func shortDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}

// ShortDuration is shortDuration for callers rendering a share.
func ShortDuration(d time.Duration) string { return shortDuration(d) }
