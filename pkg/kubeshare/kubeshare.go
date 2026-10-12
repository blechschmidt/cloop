// Package kubeshare is a Kubernetes cluster shared with a cloop hub through a
// least-privilege ServiceAccount (Task 20416).
//
// # Why it exists
//
// The clusters enterprises run authenticate people through exec credential
// plugins — kubelogin on AKS, `aws eks get-token` on EKS, the GKE plugin — and
// the hub refuses such a kubeconfig, because running the plugin there would
// execute a program named in an uploaded file on the control-plane host. The
// refusal used to be the end of it: the developer had to create a
// ServiceAccount, choose and bind roles, mint a token and assemble a kubeconfig
// by hand, and the token then expired mid-run because managed API servers cap
// how long one may live.
//
// A share does that work from the developer's own terminal (`cloop remote kube
// share`, which runs the plugin there through pkg/kubeexec) and leaves the hub
// holding only a static kubeconfig for a ServiceAccount that can do exactly what
// the developer chose:
//
//   - a labelled ServiceAccount in a namespace the developer names;
//   - a RoleBinding in each shared namespace to the cluster's own `view` role,
//     or `edit` for write access — never a ClusterRoleBinding unless asked;
//   - a bounded token, minted through the TokenRequest API.
//
// When the hub runs the Kubernetes access monitor, the share renews itself: one
// more Role lets the ServiceAccount create a token for itself and nobody else
// (resourceNames), and the hub uses it to mint the next token before the
// current one expires. The monitor refuses the serviceaccounts/token
// subresource to every sandbox (pkg/kubeguard), so the permission is the hub's
// to spend and never the workload's. Without the monitor the token would sit
// in the sandbox, so no such Role is installed and the developer renews with
// `cloop remote kube renew`.
//
// # What this package is, and is not
//
// The plan of objects, the few Kubernetes API calls a share makes, the token's
// claims, the static kubeconfig, the metadata the hub keeps on the secret, and
// the hub's renewal. It never runs a credential plugin and never reads a file
// a kubeconfig names: the hub imports it, and tests/security holds it to that.
package kubeshare

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// Access is what a share lets its ServiceAccount do in the shared namespaces.
type Access string

const (
	// AccessRead binds the cluster's `view` role: read most objects, not
	// Secrets, and nothing that writes.
	AccessRead Access = "read"
	// AccessWrite binds `edit`: read and write most namespaced objects.
	AccessWrite Access = "write"
)

// ClusterRole is the built-in role a binding of this access names.
func (a Access) ClusterRole() string {
	if a == AccessWrite {
		return "edit"
	}
	return "view"
}

// ParseAccess reads --access.
func ParseAccess(s string) (Access, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "read", "ro", "view":
		return AccessRead, nil
	case "write", "rw", "edit":
		return AccessWrite, nil
	}
	return "", fmt.Errorf("--access %q: want read or write", s)
}

// Renewal says who keeps a share's token current.
type Renewal string

const (
	// RenewalHub: the hub mints the next token before the current one
	// expires, with the ServiceAccount's own self-renewal Role. Only offered
	// by a hub that runs the Kubernetes access monitor.
	RenewalHub Renewal = secretbroker.KubeShareRenewalHub
	// RenewalManual: the developer renews from their terminal with
	// `cloop remote kube renew`.
	RenewalManual Renewal = "manual"
)

// Token lifetimes.
const (
	// MinTTL is the shortest token the TokenRequest API issues.
	MinTTL = 10 * time.Minute
	// MaxTTL is the longest token a share asks for. A share exists so that
	// nobody hands a sandbox a credential that outlives the work; a token for
	// longer than a week is that credential.
	MaxTTL = 7 * 24 * time.Hour
	// DefaultTTL is what a share asks for when --ttl is not given.
	DefaultTTL = 24 * time.Hour
)

// The metadata keys the hub keeps on a share's secret. None is a credential —
// metadata lands in audit rows and API responses — and the time fields are
// derived by the hub from the token itself, not trusted from the client.
const (
	// MetaShare is the share's id, and the mark that a kubeconfig secret is a
	// share at all.
	MetaShare = "kube.share"
	// MetaRenewal is RenewalHub or RenewalManual.
	MetaRenewal = secretbroker.KubeShareMetaRenewal
	// MetaServiceAccount is "<namespace>/<name>".
	MetaServiceAccount = "kube.service_account"
	// MetaNamespaces lists the shared namespaces, comma-separated; "*" for a
	// share bound cluster-wide.
	MetaNamespaces = "kube.namespaces"
	// MetaAccess is read or write.
	MetaAccess = "kube.access"
	// MetaServer is the API server the share's kubeconfig names.
	MetaServer = "kube.server"
	// MetaContext is the developer's kubeconfig context the share was made
	// from, which renew and revoke default to.
	MetaContext = "kube.context"
	// MetaObjects lists the objects the share created, for revoke.
	MetaObjects = "kube.objects"
	// MetaIssuedAt and MetaExpiresAt bound the token the secret holds.
	MetaIssuedAt  = "kube.issued_at"
	MetaExpiresAt = "kube.expires_at"
	// MetaRenewedAt, MetaRenewedBy and MetaRenewals describe the last renewal.
	MetaRenewedAt = "kube.renewed_at"
	MetaRenewedBy = "kube.renewed_by"
	MetaRenewals  = "kube.renewals"
	// MetaRenewError and MetaRenewErrorAt hold why the last renewal attempt
	// failed, until one succeeds.
	MetaRenewError   = "kube.renew_error"
	MetaRenewErrorAt = "kube.renew_error_at"
	// MetaRenewState is "lapsed" once the token expired with no renewal: the
	// hub cannot renew it any more, only its owner can.
	MetaRenewState = "kube.renew_state"
)

// RenewStateLapsed is MetaRenewState's one value.
const RenewStateLapsed = "lapsed"

// maxMetaValue bounds a metadata value the hub writes from an error.
const maxMetaValue = 300

// Labels and annotations on every object a share creates. The label is what
// revoke and an administrator find them by; the selector deliberately shares
// nothing with the executor's own (cloop.dev/managed), so the Kubernetes
// executor's orphan sweep can never mistake a share for something it owns.
const (
	LabelShare     = "cloop.dev/kube-share"
	LabelManagedBy = "app.kubernetes.io/managed-by"
	managedByValue = "cloop"

	AnnotationName    = "cloop.dev/share-name"
	AnnotationHub     = "cloop.dev/hub"
	AnnotationOwner   = "cloop.dev/owner"
	AnnotationAccess  = "cloop.dev/access"
	AnnotationCreated = "cloop.dev/created-at"
)

// Share is a share as the hub's secret metadata describes it.
type Share struct {
	ID             string
	Renewal        Renewal
	Namespace      string // the ServiceAccount's
	ServiceAccount string
	Namespaces     []string
	ClusterWide    bool
	Access         Access
	Server         string
	Context        string
	Objects        []Object
	IssuedAt       time.Time
	ExpiresAt      time.Time
	RenewedAt      time.Time
	RenewedBy      string
	Renewals       int
	RenewError     string
	RenewErrorAt   time.Time
	Lapsed         bool
}

// IsShare reports whether metadata marks a kubeconfig secret as a share.
func IsShare(meta map[string]string) bool {
	return strings.TrimSpace(meta[MetaShare]) != ""
}

// FromMetadata reads a share back. ok is false for a secret that is not one.
func FromMetadata(meta map[string]string) (Share, bool) {
	if !IsShare(meta) {
		return Share{}, false
	}
	s := Share{
		ID:         strings.TrimSpace(meta[MetaShare]),
		Renewal:    Renewal(strings.TrimSpace(meta[MetaRenewal])),
		Access:     Access(strings.TrimSpace(meta[MetaAccess])),
		Server:     strings.TrimSpace(meta[MetaServer]),
		Context:    strings.TrimSpace(meta[MetaContext]),
		RenewedBy:  strings.TrimSpace(meta[MetaRenewedBy]),
		RenewError: strings.TrimSpace(meta[MetaRenewError]),
		Lapsed:     strings.TrimSpace(meta[MetaRenewState]) == RenewStateLapsed,
	}
	if s.Renewal != RenewalHub {
		s.Renewal = RenewalManual
	}
	if s.Access != AccessWrite {
		s.Access = AccessRead
	}
	if ns, name, ok := strings.Cut(strings.TrimSpace(meta[MetaServiceAccount]), "/"); ok {
		s.Namespace, s.ServiceAccount = ns, name
	}
	for _, n := range strings.Split(meta[MetaNamespaces], ",") {
		n = strings.TrimSpace(n)
		switch {
		case n == "*":
			s.ClusterWide = true
		case n != "":
			s.Namespaces = append(s.Namespaces, n)
		}
	}
	s.Objects = ParseObjects(meta[MetaObjects])
	s.IssuedAt = parseTime(meta[MetaIssuedAt])
	s.ExpiresAt = parseTime(meta[MetaExpiresAt])
	s.RenewedAt = parseTime(meta[MetaRenewedAt])
	s.RenewErrorAt = parseTime(meta[MetaRenewErrorAt])
	s.Renewals, _ = strconv.Atoi(strings.TrimSpace(meta[MetaRenewals]))
	return s, true
}

// SharedNamespaces renders the namespaces for a person: "team-a, team-b", or
// "every namespace" for a cluster-wide share.
func (s Share) SharedNamespaces() string {
	if s.ClusterWide {
		return "every namespace"
	}
	return strings.Join(s.Namespaces, ", ")
}

// Due reports whether a share's token should be renewed now: less than half
// its lifetime remains. Half rather than a fixed margin, so a hub that is down
// for less than half a token's life never loses the chain — a 24-hour token is
// renewed every 12 hours and survives a 12-hour outage, a 10-minute one is
// renewed every 5 minutes.
//
// A share whose times are unknown is due, which makes the renewal read them
// from the token and record them.
func (s Share) Due(now time.Time) bool {
	if s.ExpiresAt.IsZero() || s.IssuedAt.IsZero() || !s.ExpiresAt.After(s.IssuedAt) {
		return true
	}
	half := s.ExpiresAt.Sub(s.IssuedAt) / 2
	return !now.Before(s.ExpiresAt.Add(-half))
}

// Expired reports whether the token the hub holds has run out.
func (s Share) Expired(now time.Time) bool {
	return !s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt)
}

// Lifetime is the token's issued lifetime, which a renewal asks for again.
func (s Share) Lifetime() time.Duration {
	if s.ExpiresAt.IsZero() || s.IssuedAt.IsZero() {
		return 0
	}
	return s.ExpiresAt.Sub(s.IssuedAt)
}

// Metadata renders a share's descriptive fields for the secret. The time and
// renewal-history fields are the hub's to write and are left to it.
func (s Share) Metadata() map[string]string {
	ns := strings.Join(s.Namespaces, ",")
	if s.ClusterWide {
		ns = "*"
	}
	m := map[string]string{
		MetaShare:          s.ID,
		MetaRenewal:        string(s.Renewal),
		MetaServiceAccount: s.Namespace + "/" + s.ServiceAccount,
		MetaNamespaces:     ns,
		MetaAccess:         string(s.Access),
		MetaServer:         s.Server,
		MetaObjects:        FormatObjects(s.Objects),
	}
	if s.Context != "" {
		m[MetaContext] = s.Context
	}
	return m
}

// RecordToken writes the token's own claims into meta: the hub's half of the
// metadata, from the credential rather than from whoever sent it.
func RecordToken(meta map[string]string, c Claims) {
	meta[MetaServiceAccount] = c.Namespace + "/" + c.ServiceAccount
	meta[MetaIssuedAt] = c.IssuedAt.UTC().Format(time.RFC3339)
	meta[MetaExpiresAt] = c.ExpiresAt.UTC().Format(time.RFC3339)
}

// RecordRenewal stamps a successful renewal: new times, who renewed, one more
// renewal, and any earlier failure cleared.
func RecordRenewal(meta map[string]string, c Claims, by string, at time.Time) {
	RecordToken(meta, c)
	meta[MetaRenewedAt] = at.UTC().Format(time.RFC3339)
	meta[MetaRenewedBy] = by
	n, _ := strconv.Atoi(strings.TrimSpace(meta[MetaRenewals]))
	meta[MetaRenewals] = strconv.Itoa(n + 1)
	delete(meta, MetaRenewError)
	delete(meta, MetaRenewErrorAt)
	delete(meta, MetaRenewState)
}

// RecordFailure stamps a failed renewal attempt. lapsed marks a token that has
// expired, which only its owner can now replace.
func RecordFailure(meta map[string]string, reason string, at time.Time, lapsed bool) {
	meta[MetaRenewError] = FailureText(reason)
	meta[MetaRenewErrorAt] = at.UTC().Format(time.RFC3339)
	if lapsed {
		meta[MetaRenewState] = RenewStateLapsed
	}
}

// FailureText is a renewal failure as RecordFailure stores it: trimmed and
// bounded, so a caller can tell whether the stored one already says it.
func FailureText(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) > maxMetaValue {
		reason = strings.ToValidUTF8(reason[:maxMetaValue-1], "") + "…"
	}
	return reason
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// Object is one Kubernetes object a share created.
type Object struct {
	Kind      string // ServiceAccount, RoleBinding, Role, ClusterRoleBinding
	Namespace string // empty for a ClusterRoleBinding
	Name      string
}

func (o Object) String() string {
	if o.Namespace == "" {
		return o.Kind + " " + o.Name
	}
	return o.Kind + " " + o.Namespace + "/" + o.Name
}

// FormatObjects renders objects for MetaObjects: "Kind:ns/name" entries, comma
// separated, "Kind:name" for a cluster-scoped one. Names and namespaces are DNS
// labels, so none of the separators can occur inside one.
func FormatObjects(objs []Object) string {
	parts := make([]string, 0, len(objs))
	for _, o := range objs {
		if o.Namespace == "" {
			parts = append(parts, o.Kind+":"+o.Name)
			continue
		}
		parts = append(parts, o.Kind+":"+o.Namespace+"/"+o.Name)
	}
	return strings.Join(parts, ",")
}

// ParseObjects reads MetaObjects back. Malformed entries are skipped: revoke
// also finds objects by label, so a lost entry costs nothing.
func ParseObjects(s string) []Object {
	var out []Object
	for _, part := range strings.Split(s, ",") {
		kind, rest, ok := strings.Cut(strings.TrimSpace(part), ":")
		if !ok || kind == "" || rest == "" {
			continue
		}
		o := Object{Kind: kind, Name: rest}
		if ns, name, nested := strings.Cut(rest, "/"); nested {
			o.Namespace, o.Name = ns, name
		}
		if o.Name == "" {
			continue
		}
		out = append(out, o)
	}
	return out
}
