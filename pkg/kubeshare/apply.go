package kubeshare

// apply.go creates a share's objects and takes them away again.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Apply creates the plan's objects in order. If one fails it deletes the ones
// it created, newest first, and returns the failure together with anything the
// rollback could not remove — a half-made share is worse than none, because a
// binding left behind grants access nobody is tracking.
//
// An object that already exists is a failure too, never adopted: its name
// carries this share's id, so it can only be left over from something else.
func Apply(ctx context.Context, c *Client, p *Plan) ([]Object, error) {
	var created []Object
	for _, m := range p.Manifests() {
		if err := c.Create(ctx, m); err != nil {
			cause := explainCreate(m.Object, p, err)
			if left := rollback(c, created); len(left) > 0 {
				cause = fmt.Errorf("%w; and the rollback could not remove %s — delete them by hand: "+
					"kubectl delete %s", cause, joinObjects(left), deleteCommand(left))
			}
			return nil, cause
		}
		created = append(created, m.Object)
	}
	return created, nil
}

// explainCreate names what a failed create means in this context.
func explainCreate(o Object, p *Plan, err error) error {
	switch {
	case IsConflict(err):
		return fmt.Errorf("create %s: it already exists, and a share never takes over an object it did not "+
			"create: %w", o, err)
	case IsNotFound(err) && o.Namespace != "":
		return fmt.Errorf("create %s: namespace %s does not exist (a share binds existing namespaces and "+
			"creates none): %w", o, o.Namespace, err)
	case IsForbidden(err) && o.Kind == "RoleBinding" && o.Name != p.RenewRoleName():
		return fmt.Errorf("create %s: your credential may not bind ClusterRole %s there. Kubernetes lets you "+
			"grant only what you hold yourself — you need %s in %s, or the bind verb: %w",
			o, p.Access.ClusterRole(), p.Access.ClusterRole(), o.Namespace, err)
	case IsForbidden(err):
		return fmt.Errorf("create %s: your credential may not: %w", o, err)
	}
	return fmt.Errorf("create %s: %w", o, err)
}

// rollback deletes created, newest first, and returns what it could not.
func rollback(c *Client, created []Object) []Object {
	ctx, cancel := context.WithTimeout(context.Background(), 2*requestTimeout)
	defer cancel()
	var left []Object
	for i := len(created) - 1; i >= 0; i-- {
		if err := c.Delete(ctx, created[i]); err != nil {
			left = append(left, created[i])
		}
	}
	return left
}

// Mint mints the share's first token for the plan's ServiceAccount.
func Mint(ctx context.Context, c *Client, p *Plan) (Token, Claims, error) {
	tok, err := c.RequestToken(ctx, p.ServiceAccountNamespace, p.ServiceAccount, p.TTL)
	if err != nil {
		return Token{}, Claims{}, fmt.Errorf("mint a token for %s/%s: %w", p.ServiceAccountNamespace, p.ServiceAccount, err)
	}
	claims, err := ParseClaims(tok.Value)
	if err != nil {
		return Token{}, Claims{}, fmt.Errorf("the cluster minted a token cloop cannot read: %w", err)
	}
	return tok, claims, nil
}

// Removal is what Remove did.
type Removal struct {
	// Removed are the objects deleted.
	Removed []Object
	// Gone are the objects Remove looked for and the cluster no longer has.
	Gone []Object
	// Refused are objects Remove found and did not delete, because nothing
	// read back from the cluster says this share created them, with why.
	Refused map[Object]string
	// Failed are the ones that could not be removed, with why — including a
	// ServiceAccount Remove refused, which leaves every token minted for it
	// valid until it expires.
	Failed map[Object]error
}

// Clean reports that nothing the share created was left behind.
func (r Removal) Clean() bool { return len(r.Failed) == 0 }

// disowns reports why an object read back from the cluster is not one this
// share created, or "" when it is: it must carry the share's label and an
// owner annotation naming the share's owner. Both are set at creation and
// neither is anything a share's metadata — its uploader's to write — can
// supply (Task 20420).
func (s Share) disowns(m ObjectMeta) string {
	if !ValidShareID(s.ID) {
		return "the share has no valid id to match it by"
	}
	switch got := m.Labels[LabelShare]; {
	case got == "":
		return "it does not carry the " + LabelShare + " label, so no share created it"
	case got != s.ID:
		return fmt.Sprintf("its %s label is %q, another share's", LabelShare, got)
	}
	if ann := m.Annotations[AnnotationOwner]; !OwnerMatches(ann, s.Owner) {
		owner := s.Owner
		if owner == "" {
			owner = "nobody"
		}
		return fmt.Sprintf("its %s annotation is %q, and the hub records the share as %s's", AnnotationOwner, ann, owner)
	}
	return ""
}

// Remove deletes what a share created in the cluster, and nothing else.
//
// Revoke runs with the developer's own credentials — often an administrator's
// — over a share whose metadata its uploader wrote. So nothing in that
// metadata is taken on trust (Task 20420). The candidates are what the share's
// plan creates (ExpectedObjects), what its metadata lists, and what carries
// its label in the namespaces it names; each is read back from the cluster and
// deleted only if it carries the share's label and an owner annotation naming
// the share's owner, and then by uid and resourceVersion, so an object that
// changed after it was read is not the one deleted. Anything else is left
// alone and reported in Refused.
//
// The ServiceAccount goes first. Deleting it invalidates every token ever
// minted for it at once — the hub's, and any copy a workload kept — so the
// credential is dead before the first binding is touched, and a revoke that
// fails halfway leaves bindings to nothing rather than a live token. A
// ServiceAccount that exists and is not the share's is a failure, not just a
// refusal: whatever tokens the share holds stay valid until they expire.
func Remove(ctx context.Context, c *Client, s Share) Removal {
	res := Removal{Failed: map[Object]error{}, Refused: map[Object]string{}}
	done := map[Object]bool{}
	sa := Object{Kind: "ServiceAccount", Namespace: s.Namespace, Name: s.ServiceAccount}

	consider := func(o Object, listed *ObjectMeta) {
		if done[o] {
			return
		}
		done[o] = true
		if !o.Valid() {
			res.Refused[o] = "it is not an object a share creates"
			return
		}
		var meta ObjectMeta
		if listed != nil {
			meta = *listed
		} else {
			got, err := c.Get(ctx, o)
			switch {
			case IsNotFound(err):
				res.Gone = append(res.Gone, o)
				return
			case err != nil:
				res.Failed[o] = err
				return
			}
			meta = got
		}
		if why := s.disowns(meta); why != "" {
			res.Refused[o] = why
			if o == sa {
				res.Failed[o] = fmt.Errorf("not deleted: %s — so the tokens minted for the share's ServiceAccount "+
					"stay valid until they expire", why)
			}
			return
		}
		if err := c.DeleteExact(ctx, o, meta); err != nil {
			if IsConflict(err) {
				err = fmt.Errorf("it changed after it was checked, so it was not deleted: %w", err)
			}
			res.Failed[o] = err
			return
		}
		res.Removed = append(res.Removed, o)
	}

	objs := append(s.ExpectedObjects(), s.Objects...)
	sort.SliceStable(objs, func(i, j int) bool { return removalOrder(objs[i]) < removalOrder(objs[j]) })
	for _, o := range objs {
		consider(o, nil)
	}

	// The sweep: anything else with the share's label, in the namespaces the
	// share names — checked exactly as the listed objects are. A listing the
	// credential may not make is not a failure — the objects above were
	// already handled — but it is reported, so a "removed everything" is never
	// claimed on a sweep that did not run.
	if ValidShareID(s.ID) {
		for _, ns := range shareNamespaces(s) {
			for _, kind := range []string{"ServiceAccount", "RoleBinding", "Role"} {
				found, err := c.ListLabelled(ctx, kind, ns, s.ID)
				if err != nil {
					res.Failed[Object{Kind: kind + " list", Namespace: ns, Name: LabelShare + "=" + s.ID}] = err
					continue
				}
				for i := range found {
					consider(found[i].Object, &found[i].Meta)
				}
			}
		}
		if s.ClusterWide {
			found, err := c.ListLabelled(ctx, "ClusterRoleBinding", "", s.ID)
			if err != nil {
				res.Failed[Object{Kind: "ClusterRoleBinding list", Name: LabelShare + "=" + s.ID}] = err
			}
			for i := range found {
				consider(found[i].Object, &found[i].Meta)
			}
		}
	}
	return res
}

// shareNamespaces are the namespaces a share names that can name one: the
// ServiceAccount's, then the shared ones, each once.
func shareNamespaces(s Share) []string {
	var out []string
	seen := map[string]bool{}
	for _, ns := range append([]string{s.Namespace}, s.Namespaces...) {
		if ValidNamespace(ns) && !seen[ns] {
			seen[ns] = true
			out = append(out, ns)
		}
	}
	return out
}

// removalOrder puts the ServiceAccount first, then what grants it something.
func removalOrder(o Object) int {
	switch o.Kind {
	case "ServiceAccount":
		return 0
	case "ClusterRoleBinding":
		return 1
	case "RoleBinding":
		return 2
	}
	return 3
}

// Remaining checks, after a removal, that nothing the share created is left
// in the namespaces it names — nothing carrying its label and its owner — and
// returns what is. An object carrying the label for another owner is not the
// share's to remove, and Remove reported it as refused.
func Remaining(ctx context.Context, c *Client, s Share) ([]Object, error) {
	if !ValidShareID(s.ID) {
		return nil, fmt.Errorf("the share has no valid id to look its objects up by")
	}
	var left []Object
	var errs []error
	keep := func(found []Labelled) {
		for _, f := range found {
			if s.disowns(f.Meta) == "" {
				left = append(left, f.Object)
			}
		}
	}
	for _, ns := range shareNamespaces(s) {
		for _, kind := range []string{"ServiceAccount", "RoleBinding", "Role"} {
			found, err := c.ListLabelled(ctx, kind, ns, s.ID)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			keep(found)
		}
	}
	if s.ClusterWide {
		found, err := c.ListLabelled(ctx, "ClusterRoleBinding", "", s.ID)
		if err != nil {
			errs = append(errs, err)
		}
		keep(found)
	}
	return left, errors.Join(errs...)
}

// VerifyServiceAccount checks with the cluster that the share's
// ServiceAccount is one the share created: named as a share names it, and
// read back carrying the share's label and an owner annotation naming its
// owner (Task 20420). Renew mints a token for it with the developer's own
// credentials, so this is what stops a share's metadata pointing that at
// somebody else's ServiceAccount — kube-system's, say — and the hub then
// holding a token for it.
func VerifyServiceAccount(ctx context.Context, c *Client, s Share) error {
	if !ValidNamespace(s.Namespace) || !IsShareServiceAccount(s.ServiceAccount, s.ID) {
		return fmt.Errorf("the share names ServiceAccount %q in namespace %q, which is not one a share with id "+
			"%q creates (cloop-<name>-%s)", s.ServiceAccount, s.Namespace, s.ID, s.ID)
	}
	o := Object{Kind: "ServiceAccount", Namespace: s.Namespace, Name: s.ServiceAccount}
	meta, err := c.Get(ctx, o)
	if err != nil {
		return fmt.Errorf("read %s: %w", o, err)
	}
	if why := s.disowns(meta); why != "" {
		return fmt.Errorf("refusing to mint a token for %s: %s", o, why)
	}
	return nil
}

func joinObjects(objs []Object) string {
	parts := make([]string, 0, len(objs))
	for _, o := range objs {
		parts = append(parts, o.String())
	}
	return strings.Join(parts, ", ")
}

// deleteCommand is the kubectl invocation that removes objs.
func deleteCommand(objs []Object) string {
	var parts []string
	for _, o := range objs {
		kind := strings.ToLower(o.Kind)
		if o.Namespace == "" {
			parts = append(parts, kind+"/"+o.Name)
			continue
		}
		parts = append(parts, "-n "+o.Namespace+" "+kind+"/"+o.Name)
	}
	return strings.Join(parts, " ; kubectl delete ")
}

// DeleteCommand is the kubectl invocation that removes whatever carries the
// share's label in namespace ns. For the share's own terminal, cleaning up
// after a share it failed to finish; a revoke advises FindCommand instead,
// since anything labelled with the id would match.
func DeleteCommand(shareID, ns string) string {
	if ns == "" {
		return "kubectl delete clusterrolebinding -l " + LabelShare + "=" + shareID
	}
	return "kubectl delete serviceaccount,rolebinding,role -n " + ns + " -l " + LabelShare + "=" + shareID
}

// FindCommand is the kubectl invocation that lists whatever carries the
// share's label in namespace ns, with the owner annotation to check each
// against before deleting it.
func FindCommand(shareID, ns string) string {
	cols := " -o custom-columns=KIND:.kind,NAMESPACE:.metadata.namespace,NAME:.metadata.name," +
		"OWNER:.metadata.annotations.cloop\\.dev/owner"
	if ns == "" {
		return "kubectl get clusterrolebindings -l " + LabelShare + "=" + shareID + cols
	}
	return "kubectl get serviceaccounts,rolebindings,roles -n " + ns + " -l " + LabelShare + "=" + shareID + cols
}

// DeleteCommandFor is the kubectl invocation that removes exactly objs.
func DeleteCommandFor(objs []Object) string {
	if len(objs) == 0 {
		return ""
	}
	return "kubectl delete " + deleteCommand(objs)
}

// Expiry describes a token's expiry relative to now, for a person.
func Expiry(expires, now time.Time) string {
	if expires.IsZero() {
		return "unknown"
	}
	d := expires.Sub(now)
	at := expires.UTC().Format("2006-01-02 15:04 UTC")
	if d <= 0 {
		return "expired " + at
	}
	return fmt.Sprintf("%s (in %s)", at, roundDuration(d))
}

// roundDuration renders a duration to the minute, or the second under one.
func roundDuration(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	d = d.Round(time.Minute)
	h, m := d/time.Hour, (d%time.Hour)/time.Minute
	switch {
	case h >= 48:
		return fmt.Sprintf("%dd%dh", h/24, h%24)
	case h > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}
