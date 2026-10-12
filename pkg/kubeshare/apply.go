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
	// Removed are the objects deleted, or found gone already.
	Removed []Object
	// Failed are the ones that could not be, with why.
	Failed map[Object]error
}

// Clean reports that nothing was left behind.
func (r Removal) Clean() bool { return len(r.Failed) == 0 }

// Remove deletes a share's objects: every one its metadata lists, and anything
// else carrying its label in the namespaces it names.
//
// The ServiceAccount goes first. Deleting it invalidates every token ever
// minted for it at once — the hub's, and any copy a workload kept — so the
// credential is dead before the first binding is touched, and a revoke that
// fails halfway leaves bindings to nothing rather than a live token.
func Remove(ctx context.Context, c *Client, s Share) Removal {
	res := Removal{Failed: map[Object]error{}}
	done := map[Object]bool{}
	del := func(o Object) {
		if done[o] {
			return
		}
		done[o] = true
		if err := c.Delete(ctx, o); err != nil {
			res.Failed[o] = err
			return
		}
		res.Removed = append(res.Removed, o)
	}

	objs := append([]Object(nil), s.Objects...)
	if s.ServiceAccount != "" && s.Namespace != "" {
		objs = append(objs, Object{Kind: "ServiceAccount", Namespace: s.Namespace, Name: s.ServiceAccount})
	}
	sort.SliceStable(objs, func(i, j int) bool { return removalOrder(objs[i]) < removalOrder(objs[j]) })
	for _, o := range objs {
		del(o)
	}

	// The sweep: anything else with the share's label, in the namespaces the
	// share names. A listing the credential may not make is not a failure —
	// the listed objects were already handled — but it is reported, so a
	// "removed everything" is never claimed on a sweep that did not run.
	if s.ID != "" {
		namespaces := append([]string{s.Namespace}, s.Namespaces...)
		seen := map[string]bool{}
		for _, ns := range namespaces {
			if ns == "" || seen[ns] {
				continue
			}
			seen[ns] = true
			for _, kind := range []string{"ServiceAccount", "RoleBinding", "Role"} {
				found, err := c.ListLabelled(ctx, kind, ns, s.ID)
				if err != nil {
					res.Failed[Object{Kind: kind + " list", Namespace: ns, Name: LabelShare + "=" + s.ID}] = err
					continue
				}
				for _, o := range found {
					del(o)
				}
			}
		}
		if s.ClusterWide {
			found, err := c.ListLabelled(ctx, "ClusterRoleBinding", "", s.ID)
			if err != nil {
				res.Failed[Object{Kind: "ClusterRoleBinding list", Name: LabelShare + "=" + s.ID}] = err
			}
			for _, o := range found {
				del(o)
			}
		}
	}
	return res
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

// Remaining checks, after a removal, that nothing with the share's label is
// left in the namespaces it names, and returns what is.
func Remaining(ctx context.Context, c *Client, s Share) ([]Object, error) {
	var left []Object
	var errs []error
	namespaces := append([]string{s.Namespace}, s.Namespaces...)
	seen := map[string]bool{}
	for _, ns := range namespaces {
		if ns == "" || seen[ns] {
			continue
		}
		seen[ns] = true
		for _, kind := range []string{"ServiceAccount", "RoleBinding", "Role"} {
			found, err := c.ListLabelled(ctx, kind, ns, s.ID)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			left = append(left, found...)
		}
	}
	if s.ClusterWide {
		found, err := c.ListLabelled(ctx, "ClusterRoleBinding", "", s.ID)
		if err != nil {
			errs = append(errs, err)
		}
		left = append(left, found...)
	}
	return left, errors.Join(errs...)
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
// share's label in namespace ns.
func DeleteCommand(shareID, ns string) string {
	if ns == "" {
		return "kubectl delete clusterrolebinding -l " + LabelShare + "=" + shareID
	}
	return "kubectl delete serviceaccount,rolebinding,role -n " + ns + " -l " + LabelShare + "=" + shareID
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
