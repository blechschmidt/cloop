package kubeshare

// renew.go keeps a share's token current, on the hub (Task 20416).
//
// Two ways, one result — the stored kubeconfig with a new token in it and
// nothing else changed:
//
//   - Renew is the hub's own renewal of a share made for it: the token the
//     secret holds authenticates a TokenRequest for its own ServiceAccount,
//     which the share's self-renewal Role permits and nothing else does. It
//     must happen before that token expires — an expired token cannot
//     authenticate the request for its successor — which is why the hub renews
//     at half-life (Share.Due) and a share whose token lapsed can only be
//     revived from its owner's terminal.
//   - Adopt takes a token the owner minted with their own credentials (`cloop
//     remote kube renew`) and checks it, with the cluster, before it replaces
//     anything: it must authenticate, as the share's own ServiceAccount, at
//     the server the share names.
//
// Neither runs a credential plugin or reads a file: the stored kubeconfig is
// parsed by pkg/executor/kubernetes.ParseKubeconfig, the hub's own parser, so a
// share can only ever hold what that parser accepts.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
)

// Errors a renewal distinguishes.
var (
	// ErrLapsed is a token that expired before it was renewed. Nothing the
	// hub holds can authenticate a renewal any more; only the share's owner,
	// with their own credentials, can mint the next token.
	ErrLapsed = errors.New("the share's token expired before it was renewed")
	// ErrUnrenewable is a stored kubeconfig a share could not have written:
	// it parses to no single ServiceAccount token.
	ErrUnrenewable = errors.New("the stored kubeconfig is not a renewable share")
	// ErrWrongToken is a pushed token that is not the share's ServiceAccount's.
	ErrWrongToken = errors.New("the token is not for the share's ServiceAccount")
	// ErrWrongServer is a pushed token minted at another API server than the
	// share's kubeconfig names, or through another CA — or one whose origin
	// nobody named (Task 20420). The hub never sends a token anywhere but the
	// server that minted it.
	ErrWrongServer = errors.New("the token was not minted by the share's API server")
)

// Origin is where a token pushed to the hub was minted: the API server the
// terminal's context reached and the CA it trusted there.
type Origin struct {
	Server        string
	CAFingerprint string
}

// Lapsed reports whether err means the hub can never renew the share again on
// its own: the token expired, or the cluster no longer accepts it — the
// ServiceAccount was deleted, or the token revoked with it.
func Lapsed(err error) bool { return errors.Is(err, ErrLapsed) || IsUnauthorized(err) }

// Renewed is a share's kubeconfig with a new token in it.
type Renewed struct {
	Kubeconfig []byte
	// Claims are the new token's; Previous the replaced one's.
	Claims   Claims
	Previous Claims
	// Verified reports that the cluster itself confirmed who the new token
	// is (Adopt on a cluster that answers SelfSubjectReview).
	Verified bool
}

// Inspect parses a stored share kubeconfig and returns its REST config and its
// token's claims.
func Inspect(kubeconfig []byte) (*kubernetes.RESTConfig, Claims, error) {
	rc, err := kubernetes.ParseKubeconfig(kubeconfig, "")
	if err != nil {
		return nil, Claims{}, fmt.Errorf("%w: %v", ErrUnrenewable, err)
	}
	if rc.BearerToken == "" {
		return nil, Claims{}, fmt.Errorf("%w: its user has no bearer token", ErrUnrenewable)
	}
	c, err := ParseClaims(rc.BearerToken)
	if err != nil {
		return nil, Claims{}, fmt.Errorf("%w: %v", ErrUnrenewable, err)
	}
	return rc, c, nil
}

// Renew mints the next token for the share's ServiceAccount, authenticated by
// the token the share holds, for the lifetime that token was issued with.
func Renew(ctx context.Context, kubeconfig []byte, now time.Time) (*Renewed, error) {
	rc, old, err := Inspect(kubeconfig)
	if err != nil {
		return nil, err
	}
	if !now.Before(old.ExpiresAt) {
		return nil, fmt.Errorf("%w (it expired at %s)", ErrLapsed, old.ExpiresAt.Format(time.RFC3339))
	}
	ttl := old.Lifetime()
	switch {
	case ttl < MinTTL:
		ttl = MinTTL
	case ttl > MaxTTL:
		ttl = MaxTTL
	}
	c, err := NewClient(rc)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	tok, err := c.RequestToken(ctx, old.Namespace, old.ServiceAccount, ttl)
	if err != nil {
		return nil, explainRenewal(err, old)
	}
	fresh, err := ParseClaims(tok.Value)
	if err != nil {
		return nil, fmt.Errorf("the TokenRequest answered with a token cloop cannot read: %w", err)
	}
	if fresh.Namespace != old.Namespace || fresh.ServiceAccount != old.ServiceAccount {
		return nil, fmt.Errorf("%w: the cluster minted one for %s while renewing %s", ErrWrongToken,
			fresh.Subject(), old.Subject())
	}
	doc, err := ReplaceToken(kubeconfig, tok.Value)
	if err != nil {
		return nil, err
	}
	return &Renewed{Kubeconfig: doc, Claims: fresh, Previous: old}, nil
}

// explainRenewal turns the API server's refusal into the sentence its owner
// needs.
func explainRenewal(err error, old Claims) error {
	switch {
	case IsUnauthorized(err):
		return fmt.Errorf("the cluster no longer accepts the share's token — its ServiceAccount %s/%s was "+
			"deleted, or the token revoked — so the hub cannot renew it: %w", old.Namespace, old.ServiceAccount, err)
	case IsForbidden(err):
		return fmt.Errorf("the ServiceAccount %s/%s may not create its own token: its self-renewal Role or "+
			"RoleBinding (%s-renew) is missing or was changed: %w", old.Namespace, old.ServiceAccount,
			old.ServiceAccount, err)
	case IsNotFound(err):
		return fmt.Errorf("the cluster has no ServiceAccount %s/%s any more: %w", old.Namespace, old.ServiceAccount, err)
	}
	return fmt.Errorf("renew the token of %s/%s: %w", old.Namespace, old.ServiceAccount, err)
}

// Adopt checks a token the share's owner minted and returns the stored
// kubeconfig carrying it. The token must have been minted at the API server
// the stored kubeconfig names, through the CA it trusts (origin), be a bounded
// token for the share's own ServiceAccount, still valid, and — where the
// cluster can say — authenticated by the cluster the share names as that
// ServiceAccount.
//
// The origin check comes first because the confirmation sends the token to
// the stored server. That server is the share's uploader's to name, and the
// token was minted with somebody else's credentials, so a token is never sent
// to a server other than the one that minted it (Task 20420).
func Adopt(ctx context.Context, kubeconfig []byte, token string, origin Origin, now time.Time) (*Renewed, error) {
	rc, old, err := Inspect(kubeconfig)
	if err != nil {
		return nil, err
	}
	switch {
	case strings.TrimSpace(origin.Server) == "" || strings.TrimSpace(origin.CAFingerprint) == "":
		return nil, fmt.Errorf("%w: the request does not say which API server minted the token, so the hub will "+
			"not send it to %s to check it — upgrade cloop on the machine that minted it", ErrWrongServer, rc.Server)
	case normalizeServer(origin.Server) != normalizeServer(rc.Server):
		return nil, fmt.Errorf("%w: it was minted at %s, and the share's kubeconfig names %s; the hub sends a "+
			"token only to the server that minted it", ErrWrongServer, origin.Server, rc.Server)
	case strings.TrimSpace(origin.CAFingerprint) != CAFingerprint(rc.CAData):
		return nil, fmt.Errorf("%w: it was minted through a CA other than the one the share's kubeconfig trusts "+
			"for %s", ErrWrongServer, rc.Server)
	}
	token = strings.TrimSpace(token)
	fresh, err := ParseClaims(token)
	if err != nil {
		return nil, err
	}
	if fresh.Namespace != old.Namespace || fresh.ServiceAccount != old.ServiceAccount {
		return nil, fmt.Errorf("%w: it is %s's, and the share is %s's", ErrWrongToken, fresh.Subject(), old.Subject())
	}
	if !now.Before(fresh.ExpiresAt) {
		return nil, fmt.Errorf("the token expired at %s", fresh.ExpiresAt.Format(time.RFC3339))
	}
	if fresh.Lifetime() > MaxTTL+time.Minute {
		return nil, fmt.Errorf("the token lives %s; a share holds tokens for at most %s",
			fresh.Lifetime().Round(time.Minute), shortDuration(MaxTTL))
	}
	// Ask the cluster. A token whose claims say the right thing could still be
	// one the cluster never issued; the hub is about to hand it to sandboxes.
	probe := *rc
	probe.BearerToken = token
	c, err := NewClient(&probe)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	who, ok, err := c.WhoAmI(ctx)
	if err != nil {
		if IsUnauthorized(err) {
			return nil, fmt.Errorf("the cluster at %s does not accept the token", rc.Server)
		}
		return nil, fmt.Errorf("check the token with the cluster at %s: %w", rc.Server, err)
	}
	if ok && who != fresh.Subject() {
		return nil, fmt.Errorf("%w: the cluster authenticates it as %s", ErrWrongToken, who)
	}
	doc, err := ReplaceToken(kubeconfig, token)
	if err != nil {
		return nil, err
	}
	return &Renewed{Kubeconfig: doc, Claims: fresh, Previous: old, Verified: ok}, nil
}
