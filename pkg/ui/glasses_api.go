package ui

// Per-user display-glasses link (Task 20194).
//
// # The constraint that shapes this
//
// Meta Ray-Ban Display glasses add a web app by URL and nothing else. There is
// no keyboard to type a password into, no browser chrome to complete an OIDC
// redirect in, and no place to paste a bearer token. Whatever authenticates
// the wearer has to already be inside the URL they saved.
//
// A credential in a URL is a credential in browser history, in the phone app
// that stored it, and in the access log of every proxy in front of the hub. So
// the design question is not "can we avoid it" — the device leaves no other
// option — but "what is the smallest thing that URL may be able to do".
//
// # What the link can do
//
// Five properties, each enforced somewhere that is not this file:
//
//   - A fixed role, never the generating user's, so what the URL can do does
//     not depend on who was signed in when it was made. A link minted
//     read-only carries `viewer` and nothing else — every gate in routes.go
//     asking for run.start, task.mutate, config.write or secret.grant refuses
//     it — and links issued before dictation existed are all of that kind.
//
//     The default carries `operator`, so a wearer with no keyboard can still
//     add a task by speaking it (Task 20238). `operator` also names run.start,
//     and the only thing that makes that acceptable is the next property: the
//     token is pinned to /api/glasses/, where the sole task.mutate routes are
//     transcribe and task-create and no run route exists. The *reachable*
//     grant is therefore exactly "viewer, plus add a task" — which is why
//     TestGlassesSurface_GrantsNoMoreThanTaskMutate fails the build if a
//     stronger route ever appears under that prefix.
//
//   - Confined to this surface. `viewer` is not a small permission: it carries
//     project.read, and project.read is what GET /api/provider-calls/{id}
//     declares — an endpoint returning an agent call's prompt and response
//     verbatim, which routinely contains whatever the agent was handed.
//     tokenKindAdmitted pins a glasses token to /glasses and /api/glasses/,
//     because no role in the ladder expresses "may read task titles but not
//     agent transcripts".
//
//   - Never more than its owner. The token is minted with an owner binding
//     (apitoken.Owner), and grant.decide intersects its role ceiling with the
//     owner's authority re-resolved from the *current policy* on every request
//     (authz.Intersect). Editing a role mapping narrows every link that user
//     holds, immediately. The claims themselves are the mint-time snapshot,
//     though — an IdP dropping someone from a group is not noticed until the
//     link expires, so offboarding means revoking, not just unbinding. That is
//     what `cloop hub user offboard` does (Task 20261): a glasses link is one
//     of the surfaces it severs, counted and audited separately from a PAT
//     because "their link still works" is its own incident.
//
//   - Only their projects. visibleProjectEntries filters through
//     recipientIdentity, which resolves an owner-bound token to its owner — so
//     the link's ?project_idx namespace is the owner's, exactly as their
//     dashboard's is.
//
//   - One per user, expiring. Minting rotates: every live link the user holds
//     is revoked in the same call, so "regenerate" is also "revoke what I
//     handed out", and a link the wearer forgot about cannot outlive the one
//     they are using.
//
// # What it deliberately does not do
//
// It does not mint. A caller authenticating *with* a token cannot use it to
// create another — otherwise revoking a leaked link would be pointless, since
// the leak could have already issued its own successor with a fresh expiry.
//
// # Why these endpoints instead of /api/tasks
//
// The wearable renders four fields per task on a display the size of a stamp,
// over a phone's link. /api/tasks answers with the whole pm.Task — description,
// result, annotations, diagnosis — which on this project's own plan is
// megabytes for a screen that shows a dozen titles. These endpoints project
// each record down to what the glasses draw, so the payload is bounded by the
// page size rather than by how much the agent has written.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

const (
	// glassesTokenName is the label the link's token carries in the tokens
	// panel, so an operator auditing credentials can tell at a glance what a
	// row is without decoding its kind.
	glassesTokenName = "Display glasses link"

	// glassesTTLDays is how long a freshly generated link lasts.
	//
	// Thirty days is a compromise between the two failure modes. Shorter, and
	// a wearer re-pairs their glasses often enough to start looking for a way
	// to turn expiry off. Longer, and a URL sitting in a phone's app list
	// outlives the job the person had when they saved it. Regenerating is one
	// button, and it revokes the old link in the same step.
	glassesTTLDays = 30

	// glassesPageSize is how many tasks one screen of the wearable requests.
	glassesPageSize = 25

	// glassesMaxPageSize bounds the client-supplied limit. The point is the
	// payload ceiling, not the page: an unbounded limit would put the whole
	// plan back on the wire and undo the reason these endpoints exist.
	glassesMaxPageSize = 100

	// glassesTextCap truncates the free text on the task detail screen. The
	// glasses show a few dozen words at a time; a task result on this project
	// runs to kilobytes, none of which would ever be scrolled to.
	glassesTextCap = 1200

	// glassesQuickCap is how many ready-made tasks the Add screen offers, and
	// glassesQuickRepairs how many of those may name a specific failure
	// (Task 20243). Both are small because the wearer reaches a row by swiping
	// to it: a list long enough to need scrolling is a list nobody reaches the
	// end of.
	glassesQuickCap     = 5
	glassesQuickRepairs = 2

	// glassesQuickTitleCap bounds a ready-made title. It becomes a real task
	// title, and one of them interpolates a failed task's own title, which on
	// this project's plan runs to a paragraph.
	glassesQuickTitleCap = 160
)

// ---------------------------------------------------------------------------
// the link
// ---------------------------------------------------------------------------

// glassesLinkView describes the caller's current link without revealing it.
// The URL is returned exactly once, by the mint call; afterwards only these
// facts survive, because the secret half is not stored anywhere.
type glassesLinkView struct {
	Exists    bool   `json:"exists"`
	Prefix    string `json:"prefix,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	LastUsed  string `json:"last_used_at,omitempty"`
	Owner     string `json:"owner,omitempty"`

	// PerUser reports whether this hub can tell one user's link from
	// another's. False on a single-tenant hub (OIDC off), where there is one
	// operator and therefore one link; the panel says so rather than implying
	// an isolation the deployment does not have.
	PerUser bool `json:"per_user"`

	// CanAddTasks reports whether this link may dictate tasks (Task 20238).
	// Read off the stored token, so a link minted before dictation existed
	// keeps reading as read-only until its holder regenerates it.
	CanAddTasks bool `json:"can_add_tasks"`
}

// glassesLinkResponse is the mint result. URL is the whole point and exists
// only here.
type glassesLinkResponse struct {
	Link    glassesLinkView `json:"link"`
	URL     string          `json:"url"`
	Warning string          `json:"warning"`
}

// handleGlassesLinkGet serves GET /api/glasses/link.
func (s *Server) handleGlassesLinkGet(w http.ResponseWriter, r *http.Request) {
	if !s.glassesSelfService(w, r) {
		return
	}
	tok, err := s.currentGlassesToken(r)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	jsonOK(w, map[string]any{"link": s.glassesLinkView(r, tok)})
}

// handleGlassesLinkCreate serves POST /api/glasses/link: mint a fresh link and
// revoke the one it replaces.
//
// Rotation rather than accumulation is the whole lifecycle. A user who taps
// "regenerate" is usually doing it because the old URL went somewhere it
// should not have, and a call that left the old one live would answer the
// wrong question.
func (s *Server) handleGlassesLinkCreate(w http.ResponseWriter, r *http.Request) {
	if !s.glassesSelfService(w, r) {
		return
	}
	mgr, ok := s.tokenManagerOr(w)
	if !ok {
		return
	}

	// An absent or empty body means "the default link", so the panel's
	// Generate button needs no payload and every existing caller keeps
	// working. Only an explicit read_only:true narrows it.
	var opts struct {
		ReadOnly bool `json:"read_only"`
	}
	if r.Body != nil {
		limitJSONBody(w, r, maxJSONBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&opts); err != nil && !errors.Is(err, io.EOF) {
			respondToBodyError(w, err)
			return
		}
	}
	readOnly := opts.ReadOnly

	owner := ownerFromIdentity(s.sessionIdentity(r))
	if s.oidcEnabled() && owner == nil {
		// OIDC is on and the caller has no session: they reached this with the
		// static bearer token, i.e. as the deployment itself. Minting an
		// unbound link there would produce a credential that reads every
		// tenant's projects — the one thing this endpoint exists not to do.
		apierror.WriteError(w, apierror.New(apierror.CodeForbidden,
			"a display-glasses link is issued to a signed-in user; sign in to generate one"))
		return
	}

	// Serialize rotation. Two Generate taps — a second tab, or the phone and
	// the dashboard at once — would otherwise both read "no previous link",
	// both mint, and leave a second live 30-day credential that no later call
	// can find: the lookup returns the newest match, so Revoke would only ever
	// withdraw the one the panel is showing.
	s.glassesMu.Lock()
	defer s.glassesMu.Unlock()

	// Revoke first, and revoke *every* live link this user holds rather than
	// the newest one. If the mint below fails the user is left with no link
	// and a clear error, which is recoverable; the other order can leave two
	// live links and no record of which one the caller believes they hold.
	previous, err := s.liveGlassesTokens(r)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	actor := s.glassesActor(r, ownerFromIdentity(s.sessionIdentity(r)))
	for _, prev := range previous {
		if rerr := mgr.Revoke(prev.ID); rerr != nil && !errors.Is(rerr, apitoken.ErrNotFound) {
			apierror.WriteError(w, apierror.New(apierror.CodeInternal, rerr.Error()))
			return
		}
		s.auditTokenEvent(tokenAuditRecord{
			Actor:     actor,
			EventType: auditaction.ActionAPITokenRevoked,
			TokenID:   prev.Prefix,
			Extra:     map[string]any{"name": prev.Name, "reason": "glasses_link_rotated"},
		})
	}

	minted, err := mgr.Mint(apitoken.MintOptions{
		Name: glassesTokenName,
		// A fixed role, not the caller's own. A link that acted with an
		// operator's authority because an operator generated it would make
		// "what can this URL do" depend on who was signed in, which is not a
		// property anyone can reason about after the fact. The owner binding
		// narrows this further; nothing widens it.
		//
		// Which fixed role is the wearer's choice, and read-only is still what
		// most links should be (Task 20238). The default carries `operator`
		// because dictating a task is the one thing a wearer can actually do
		// on a device with no keyboard — but `operator` also names run.start,
		// the permission that spends money, so it is only safe here because of
		// the second layer:
		//
		//   tokenKindAdmitted pins a glasses token to /glasses and
		//   /api/glasses/, and the only task.mutate routes under that prefix
		//   are transcribe and task-create. There is no run endpoint there, so
		//   the *reachable* grant is exactly "viewer, plus add a task".
		//
		// That makes the path pin load-bearing rather than defence in depth,
		// which is why TestGlassesSurface_GrantsNoMoreThanTaskMutate asserts
		// it: adding a stronger route under /api/glasses/ would retroactively
		// widen every link already sitting in someone's phone.
		Roles:     []string{string(glassesRole(readOnly))},
		CreatedBy: actor,
		ExpiresAt: time.Now().Add(glassesTTLDays * 24 * time.Hour),
		Kind:      apitoken.KindGlasses,
		Owner:     owner,
	})
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
		return
	}

	s.auditTokenEvent(tokenAuditRecord{
		Actor:     actor,
		EventType: auditaction.ActionAPITokenCreated,
		TokenID:   minted.Token.Prefix,
		Extra: map[string]any{
			"name":       minted.Token.Name,
			"kind":       apitoken.KindGlasses,
			"roles":      minted.Token.Roles,
			"owner":      owner.Key(),
			"expires_at": formatTokenTime(minted.Token.ExpiresAt),
		},
	})

	link := s.glassesURL(r, minted.Plaintext)
	reach := "read your projects and tasks"
	if !readOnly {
		reach = "read your projects and tasks, and add new ones by dictation"
	}
	warning := "This URL is the credential. It is shown once and cannot be recovered — " +
		"cloop stores only a hash. Anyone who has it can " + reach + " " +
		"until it expires, so add it to your glasses and do not paste it anywhere else. " +
		"Generating a new link revokes this one."
	// Say so when the link just handed out is a plaintext one. Reaching the hub
	// over http is legitimate (loopback, a LAN, a proxy terminating TLS
	// elsewhere), so this is not a refusal — but a credential travelling in a
	// query string over an unencrypted hop is worth one sentence at the moment
	// the user is deciding where to put it, rather than a discovery later.
	if strings.HasPrefix(link, "http://") && !linkHostIsLoopback(link) {
		warning += " Note: this is an http link, so the credential in it crosses the network " +
			"unencrypted. Set ui.external_url to your https address, or terminate TLS in " +
			"front of the hub, before pairing a device off this machine."
	}

	jsonOK(w, glassesLinkResponse{
		Link:    s.glassesLinkView(r, &minted.Token),
		URL:     link,
		Warning: warning,
	})
}

// glassesRole maps the wearer's choice onto a role.
//
// Two values, not a spectrum. The role ladder is cumulative — there is no
// "viewer plus task.mutate" tier to name — so the grant is expressed as
// operator-confined-by-path rather than as a bespoke permission set, and the
// confinement is what the test named above holds in place.
func glassesRole(readOnly bool) authz.Role {
	if readOnly {
		return authz.RoleViewer
	}
	return authz.RoleOperator
}

// glassesCanAddTasks reports whether a link may dictate tasks, read off the
// token rather than recomputed — a link minted before this existed carries
// viewer and must keep reading as read-only.
func glassesCanAddTasks(tok *apitoken.Token) bool {
	if tok == nil {
		return false
	}
	for _, role := range tok.Roles {
		if authz.Role(role) == authz.RoleOperator {
			return true
		}
	}
	return false
}

// linkHostIsLoopback reports whether a generated link points at this machine,
// where plaintext carries no network exposure and a warning would be noise.
func linkHostIsLoopback(link string) bool {
	u, err := url.Parse(link)
	if err != nil {
		return false
	}
	return tlsconf.IsLoopbackHost(u.Hostname())
}

// handleGlassesLinkRevoke serves DELETE /api/glasses/link.
func (s *Server) handleGlassesLinkRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.glassesSelfService(w, r) {
		return
	}
	// Same lock as rotation: revoking while a mint is in flight would
	// otherwise report success against a link the mint is about to replace.
	s.glassesMu.Lock()
	defer s.glassesMu.Unlock()

	live, err := s.liveGlassesTokens(r)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	if len(live) == 0 {
		jsonOK(w, map[string]any{"ok": true, "revoked": false})
		return
	}
	mgr, ok := s.tokenManagerOr(w)
	if !ok {
		return
	}
	actor := s.glassesActor(r, ownerFromIdentity(s.sessionIdentity(r)))
	for _, tok := range live {
		if err := mgr.Revoke(tok.ID); err != nil && !errors.Is(err, apitoken.ErrNotFound) {
			apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
			return
		}
		s.auditTokenEvent(tokenAuditRecord{
			Actor:     actor,
			EventType: auditaction.ActionAPITokenRevoked,
			TokenID:   tok.Prefix,
			Extra:     map[string]any{"name": tok.Name, "reason": "glasses_link_revoked"},
		})
	}
	jsonOK(w, map[string]any{"ok": true, "revoked": true})
}

// glassesSelfService rejects a caller that must not manage links.
//
// The three link routes are PermPublic — they are scoped to the caller's own
// identity by construction and take no parameter naming anyone else, the same
// reasoning that leaves POST /api/session/logout-all ungated. That makes this
// function the only guard on them, and it enforces one rule: a token may not
// mint, inspect, or revoke a link.
//
// Without it a leaked glasses URL could issue itself a successor with a fresh
// 30-day expiry before anyone noticed, which would make revocation advisory.
// The same rule keeps a CI PAT from quietly acquiring a second credential
// shaped like a person's.
func (s *Server) glassesSelfService(w http.ResponseWriter, r *http.Request) bool {
	if tokenFromRequest(r) == nil {
		return true
	}
	apierror.WriteError(w, apierror.New(apierror.CodeForbidden,
		"a display-glasses link can only be managed from a signed-in browser session, "+
			"not with an API token"))
	return false
}

// currentGlassesToken returns the caller's newest live link, or nil. It is
// what the panel reports; rotation and revocation act on liveGlassesTokens.
func (s *Server) currentGlassesToken(r *http.Request) (*apitoken.Token, error) {
	live, err := s.liveGlassesTokens(r)
	if err != nil || len(live) == 0 {
		return nil, err
	}
	return live[0], nil
}

// liveGlassesTokens returns every link the caller currently holds, newest
// first.
//
// Plural, not singular. "One live link per user" is an invariant this code
// maintains rather than one the store enforces, and the way it breaks is
// mundane: a second browser tab, a retried request, or an owner key that moved
// (see ownerMatches). A rotation that revoked only the newest match would
// leave the others live for their full term and invisible to every route here
// — a credential nobody can see is a credential nobody revokes. Revoking all
// of them makes the invariant self-healing instead of assumed.
//
// "Live" means not revoked and not expired: an expired row still exists (the
// trail keeps it) but must read as no link at all, or the panel would offer to
// revoke something that already stopped working.
func (s *Server) liveGlassesTokens(r *http.Request) ([]*apitoken.Token, error) {
	mgr, err := s.tokenManager()
	if err != nil {
		return nil, err
	}
	tokens, err := mgr.List()
	if err != nil {
		return nil, err
	}
	want := ownerFromIdentity(s.sessionIdentity(r))
	multiTenant := s.oidcEnabled()
	now := time.Now()

	var out []*apitoken.Token
	for i := range tokens {
		tok := &tokens[i]
		if tok.Kind != apitoken.KindGlasses || !tok.Active(now) {
			continue
		}
		// On a multi-tenant hub an owner-less row belongs to nobody — it was
		// minted before sign-on was configured, and tokenKindAdmitted already
		// refuses to honour it. Claiming it here would let whoever opens the
		// panel first adopt, display, and revoke a credential that is not
		// theirs.
		if multiTenant && tok.Owner == nil {
			continue
		}
		// A row whose binding did not decode is listed so it stays revocable
		// by an operator, but it is nobody's link: claiming it here would let
		// whoever opens the panel first adopt a credential that may not be
		// theirs.
		if tok.OwnerUnreadable {
			continue
		}
		if !ownerMatches(tok.Owner, want) {
			continue
		}
		out = append(out, tok)
	}
	return out, nil
}

// ownerMatches reports whether a stored owner binding is the same person as
// the caller.
//
// The issuer subject decides when both sides have one. Owner.Key is email-first
// because that is what project ownership is recorded under, and an email is
// exactly the claim an IdP rewrites during a domain migration — matching on it
// alone would make a user's own link invisible to them the morning their
// address changed, at which point Generate mints a second live credential
// instead of rotating the first. `sub` is the claim an IdP promises not to
// reuse, so it is the one to trust when it is there.
//
// Both nil is a match: on a hub with no sign-on there is one operator, whose
// links are the unowned ones.
func ownerMatches(stored, want *apitoken.Owner) bool {
	if stored == nil || want == nil {
		return stored == nil && want == nil
	}
	if stored.Sub != "" && want.Sub != "" {
		return stored.Sub == want.Sub
	}
	key := stored.Key()
	return key != "" && key == want.Key()
}

// glassesActor is the name written to the audit trail and to the token's
// created_by.
//
// grant.subjectLabel() is not enough on its own: on a hub with sign-on but no
// role mappings configured — a combination pkg/ui/authz.go explicitly supports
// — every signed-in user resolves to the bypass label "local", so two people's
// links would both be attributed to nobody in particular. The owner binding
// names the actual person whenever there is one.
func (s *Server) glassesActor(r *http.Request, owner *apitoken.Owner) string {
	if label := owner.Key(); label != "" {
		return label
	}
	return s.grantFor(r).subjectLabel()
}

// ownerFromIdentity builds the binding stored on a link's token. A nil
// identity — OIDC disabled — yields no binding: there is no second user to be
// narrowed relative to.
func ownerFromIdentity(id *oidcauth.Identity) *apitoken.Owner {
	if id == nil {
		return nil
	}
	return &apitoken.Owner{
		Sub:    id.Sub,
		Email:  id.Email,
		Name:   id.Name,
		Groups: id.Groups,
		Roles:  id.Roles,
	}
}

func (s *Server) glassesLinkView(r *http.Request, tok *apitoken.Token) glassesLinkView {
	v := glassesLinkView{PerUser: s.oidcEnabled()}
	if tok == nil {
		return v
	}
	v.Exists = true
	v.Prefix = tok.Prefix
	v.CreatedAt = formatTokenTime(tok.CreatedAt)
	v.ExpiresAt = formatTokenTime(tok.ExpiresAt)
	v.LastUsed = formatTokenTime(tok.LastUsedAt)
	v.Owner = tok.Owner.Label()
	v.CanAddTasks = glassesCanAddTasks(tok)
	return v
}

// glassesURL renders the link the wearer saves.
//
// The base is ui.external_url when configured, because that is the only thing
// that knows what this deployment is called from outside — a hub behind a
// reverse proxy sees a Host header that may be an internal name, and a URL
// built from it would resolve to nothing on a phone. The request is the
// fallback for a hub reached directly.
func (s *Server) glassesURL(r *http.Request, plaintext string) string {
	base := strings.TrimRight(strings.TrimSpace(s.ExternalURL), "/")
	if base == "" {
		scheme := "http"
		if s.requestIsTLS(r) {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}
	return base + "/glasses?token=" + url.QueryEscape(plaintext)
}

// ---------------------------------------------------------------------------
// the wearable's data
// ---------------------------------------------------------------------------

// glassesProject is one row of the project list: the six facts the first
// screen draws and nothing else.
type glassesProject struct {
	Idx     int    `json:"idx"`
	Name    string `json:"name"`
	Goal    string `json:"goal,omitempty"`
	Status  string `json:"status,omitempty"`
	Running bool   `json:"running"`
	Done    int    `json:"done"`
	Total   int    `json:"total"`
	Failed  int    `json:"failed"`
}

// handleGlassesProjects serves GET /api/glasses/projects.
//
// Indices are positions in the caller's *visible* list, which is the same
// namespace resolveWorkDir maps ?project_idx through — so a link cannot reach
// a project by index that it could not see in this response.
func (s *Server) handleGlassesProjects(w http.ResponseWriter, r *http.Request) {
	s.refreshProjectStatuses()
	entries, statuses := s.cachedProjectView()
	statuses, _ = s.filterStatusesForRecipient(s.recipientIdentity(r), tokenFromRequest(r), entries, statuses)

	// The index must be the position in visibleProjectEntries, not in the
	// status list: the two are built from the same registry but the status
	// list can omit a project whose state failed to load, which would shift
	// every index after it onto the wrong project.
	visible := s.visibleProjectEntries(r)
	idxByPath := make(map[string]int, len(visible))
	for i, e := range visible {
		idxByPath[e.Path] = i
	}

	out := make([]glassesProject, 0, len(statuses))
	for _, st := range statuses {
		// A project the wearer hid from their dashboard stays hidden on the
		// glasses. The display fits a handful of rows, so honouring the
		// decluttering matters more here than anywhere else.
		if st.Hidden {
			continue
		}
		idx, ok := idxByPath[st.Path]
		if !ok {
			continue
		}
		out = append(out, glassesProject{
			Idx:     idx,
			Name:    st.Name,
			Goal:    truncateForGlasses(st.Goal, 160),
			Status:  st.Status,
			Running: st.Running,
			Done:    st.DoneTasks,
			Total:   st.TotalTasks,
			Failed:  st.FailedTasks,
		})
	}
	// Running projects first — that is what the wearer glanced up to check —
	// then by name so the list does not reshuffle between refreshes.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Running != out[j].Running {
			return out[i].Running
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	// Dictation availability rides along on the first screen's response rather
	// than costing a second request (Task 20238). This page is loaded over a
	// phone tether, and its own header says the budget is one round trip.
	jsonOK(w, map[string]any{
		"projects":  out,
		"dictation": s.dictationStatusFor(r),
	})
}

// ---------------------------------------------------------------------------
// ready-made tasks
// ---------------------------------------------------------------------------

// glassesQuickTask is one row of the Add screen: a task the wearer can create
// with a single pinch (Task 20243).
//
// # Why the wearable needs these at all
//
// A task is a sentence, and the glasses cannot take one. Meta's build guide
// lists microphone, camera and text input as unsupported for Ray-Ban Display
// web apps; what the runtime delivers is arrow keys and Enter, synthesised from
// band and captouch gestures. Dictation (Task 20238) therefore only works when
// the same link is opened on the paired phone — which left the wearer with no
// way to add anything at all while actually wearing the device, and no button
// to press either, since the dictate control hides itself where it cannot work.
//
// So the composition method has to be one the hardware can express: choosing
// from a list. These are the list.
//
// # Why they are built here and not in the page
//
// Two of them name a real failure by id and title, which only the plan knows.
// Keeping the whole set server-side means the page has one code path rather
// than one for the contextual rows and another for the fixed ones, and means
// the wording can improve without re-pairing anyone's glasses.
//
// # Why no AI call
//
// Asking a provider to brainstorm titles is the obvious richer answer, and it
// is deliberately not what this does. On a hub configured for the claudecode
// provider a provider call spawns the `claude` binary on the control-plane
// host, and "an HTTP handler must not cause a program to run on the host" is
// the load-bearing guarantee of the executor design (tests/security
// TestNoHandlerReachesProcessExecution). A glasses link is a credential that
// lives in a URL in a phone's app list; it is the last credential that should
// be able to start a process here. These rows cost nothing and cannot.
type glassesQuickTask struct {
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}

// glassesStandingTasks are the ready-made rows that do not depend on the plan.
//
// Each is a real instruction rather than a category, because the wearer never
// gets to elaborate: whatever is here is the entire brief the agent will act
// on. They are also all work that is worth doing on any project at any time,
// which is what makes a fixed list honest rather than filler.
var glassesStandingTasks = []glassesQuickTask{
	{
		Title: "Review the recent changes and fix any bugs found",
		Description: "Go over the work committed most recently. Look for correctness bugs, " +
			"unhandled errors, race conditions and resource leaks, fix what you find, and add a " +
			"regression test for each fix. Verify with a build and the full test suite.",
	},
	{
		Title: "Add tests for the code that changed most recently",
		Description: "Identify the packages touched by the most recent commits, find the paths " +
			"that have no coverage, and add tests for them — including the failure paths, not " +
			"just the happy one. Run the full suite and make sure it passes.",
	},
	{
		Title: "Update the documentation to match the current behaviour",
		Description: "Check the README and the docs tree against what the code actually does " +
			"now. Correct anything stale, document anything recently added that is missing, and " +
			"remove anything describing a feature that no longer exists.",
	},
}

// glassesQuickTasks builds the Add screen's list: repairs for the newest
// failures first, then the standing set, capped.
//
// allowed is the caller's own task.mutate standing. A read-only link gets an
// empty list rather than rows it would be refused for pinching — the page
// hides the whole screen in that case, and this makes that a property of the
// response rather than of the client agreeing to behave.
func glassesQuickTasks(plan *pm.Plan, allowed bool) []glassesQuickTask {
	out := make([]glassesQuickTask, 0, glassesQuickCap)
	if !allowed {
		return out
	}

	if plan != nil {
		var failed []*pm.Task
		for _, t := range plan.Tasks {
			switch taskStatusOrPending(t) {
			case string(pm.TaskFailed), string(pm.TaskTimedOut):
				failed = append(failed, t)
			}
		}
		// Newest first: a failure from ten minutes ago is the one the wearer
		// glanced up to look at, and one from last month has had its chance.
		sort.SliceStable(failed, func(i, j int) bool { return failed[i].ID > failed[j].ID })
		for _, t := range failed {
			if len(out) >= glassesQuickRepairs {
				break
			}
			out = append(out, glassesRepairTask(t))
		}
	}

	for _, q := range glassesStandingTasks {
		if len(out) >= glassesQuickCap {
			break
		}
		out = append(out, q)
	}
	return out
}

// glassesRepairTask turns one failed task into a pinch-to-add repair job.
//
// The description tells the agent to diagnose before retrying, because the
// wearer cannot add that themselves and a bare "fix task 63" invites exactly
// the blind re-run that produced the failure the first time.
func glassesRepairTask(t *pm.Task) glassesQuickTask {
	title := truncateForGlasses(t.Title, 100)
	return glassesQuickTask{
		Title: truncateForGlasses(
			fmt.Sprintf("Fix the failure in task #%d: %s", t.ID, title), glassesQuickTitleCap),
		Description: fmt.Sprintf("Task #%d (%q) ended as %s. Read its recorded result, work out "+
			"why it actually failed rather than retrying it blindly, fix the underlying cause, and "+
			"verify with a build and the test suite.", t.ID, title, taskStatusOrPending(t)),
	}
}

// glassesTask is one row of the task list.
type glassesTask struct {
	ID       int    `json:"id"`
	Title    string `json:"title"`
	Status   string `json:"status"`
	Priority int    `json:"priority,omitempty"`
}

// handleGlassesTasks serves GET /api/glasses/tasks?project_idx=N.
//
// Paged, because a plan runs to hundreds of tasks and the display shows a
// handful. The counts are computed over the whole plan rather than the page,
// so the header the wearer reads ("12 of 213") does not change meaning as they
// scroll.
func (s *Server) handleGlassesTasks(w http.ResponseWriter, r *http.Request) {
	dictation := s.dictationStatusFor(r)

	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil || ps.Plan == nil {
		// Still answer with the capability block and the standing rows: a
		// project whose plan has not been created yet is exactly one where
		// adding a task is the useful thing to do, and a screen that offered
		// nothing there would read as broken rather than empty.
		jsonOK(w, map[string]any{
			"tasks": []glassesTask{}, "total": 0, "offset": 0,
			"limit": glassesPageSize, "counts": map[string]int{},
			"dictation": dictation,
			"quick":     glassesQuickTasks(nil, dictation.CanAddTasks),
		})
		return
	}

	statusFilter := map[string]bool{}
	for _, sv := range parseCSVList(r.URL.Query().Get("status"), maxCSVItems, maxCSVItemLen) {
		statusFilter[sv] = true
	}

	counts := map[string]int{}
	matched := make([]*pm.Task, 0, len(ps.Plan.Tasks))
	for _, t := range ps.Plan.Tasks {
		st := taskStatusOrPending(t)
		counts[st]++
		if len(statusFilter) > 0 && !statusFilter[st] {
			continue
		}
		matched = append(matched, t)
	}

	// Running first, then pending by priority, then everything else newest
	// first — the same intent as the dashboard's ordering, which is what makes
	// the two agree about "the task I am looking for is near the top".
	sort.SliceStable(matched, func(i, j int) bool {
		a, b := matched[i], matched[j]
		ra, rb := taskStatusOrPending(a) == string(pm.TaskInProgress), taskStatusOrPending(b) == string(pm.TaskInProgress)
		if ra != rb {
			return ra
		}
		pa, pb := taskStatusOrPending(a) == string(pm.TaskPending), taskStatusOrPending(b) == string(pm.TaskPending)
		if pa != pb {
			return pa
		}
		if pa && a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if pa {
			return a.ID < b.ID
		}
		return a.ID > b.ID
	})

	offset, limit := glassesPaging(r)
	if offset > len(matched) {
		offset = len(matched)
	}
	end := offset + limit
	if end > len(matched) {
		end = len(matched)
	}
	page := make([]glassesTask, 0, end-offset)
	for _, t := range matched[offset:end] {
		page = append(page, glassesTask{
			ID:       t.ID,
			Title:    truncateForGlasses(t.Title, 200),
			Status:   taskStatusOrPending(t),
			Priority: t.Priority,
		})
	}

	jsonOK(w, map[string]any{
		"project": s.projectNameForPath(s.resolveWorkDir(r)),
		"goal":    truncateForGlasses(ps.Goal, 200),
		"tasks":   page,
		"total":   len(matched),
		"offset":  offset,
		"limit":   limit,
		"counts":  counts,
		// Repeated here, and this is the authoritative copy (Task 20238). The
		// project list carries it too so the first screen costs one request,
		// but that response has no ?project_idx and so resolves task.mutate
		// against the default project. A user whose operator binding is scoped
		// to one project would be told the wrong thing there; this route is
		// the one that knows which project the wearer actually opened.
		"dictation": dictation,
		// The Add screen's rows (Task 20243), on this response rather than a
		// route of their own: the wearable's budget is one request per screen,
		// and two of these are derived from the same plan already loaded here.
		"quick": glassesQuickTasks(ps.Plan, dictation.CanAddTasks),
	})
}

// handleGlassesTaskDetail serves GET /api/glasses/tasks/{id}.
//
// It reads from the plan only. The artifact and live-output files the
// dashboard's detail modal opens are unbounded agent transcripts; putting one
// on a wearable's link to render on a stamp-sized display would spend the
// wearer's bandwidth on text they cannot scroll to.
func (s *Server) handleGlassesTaskDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(strings.TrimSpace(r.PathValue("id")))
	if err != nil || id <= 0 {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "a positive task id is required"))
		return
	}
	ps, lerr := state.Load(s.resolveWorkDir(r))
	if lerr != nil || ps.Plan == nil {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "no such task"))
		return
	}
	for _, t := range ps.Plan.Tasks {
		if t.ID != id {
			continue
		}
		out := map[string]any{
			"id":          t.ID,
			"title":       truncateForGlasses(t.Title, 200),
			"status":      taskStatusOrPending(t),
			"priority":    t.Priority,
			"description": truncateForGlasses(t.Description, glassesTextCap),
			"result":      truncateForGlasses(t.Result, glassesTextCap),
			// Where it ran (Task 20244). Sent as one pre-rendered line plus a
			// boolean rather than three raw fields: the glasses view builds
			// text nodes, has no room for a chip row, and every formatting
			// decision it makes has to be made on a device that cannot be
			// debugged. on_host is what drives the warning styling there.
			"executor": glassesExecutorLine(t),
			"on_host":  taskRanOnHost(t),
		}
		if t.StartedAt != nil {
			out["started_at"] = t.StartedAt.UTC().Format(time.RFC3339)
		}
		if t.CompletedAt != nil {
			out["completed_at"] = t.CompletedAt.UTC().Format(time.RFC3339)
		}
		jsonOK(w, out)
		return
	}
	apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "no such task"))
}

// glassesExecutorLine renders a task's placement as one short line for the
// glasses detail pane (Task 20244).
//
// Empty when the task carries no attribution, which makes the block hide
// itself rather than display a reassuring blank. The host case is prefixed
// with a warning marker because the display has no colour vocabulary an
// operator can rely on at a glance and the text has to carry the signal
// on its own.
func glassesExecutorLine(t *pm.Task) string {
	if t == nil || (t.ExecutorID == "" && t.ExecutorKind == "") {
		return ""
	}
	where := t.ExecutorID
	if where == "" {
		where = t.ExecutorKind
	}
	iso := t.Isolation
	if iso == "" {
		iso = "unknown"
	}
	if taskRanOnHost(t) {
		return truncateForGlasses("⚠ HOST — "+where+" (no sandbox)", 120)
	}
	return truncateForGlasses(where+" — "+iso, 120)
}

// handleGlassesPage serves the wearable's HTML shell at /glasses.
//
// A separate document from the dashboard, not a mode of it: the dashboard
// bundle is hundreds of kilobytes of panels the glasses cannot render and a
// wearer cannot operate, and shipping it over a phone tether to draw a list of
// titles would be the whole page-load budget spent before the first paint.
func (s *Server) handleGlassesPage(w http.ResponseWriter, r *http.Request) {
	writeAsset(w, r, loadAssets().glasses)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func glassesPaging(r *http.Request) (offset, limit int) {
	limit = glassesPageSize
	if v, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit"))); err == nil && v > 0 {
		limit = v
	}
	if limit > glassesMaxPageSize {
		limit = glassesMaxPageSize
	}
	if v, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("offset"))); err == nil && v > 0 {
		offset = v
	}
	return offset, limit
}

// taskStatusOrPending normalizes the empty status, which older plans use for a
// task nobody has picked up yet.
func taskStatusOrPending(t *pm.Task) string {
	if t == nil || t.Status == "" {
		return string(pm.TaskPending)
	}
	return string(t.Status)
}

// truncateForGlasses caps a string at n runes — runes, not bytes, so a cut
// never lands mid-character and hands the display a replacement glyph.
func truncateForGlasses(s string, n int) string {
	s = strings.TrimSpace(s)
	if n <= 0 || len(s) <= n {
		return s
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return strings.TrimRight(string(runes[:n]), " \t\n") + "…"
}
