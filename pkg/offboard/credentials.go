// What a departed identity keeps on the hub rather than holds open (Task 20400).
//
// The surfaces in offboard.go are things a person can *use*: a session, a
// token, a membership, a running task. Ending them answers "can they still act
// here?". It does not answer "is anything of theirs still here?", and three
// stores added after Task 20261 kept the answer at yes:
//
//   - personal broker secrets (migration 0039): their GitHub PATs, the
//     git-proxy-guarded ones included, and their kubeconfigs, sealed and
//     indefinitely kept, with every grant over them still live — so a shared
//     project a colleague runs kept spending a departed person's credential;
//   - self-service grant requests they filed (migration 0037), still open, so
//     an approver could mint a grant for somebody the hub no longer admits;
//   - their Claude Code login home (claudecodeauth.HomeFor): an OAuth refresh
//     token in plaintext, plus the CLI's session transcripts and project
//     history, under each hub member's config directory — and a login they had
//     in flight, parked in that member's memory.
//
// claudecodeauth.ForgetHome even said it was "the deprovisioning path", and
// nothing called it.
//
// # Destroyed, unless held
//
// The default destroys: secrets are deleted through the broker — the sealed
// columns scrubbed before the row goes, the deletion audited, a tombstone left
// so a project that loses the credential is told what it was — and the Claude
// home is logged out, so the session is revoked at Anthropic and not only on
// this disk, and then removed. A legal hold (Options.KeepCredentials) keeps the
// secrets and the home exactly as they are and says so in the plan and in the
// trail. It severs everything else regardless: the grants are revoked, the
// requests withdrawn and a login in flight cancelled, because a hold preserves
// evidence and is not a reason to keep spending a departed person's credential.

package offboard

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ---------------------------------------------------------------------------
// Plan types
// ---------------------------------------------------------------------------

// PersonalSecretRef is one secret the identity owns personally.
type PersonalSecretRef struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Owner     string    `json:"owner,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

// PersonalGrantRef is one live grant over a personal secret of the identity.
//
// Listed with its subject because a grant to a project somebody else owns is
// how a colleague's work loses the credential, and an operator approving the
// run should see that before it happens rather than hear about it afterwards.
type PersonalGrantRef struct {
	ID         string    `json:"id"`
	SecretID   string    `json:"secret_id"`
	SecretName string    `json:"secret_name,omitempty"`
	Subject    string    `json:"subject"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
}

// GrantRequestRef is one self-service grant request the identity filed that is
// still waiting for a decision.
type GrantRequestRef struct {
	ID          string    `json:"id"`
	RequestedBy string    `json:"requested_by"`
	SecretName  string    `json:"secret_name,omitempty"`
	Kind        string    `json:"kind,omitempty"`
	Subject     string    `json:"subject"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
}

// ClaudeHomeRef is one copy of a Claude Code login the hub keeps for the
// identity: the private CLAUDE_CONFIG_DIR one hub process resolves for one
// spelling of it.
//
// One identity can have several. Each spelling of the person — their email, and
// "sub:<subject>" from a time the IdP withheld it — keys its own directory, and
// each hub process resolves the directory under its own config root, so a
// cluster whose members run under different users or container filesystems
// keeps one copy per member.
type ClaudeHomeRef struct {
	// Member names the hub process keeping this copy: a cluster member id, or
	// "" for the process running the offboarding.
	Member string `json:"member,omitempty"`
	// OwnerKey is the spelling of the identity the directory is keyed by.
	OwnerKey string `json:"owner_key"`
	// Dir is the directory on that member's filesystem.
	Dir string `json:"dir"`
	// Exists, Credential and Login are what was found there: the directory,
	// a non-empty credential file in it, and a `claude auth login` in flight
	// for this spelling on that member.
	Exists     bool `json:"exists"`
	Credential bool `json:"credential"`
	Login      bool `json:"login,omitempty"`
}

// ClaudeHomeResult is what the run did to one copy.
type ClaudeHomeResult struct {
	ClaudeHomeRef
	// LoginCancelled reports that a login in flight was killed.
	LoginCancelled bool `json:"login_cancelled,omitempty"`
	// LoggedOut reports that `claude auth logout` ran and succeeded, which
	// revokes the session at Anthropic and not only on this disk.
	LoggedOut bool `json:"logged_out,omitempty"`
	// Logout says why logout did not run, or how it failed. Best-effort: the
	// directory is removed either way.
	Logout string `json:"logout,omitempty"`
	// Removed reports that the directory is gone.
	Removed bool `json:"removed,omitempty"`
	// Kept reports that a legal hold left the directory in place.
	Kept bool `json:"kept,omitempty"`
	// Error is what failed when the copy could not be removed.
	Error string `json:"error,omitempty"`
}

// ClaudeUnreached is a hub process whose copies the run could not reach: a
// member that did not answer, or one that stopped and left its tree behind.
// A copy nobody reached may still hold a live refresh token, so it is reported
// rather than assumed absent.
type ClaudeUnreached struct {
	Member string `json:"member"`
	Detail string `json:"detail"`
}

// Credentials is the identity's stored footprint: what the run destroys, or
// under a legal hold keeps.
type Credentials struct {
	Secrets  []PersonalSecretRef `json:"secrets"`
	Grants   []PersonalGrantRef  `json:"grants"`
	Requests []GrantRequestRef   `json:"requests"`
	// Claude lists every copy of a Claude login found for the identity,
	// on every hub process the run could reach.
	Claude []ClaudeHomeRef `json:"claude"`
	// ClaudeUnreached lists the hub processes the run could not ask.
	ClaudeUnreached []ClaudeUnreached `json:"claude_unreached,omitempty"`

	// Keep reports a legal hold: the secrets and the Claude homes listed
	// above are kept, everything else is severed.
	Keep bool `json:"keep"`

	// SecretsError, RequestsError and ClaudeError say why a part of this
	// footprint could not be read. A run with one set reports it as a
	// failure: what could not be listed could not be destroyed.
	SecretsError  string `json:"secrets_error,omitempty"`
	RequestsError string `json:"requests_error,omitempty"`
	ClaudeError   string `json:"claude_error,omitempty"`
}

// Empty reports whether there is nothing stored to destroy or keep.
func (c Credentials) Empty() bool {
	return len(c.Secrets) == 0 && len(c.Grants) == 0 && len(c.Requests) == 0 &&
		len(c.Claude) == 0 && len(c.ClaudeUnreached) == 0
}

// ClaudeCopies counts the copies that hold anything: a directory, or a login
// in flight.
func (c Credentials) ClaudeCopies() int {
	n := 0
	for _, h := range c.Claude {
		if h.Exists || h.Login {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Collaborators
// ---------------------------------------------------------------------------

// Secrets is the secret-store surface: the identity's personal secrets, the
// grants spending them, and the requests it filed. A run with none skips these
// and the plan says they were not checked.
type Secrets interface {
	// Owned reports the personal secrets owned by any of these owner keys,
	// and every live grant over them.
	Owned(ownerKeys []string) ([]PersonalSecretRef, []PersonalGrantRef, error)
	// Pending reports the requests still awaiting a decision that were filed
	// by any of these identities.
	Pending(requesters []string) ([]GrantRequestRef, error)
	// RevokeGrant revokes one grant.
	RevokeGrant(id, actor, reason string) error
	// DeleteSecret destroys one secret: its sealed material, and every grant
	// still pointing at it.
	DeleteSecret(id, actor, reason string) error
	// WithdrawRequest withdraws one pending request on behalf of its departed
	// requester, reporting false when it had already been decided.
	WithdrawRequest(id, actor, reason string) (bool, error)
}

// ClaudeHomes is the Claude Code login surface. A run with none skips it and
// the plan says logins were not checked.
type ClaudeHomes interface {
	// Inspect finds every copy of these owner keys' logins it can reach, and
	// names the hub processes it could not.
	Inspect(ownerKeys []string) ([]ClaudeHomeRef, []ClaudeUnreached, error)
	// Sever cancels the logins in flight and, unless keep is set, logs each
	// copy out and removes it.
	Sever(ownerKeys []string, keep bool, actor, reason string) ([]ClaudeHomeResult, []ClaudeUnreached, error)
}

// ---------------------------------------------------------------------------
// The secret broker
// ---------------------------------------------------------------------------

// brokerCallTimeout bounds one broker call. Deleting a GitHub App secret
// destroys the tokens minted from it at GitHub, which is a network round trip.
const brokerCallTimeout = 30 * time.Second

// BrokerSecrets adapts a secret broker.
//
// It reads with the broker's unscoped listings — offboarding is one of the
// callers ListSecrets stays unscoped for — and writes only through the broker,
// so every revocation, deletion and withdrawal is audited by the code that
// audits them everywhere else, and a deleted secret leaves the tombstone a
// later refusal names it from.
func BrokerSecrets(b *secretbroker.Broker) Secrets { return brokerSecrets{b: b} }

type brokerSecrets struct{ b *secretbroker.Broker }

func (s brokerSecrets) Owned(ownerKeys []string) ([]PersonalSecretRef, []PersonalGrantRef, error) {
	want := map[string]bool{}
	for _, k := range ownerKeys {
		if n := secretbroker.NormalizeOwner(k); n != "" {
			want[n] = true
		}
	}
	if len(want) == 0 {
		return nil, nil, nil
	}
	all, err := s.b.ListSecrets()
	if err != nil {
		return nil, nil, fmt.Errorf("list secrets: %w", err)
	}
	var secrets []PersonalSecretRef
	byID := map[string]PersonalSecretRef{}
	for _, sec := range all {
		if !sec.Personal() || !want[secretbroker.NormalizeOwner(sec.Owner)] {
			continue
		}
		ref := PersonalSecretRef{
			ID: sec.ID, Name: sec.Name, Kind: string(sec.Kind),
			Owner: sec.Owner, CreatedAt: sec.CreatedAt,
		}
		secrets = append(secrets, ref)
		byID[sec.ID] = ref
	}

	grants, err := s.b.ListGrants(secretbroker.GrantFilter{ActiveOnly: true})
	if err != nil {
		return secrets, nil, fmt.Errorf("list grants: %w", err)
	}
	var out []PersonalGrantRef
	for _, g := range grants {
		sec, overMine := byID[g.SecretID]
		// The owner on the grant row as well as the secret it points at: a
		// live grant whose personal secret is already gone still names whose
		// credential it spent, and still has to be revoked.
		if !overMine && !(g.Personal() && want[secretbroker.NormalizeOwner(g.Owner)]) {
			continue
		}
		out = append(out, PersonalGrantRef{
			ID: g.ID, SecretID: g.SecretID, SecretName: sec.Name,
			Subject: g.Subject.String(), ExpiresAt: g.ExpiresAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return secrets, out, nil
}

func (s brokerSecrets) Pending(requesters []string) ([]GrantRequestRef, error) {
	want := map[string]bool{}
	for _, r := range requesters {
		if r = strings.ToLower(strings.TrimSpace(r)); r != "" {
			want[r] = true
		}
	}
	if len(want) == 0 {
		return nil, nil
	}
	reqs, err := s.b.ListRequests(secretbroker.RequestFilter{PendingOnly: true})
	if err != nil {
		return nil, fmt.Errorf("list grant requests: %w", err)
	}
	var out []GrantRequestRef
	for _, r := range reqs {
		if !want[strings.ToLower(strings.TrimSpace(r.RequestedBy))] {
			continue
		}
		out = append(out, GrantRequestRef{
			ID: r.ID, RequestedBy: r.RequestedBy, SecretName: r.SecretName,
			Kind: string(r.Kind), Subject: r.Subject.String(), CreatedAt: r.CreatedAt,
		})
	}
	return out, nil
}

func (s brokerSecrets) RevokeGrant(id, actor, reason string) error {
	ctx, cancel := context.WithTimeout(context.Background(), brokerCallTimeout)
	defer cancel()
	// The cause rides on the grant, so the project's next lease can say the
	// grant went with its owner — under a legal hold too, where the secret
	// stays, and after one is lifted, when the secret goes days later.
	return s.b.RevokeWithCause(ctx, id, actor, secretbroker.RevokedOwnerOffboarded, reason)
}

func (s brokerSecrets) DeleteSecret(id, actor, reason string) error {
	ctx, cancel := context.WithTimeout(context.Background(), brokerCallTimeout)
	defer cancel()
	return s.b.DeleteSecretBecause(ctx, id, actor, secretbroker.CauseOffboarded, reason)
}

func (s brokerSecrets) WithdrawRequest(id, actor, reason string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), brokerCallTimeout)
	defer cancel()
	_, err := s.b.WithdrawRequestOnOffboard(ctx, id, actor, reason)
	if errors.Is(err, secretbroker.ErrRequestNotPending) {
		// Decided, or lapsed, between the plan and the run: nothing is left
		// open, which is the end state asked for.
		return false, nil
	}
	return err == nil, err
}

// StoreSecrets builds the secret surface over a control-plane database.
//
// The broker it builds holds no key (secretbroker.WithoutKey). Destroying a
// credential removes rows and never reads one, so an offboarding works from a
// shell that does not carry CLOOP_SECRET_KEY — the emergency the CLI exists
// for — and the hub uses the same construction, so both front ends sever the
// same rows the same way. Its audit rows go to the control plane, where every
// secret action is homed.
func StoreSecrets(db *statedb.DB) (Secrets, error) {
	if db == nil {
		return nil, fmt.Errorf("offboard: nil database")
	}
	store, err := secretstore.New(db)
	if err != nil {
		return nil, err
	}
	b, err := secretbroker.New(store,
		secretbroker.WithAuditor(secretstore.NewAuditor(db)),
		secretbroker.WithoutKey())
	if err != nil {
		return nil, fmt.Errorf("open the secret store: %w", err)
	}
	return BrokerSecrets(b), nil
}

// ---------------------------------------------------------------------------
// Claude Code logins, in one process
// ---------------------------------------------------------------------------

// defaultLogoutTimeout bounds `claude auth logout`. It contacts Anthropic to
// revoke the session; a hub that cannot reach it must not hold the offboarding.
const defaultLogoutTimeout = 10 * time.Second

// LocalClaude is the Claude login surface of one process: the homes under its
// own config directory, and the logins its Manager has in flight. A hub's
// cluster surface is one of these for itself plus every other member's answer;
// the CLI's is one of these for its own tree plus what members report over
// the bus.
type LocalClaude struct {
	// Manager holds this process's in-flight logins. Nil — a shell has none.
	Manager *claudecodeauth.Manager
	// Member labels the copies this process finds: its cluster member id, or
	// "" when it is the process running the offboarding.
	Member string
	// Root is where the homes are. Empty — production — is
	// claudecodeauth.HomeRootPath, from this process's own environment.
	// Set by tests that run two hub members in one process, where the
	// environment is shared and the trees must not be.
	Root string
	// OperatorShell marks the process as an operator's shell on the hub host —
	// `cloop hub user offboard` — rather than a hub acting on a request. The
	// host-execution policy governs what a hub runs on a request's behalf; a
	// person at a shell runs what they choose, and the logout revokes the
	// session at Anthropic, so a shell runs it whatever the policy — the same
	// on every host, rather than depending on which directory's config the
	// CLI happened to load. Never set by a hub.
	OperatorShell bool
	// OnLoginCancelled runs after a login in flight was killed, so a cluster
	// member can give up its claim on it.
	OnLoginCancelled func(ownerKey string)
	// Logout runs `claude auth logout` against one directory. Nil is
	// claudecodeauth.Logout; tests substitute it, because the real one talks
	// to Anthropic.
	Logout func(ctx context.Context, configDir string) error
	// LogoutTimeout bounds one logout. Zero is defaultLogoutTimeout.
	LogoutTimeout time.Duration
}

// claudeSpelling is one directory and the spellings of the identity that map
// to it — the slug lowercases, so "sub:X" and "sub:x" share one.
type claudeSpelling struct {
	dir  string
	keys []string
}

// spellings resolves each owner key to its directory, without creating any.
func (c LocalClaude) spellings(ownerKeys []string) ([]claudeSpelling, error) {
	var out []claudeSpelling
	index := map[string]int{}
	for _, k := range ownerKeys {
		if strings.TrimSpace(k) == "" {
			continue
		}
		var (
			dir string
			err error
		)
		if c.Root != "" {
			dir, err = claudecodeauth.HomePathIn(c.Root, k)
		} else {
			dir, err = claudecodeauth.HomePath(k)
		}
		if err != nil {
			return nil, fmt.Errorf("locate the Claude home of %s: %w", k, err)
		}
		if i, ok := index[dir]; ok {
			out[i].keys = append(out[i].keys, k)
			continue
		}
		index[dir] = len(out)
		out = append(out, claudeSpelling{dir: dir, keys: []string{k}})
	}
	return out, nil
}

// inspect reads one directory's state.
func (c LocalClaude) inspect(sp claudeSpelling) ClaudeHomeRef {
	ref := ClaudeHomeRef{Member: c.Member, OwnerKey: sp.keys[0], Dir: sp.dir}
	// Lstat, and anything at the path counts: a symlink planted where a home
	// belongs is still something the removal below has to take away.
	if _, err := os.Lstat(sp.dir); err == nil {
		ref.Exists = true
		ref.Credential = claudecodeauth.HasCredential(sp.dir)
	}
	if c.Manager != nil {
		for _, k := range sp.keys {
			if c.Manager.Snapshot(k).Active {
				ref.Login = true
			}
		}
	}
	return ref
}

// Inspect implements ClaudeHomes for this process.
func (c LocalClaude) Inspect(ownerKeys []string) ([]ClaudeHomeRef, []ClaudeUnreached, error) {
	sps, err := c.spellings(ownerKeys)
	if err != nil {
		return nil, nil, err
	}
	var out []ClaudeHomeRef
	for _, sp := range sps {
		if ref := c.inspect(sp); ref.Exists || ref.Login {
			out = append(out, ref)
		}
	}
	return out, nil, nil
}

// Sever implements ClaudeHomes for this process.
//
// The order is the one that leaves nothing to come back: the login in flight
// first, because a `claude auth login` that completes after the directory is
// gone would write a fresh credential into a new one; then logout, while the
// credential it revokes still exists; then the directory.
func (c LocalClaude) Sever(ownerKeys []string, keep bool, actor, reason string) ([]ClaudeHomeResult, []ClaudeUnreached, error) {
	sps, err := c.spellings(ownerKeys)
	if err != nil {
		return nil, nil, err
	}
	var out []ClaudeHomeResult
	for _, sp := range sps {
		res := ClaudeHomeResult{ClaudeHomeRef: c.inspect(sp)}
		if c.Manager != nil {
			for _, k := range sp.keys {
				if !c.Manager.Snapshot(k).Active {
					continue
				}
				c.Manager.Cancel(k)
				res.LoginCancelled = true
				if c.OnLoginCancelled != nil {
					c.OnLoginCancelled(k)
				}
			}
		}
		switch {
		case !res.Exists:
			// Nothing on disk. Reported only when a login was cancelled.
		case keep:
			res.Kept = true
		default:
			c.destroy(sp, &res)
		}
		if res.Exists || res.LoginCancelled {
			out = append(out, res)
		}
	}
	return out, nil, nil
}

// symlinked reports whether path is a symbolic link.
func symlinked(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}

// destroy logs one copy out, best-effort, and removes it.
func (c LocalClaude) destroy(sp claudeSpelling, res *ClaudeHomeResult) {
	if res.Credential {
		switch {
		case strings.TrimSpace(sp.dir) == "":
			// Unreachable — HomePath never returns an empty path — and
			// guarded anyway: logout with no directory signs the *host's*
			// credential out, which is every other tenant's on a hub without
			// per-user logins.
			res.Logout = "skipped: no directory to scope the logout to"
		case symlinked(sp.dir):
			// Not a directory this hub created. Logging out through it would
			// follow the link to whatever credential it points at — the
			// host's own, at worst — so it is removed without being followed.
			res.Logout = "skipped: the home is a symbolic link, which is removed without being followed"
		case !c.OperatorShell && !executor.HostExecutionAllowed():
			// Strict no-host-execution: this process runs no program on the
			// hub on anybody's behalf, and logout is one. Checked here, in the
			// step, rather than by whoever calls it, so every route to it —
			// the dashboard's offboarding, a peer's request, the bus — is
			// covered by one check (tests/security: gatedHostSteps).
			res.Logout = "skipped: executors.allow_host_process is false, so this hub runs no claude binary; " +
				"the credential is destroyed here but not revoked at Anthropic — revoke the session from the account"
		default:
			timeout := c.LogoutTimeout
			if timeout <= 0 {
				timeout = defaultLogoutTimeout
			}
			logout := c.Logout
			if logout == nil {
				logout = claudecodeauth.Logout
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			err := logout(ctx, sp.dir)
			cancel()
			if err != nil {
				res.Logout = "failed: " + secretbroker.RedactString(err.Error())
			} else {
				res.LoggedOut = true
			}
		}
	}
	var errs []string
	for _, k := range sp.keys {
		var forget error
		if c.Root != "" {
			forget = claudecodeauth.ForgetHomeIn(c.Root, k)
		} else {
			forget = claudecodeauth.ForgetHome(k)
		}
		if forget != nil {
			errs = append(errs, forget.Error())
		}
	}
	if _, err := os.Lstat(sp.dir); err == nil && len(errs) == 0 {
		errs = append(errs, "the directory is still present after removal")
	}
	if len(errs) > 0 {
		res.Error = strings.Join(errs, "; ")
		return
	}
	res.Removed = true
}

// ---------------------------------------------------------------------------
// The run step
// ---------------------------------------------------------------------------

// severStoredCredentials revokes the grants over the identity's personal
// secrets, destroys the secrets — or, under a legal hold, keeps them — and
// withdraws their pending requests, recording each part on the report and in
// the trail.
func severStoredCredentials(o Options, plan Plan, rep *Report) {
	creds := plan.Credentials
	fail := func(surface, format string, args ...any) {
		rep.Failures = append(rep.Failures, Failure{surface, fmt.Sprintf(format, args...)})
	}
	if creds.SecretsError != "" {
		fail("secret", "personal secrets could not be listed, so none were destroyed: %s", creds.SecretsError)
	}
	if creds.RequestsError != "" {
		fail("request", "pending grant requests could not be listed, so none were withdrawn: %s", creds.RequestsError)
	}
	if o.Secrets == nil {
		return
	}

	// Grants first, and under a hold too. A grant is not a credential but the
	// authority to spend one, and a legal hold preserves evidence; it is no
	// reason for a colleague's project to keep spending a departed person's
	// PAT. Revocation is a stamp, so the rows survive as evidence anyway, and
	// each carries the cause the project's next lease reads back.
	grantReason := "owner offboarded: " + o.Reason
	for _, g := range creds.Grants {
		if err := o.Secrets.RevokeGrant(g.ID, o.Actor, grantReason); err != nil {
			fail("grant", "revoke %s (%s to %s): %v", g.ID, g.SecretName, g.Subject, err)
			continue
		}
		rep.GrantsRevoked = append(rep.GrantsRevoked, g)
	}
	if o.KeepCredentials {
		rep.SecretsKept = append(rep.SecretsKept, creds.Secrets...)
	} else {
		for _, sec := range creds.Secrets {
			if err := o.Secrets.DeleteSecret(sec.ID, o.Actor, o.Reason); err != nil {
				fail("secret", "delete %s (%s): %v", sec.Name, sec.ID, err)
				continue
			}
			rep.SecretsDeleted = append(rep.SecretsDeleted, sec)
		}
		checkpointAfterDeletion(o, rep)
	}
	for _, rq := range creds.Requests {
		withdrawn, err := o.Secrets.WithdrawRequest(rq.ID, o.Actor, o.Reason)
		if err != nil {
			fail("request", "withdraw %s (%s for %s): %v", rq.ID, rq.SecretName, rq.Subject, err)
			continue
		}
		if withdrawn {
			rep.RequestsWithdrawn = append(rep.RequestsWithdrawn, rq)
		}
	}

	record := func(surface string, action auditaction.Action, payload map[string]any) {
		if err := auditSurface(o, plan, action, payload); err != nil {
			rep.Failures = append(rep.Failures, Failure{surface, err.Error()})
		}
	}
	if len(rep.GrantsRevoked) > 0 {
		grants := make([]string, 0, len(rep.GrantsRevoked))
		for _, g := range rep.GrantsRevoked {
			grants = append(grants, g.ID+" ("+g.SecretName+" to "+g.Subject+")")
		}
		record("grant", auditaction.ActionUserOffboardGrant, map[string]any{
			"count": len(rep.GrantsRevoked), "grants": grants,
		})
	}
	if len(rep.SecretsDeleted) > 0 {
		record("secret", auditaction.ActionUserOffboardSecret, map[string]any{
			"count": len(rep.SecretsDeleted), "secrets": secretLabels(rep.SecretsDeleted),
			"action": "destroyed",
		})
	}
	if len(rep.RequestsWithdrawn) > 0 {
		requests := make([]string, 0, len(rep.RequestsWithdrawn))
		for _, rq := range rep.RequestsWithdrawn {
			requests = append(requests, rq.ID+" ("+rq.SecretName+" for "+rq.Subject+")")
		}
		record("request", auditaction.ActionUserOffboardRequest, map[string]any{
			"count": len(rep.RequestsWithdrawn), "requests": requests,
		})
	}
}

// checkpointAfterDeletion folds the write-ahead log back into the database
// file once secrets were destroyed.
//
// The deletion overwrote the sealed bytes with zeroes, but in WAL mode those
// zeroed pages land in the log first: until a checkpoint copies them back, the
// database file itself still holds the old ones, and a copy of state.db taken
// without its -wal — a backup, a support bundle — would hold the ciphertext.
// So the run asks for the checkpoint at once rather than leaving it to the
// next automatic one. A reader can hold a checkpoint off; that is reported, not
// failed, since the material is already unreachable through the database.
func checkpointAfterDeletion(o Options, rep *Report) {
	if len(rep.SecretsDeleted) == 0 || o.DB == nil {
		return
	}
	summary, err := o.DB.WALCheckpointTruncate()
	switch {
	case err != nil:
		rep.Warnings = append(rep.Warnings, "the destroyed secrets' zeroed pages could not be checkpointed into "+
			"the database file yet: "+err.Error()+" — until a checkpoint runs, a copy of state.db made without its "+
			"-wal file still holds their old pages")
	case strings.HasPrefix(summary, "PARTIAL"):
		rep.Warnings = append(rep.Warnings, "a reader held the checkpoint off, so the destroyed secrets' zeroed "+
			"pages are only partly in the database file yet ("+summary+") — until the next checkpoint, a copy of "+
			"state.db made without its -wal file still holds their old pages")
	}
}

// severClaude ends the identity's Claude Code logins — cancelling one in
// flight, logging each home out and removing it, or under a legal hold keeping
// it — and records what became of every copy.
func severClaude(o Options, plan Plan, rep *Report) {
	if o.Claude == nil {
		return
	}
	// A failed inspection is not reported here: Sever looks again, and its own
	// error, if it fails the same way, is the one that says what survived.
	results, missed, err := o.Claude.Sever(plan.Target.OwnerKeys(), o.KeepCredentials, o.Actor, o.Reason)
	if err != nil {
		rep.Failures = append(rep.Failures, Failure{"claude", err.Error()})
	}
	rep.ClaudeResults = results
	for _, r := range results {
		if r.Error != "" {
			rep.Failures = append(rep.Failures, Failure{"claude",
				fmt.Sprintf("%s: %s", claudeCopyLabel(r.ClaudeHomeRef), r.Error)})
		}
	}
	for _, u := range missed {
		rep.Failures = append(rep.Failures, Failure{"claude", fmt.Sprintf(
			"hub member %s was not reached, so any copy it keeps is still there: %s", u.Member, u.Detail)})
	}
	if len(results) == 0 && len(missed) == 0 {
		return
	}

	var copies, kept []string
	cancelled, removed, loggedOut := 0, 0, 0
	for _, r := range results {
		state := "found"
		switch {
		case r.Removed:
			state, removed = "removed", removed+1
		case r.Kept:
			state = "kept"
			kept = append(kept, claudeCopyLabel(r.ClaudeHomeRef))
		case r.Error != "":
			state = "not removed: " + r.Error
		}
		if r.LoggedOut {
			loggedOut++
			state += ", logged out"
		} else if r.Logout != "" {
			state += ", logout " + r.Logout
		}
		if r.LoginCancelled {
			cancelled++
			state += ", login cancelled"
		}
		copies = append(copies, claudeCopyLabel(r.ClaudeHomeRef)+" ["+r.OwnerKey+"]: "+state)
	}
	unreached := make([]string, 0, len(missed))
	for _, u := range missed {
		unreached = append(unreached, u.Member+": "+u.Detail)
	}
	if err := auditSurface(o, plan, auditaction.ActionUserOffboardClaude, map[string]any{
		"copies": copies, "removed": removed, "logged_out": loggedOut,
		"logins_cancelled": cancelled, "unreached": unreached, "kept": kept,
	}); err != nil {
		rep.Failures = append(rep.Failures, Failure{"claude", err.Error()})
	}
}

// claudeCopyLabel names one copy for a failure line.
func claudeCopyLabel(h ClaudeHomeRef) string {
	if h.Member != "" {
		return "hub member " + h.Member + ": " + h.Dir
	}
	return h.Dir
}

// auditHold records an offboarding run under a legal hold, and what it kept.
//
// Its own row, written whether or not anything was found to keep: "was this
// person's offboarding run under a legal hold" is the question a reviewer asks,
// and the answer must not depend on whether they happened to have stored
// anything.
func auditHold(o Options, plan Plan, rep *Report) {
	if !o.KeepCredentials {
		return
	}
	var claude []string
	for _, r := range rep.ClaudeResults {
		if r.Kept {
			claude = append(claude, claudeCopyLabel(r.ClaudeHomeRef))
		}
	}
	if err := auditSurface(o, plan, auditaction.ActionUserOffboardHold, map[string]any{
		"secrets": secretLabels(rep.SecretsKept), "claude_homes": claude,
		"grants_revoked": len(rep.GrantsRevoked), "requests_withdrawn": len(rep.RequestsWithdrawn),
	}); err != nil {
		rep.Failures = append(rep.Failures, Failure{"hold", err.Error()})
	}
}

// secretLabels renders secrets for a payload: name, kind and id.
func secretLabels(in []PersonalSecretRef) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, s.Name+" ("+s.Kind+", "+s.ID+")")
	}
	return out
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

// planCredentials collects the identity's stored footprint. A collaborator the
// run lacks is a warning, as for leases and projects: "not checked" must not
// read as "nothing there". A collaborator that fails is recorded on the
// section, so the run reports it as a failure rather than as an empty list.
func planCredentials(o Options, t Target, tokens []apitoken.Token, warnings *[]string) Credentials {
	c := Credentials{
		Keep: o.KeepCredentials,
		// Non-nil, so a front end rendering "0 personal secrets" can tell
		// an empty finding from a field that was never filled.
		Secrets: []PersonalSecretRef{}, Grants: []PersonalGrantRef{},
		Requests: []GrantRequestRef{}, Claude: []ClaudeHomeRef{},
	}
	keys := t.OwnerKeys()

	if o.Secrets == nil {
		*warnings = append(*warnings, "personal secrets, the grants over them and pending grant requests "+
			"were not checked: no secret store available to this run")
	} else {
		secrets, grants, err := o.Secrets.Owned(keys)
		if err != nil {
			c.SecretsError = err.Error()
			*warnings = append(*warnings, "could not enumerate personal secrets: "+err.Error())
		}
		c.Secrets = append(c.Secrets, secrets...)
		c.Grants = append(c.Grants, grants...)

		reqs, err := o.Secrets.Pending(requesterSpellings(t, tokens))
		switch {
		case errors.Is(err, secretbroker.ErrRequestsUnsupported):
			// A store that keeps no requests has none to leave open.
		case err != nil:
			c.RequestsError = err.Error()
			*warnings = append(*warnings, "could not enumerate pending grant requests: "+err.Error())
		default:
			c.Requests = append(c.Requests, reqs...)
		}
	}

	if o.Claude == nil {
		*warnings = append(*warnings, "Claude Code logins were not checked: no Claude home surface available to this run")
	} else {
		homes, unreached, err := o.Claude.Inspect(keys)
		if err != nil {
			c.ClaudeError = err.Error()
			*warnings = append(*warnings, "could not inspect Claude Code logins: "+err.Error())
		}
		c.Claude = append(c.Claude, homes...)
		c.ClaudeUnreached = unreached
		for _, u := range unreached {
			*warnings = append(*warnings, fmt.Sprintf(
				"hub member %s could not be asked about Claude Code logins, and a copy it keeps would survive "+
					"this run: %s", u.Member, u.Detail))
		}
	}
	return c
}

// requesterSpellings are the strings a request filed by this person can carry
// in its requested_by: each owner key, and the label of each API token bound to
// them — a request filed through a person's own PAT is recorded under the
// token, and is theirs as much as one filed from their browser.
//
// Every token, revoked or not: revoking the token did not withdraw what was
// filed with it.
func requesterSpellings(t Target, tokens []apitoken.Token) []string {
	out := append([]string(nil), t.OwnerKeys()...)
	for i := range tokens {
		tok := &tokens[i]
		if t.matchesOwner(tok.Owner) {
			out = append(out, tok.Label())
		}
	}
	return out
}
