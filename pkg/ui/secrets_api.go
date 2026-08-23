package ui

// The Secrets & Grants panel's backend (Task 20171).
//
// pkg/secretbroker, pkg/secretstore and pkg/egressbroker already implemented
// all four grantable resource kinds the project goal names — GitHub repo
// scope, PAT permission subset, kubeconfig context/namespace, and an egress
// allowlist with byte quotas — but they were reachable only from
// `cloop secret grant` and `cloop egress`. A hosted operator with a browser
// and no shell on the hub could not see what an executor was allowed to
// touch, let alone take it away. These eight endpoints close that gap:
//
//	GET    /api/secrets            stored credentials, metadata + fingerprint
//	POST   /api/secrets            mint one (payload in, never back out)
//	DELETE /api/secrets/{id}       delete, revoking its grants with it
//	GET    /api/grants             secret grants and egress grants, unified
//	POST   /api/grants             create one, per-kind constraints enforced
//	DELETE /api/grants/{id}        revoke
//	GET    /api/leases             leases outstanding on this hub right now
//	POST   /api/leases/{id}/revoke wipe one executor's credential directory
//
// # The non-disclosure invariant
//
// No response built in this file may contain secret material or a decrypted
// lease token. That is enforced structurally rather than by review: the view
// structs below have no field that could hold a payload, and nothing here
// ever calls Cipher.Open — the only decrypting path in the process is
// Broker.Lease, which materialises into a workload's tmpfs and never into an
// http.ResponseWriter. What an operator gets instead is a fingerprint over
// the *sealed* bytes, which identifies the stored record without being a
// guessing oracle for the value inside it.
//
// tests/security/uiroutes_test.go seeds known plaintext into every kind and
// asserts it never appears in any of these responses, in any encoding.
//
// # Permissions
//
// Reads and creations require authz.PermSecretGrant; deletions and
// revocations require authz.PermSecretRevoke. Both sit at maintainer and
// above, so viewers and operators are denied every route here by the route
// table's deny-by-default gate. Reads are deliberately not viewer-visible:
// the list of which credentials exist, who holds them, and which executor
// they are bound to is reconnaissance, and the role that cannot broker
// access has no reason to enumerate it.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	// secretGrantTTLMinMinutes and secretGrantTTLMaxMinutes bound the TTL the
	// wizard may request.
	//
	// The lower bound exists because a grant that expires before the executor
	// it was written for next asks for a lease is indistinguishable from one
	// that was never created. The upper bound (90 days) is not a security
	// boundary — an operator can always re-grant — but it stops the panel
	// from being an easy way to create the forever-credential the whole
	// broker exists to replace.
	secretGrantTTLMinMinutes = 1
	secretGrantTTLMaxMinutes = 90 * 24 * 60

	// secretPayloadMaxBytes caps a minted payload. A kubeconfig with several
	// clusters is a few KB; anything past 256 KiB is a mistake or an attempt
	// to use the secret store as a filesystem.
	secretPayloadMaxBytes = 256 << 10

	// secretFingerprintHexLen is how much of the digest is shown. 16 hex
	// characters (64 bits) is far beyond collision range for one hub's secret
	// count and short enough to compare by eye.
	secretFingerprintHexLen = 16
)

// ---------------------------------------------------------------------------
// wire types
// ---------------------------------------------------------------------------

// secretView is one row of GET /api/secrets.
//
// There is deliberately no payload field, and no length field either: the
// size of a sealed credential is a weak oracle for the plaintext behind it,
// and nothing in the panel needs it.
type secretView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`

	// Fingerprint is a truncated SHA-256 over the *sealed* payload, prefixed
	// with the algorithm.
	//
	// It identifies the stored record, not the value: re-minting the same
	// credential produces different ciphertext and therefore a different
	// fingerprint. That is the intended trade. A digest over the plaintext
	// would let an operator compare two secrets for equality, and would also
	// hand anyone who can read this endpoint an offline oracle against which
	// to test guesses — fatal for the low-entropy payloads (a registry
	// password, an env value) that the store also holds.
	Fingerprint string `json:"fingerprint"`

	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	CreatedBy string            `json:"created_by,omitempty"`

	// Grants and ActiveGrants let the panel warn before a delete that would
	// pull access out from under a running project.
	Grants       int `json:"grants"`
	ActiveGrants int `json:"active_grants"`
}

// grantView is one row of GET /api/grants, covering both brokers.
//
// The two grant types are rendered through one struct because they are one
// concept to an operator — "this subject may use this resource until then" —
// and a panel that split them into two tables would make the fourth
// grantable kind look like a different feature. Source says which broker
// owns the row, which is what the delete route dispatches on.
type grantView struct {
	ID string `json:"id"`
	// Source is "secret" or "egress".
	Source string `json:"source"`
	// Kind is the secret's kind, or "egress" for an egress grant.
	Kind string `json:"kind"`

	SecretID   string `json:"secret_id,omitempty"`
	SecretName string `json:"secret_name,omitempty"`

	Scope   string `json:"scope,omitempty"`
	Subject string `json:"subject"`

	// Summary is the audit-safe one-line rendering the CLI and the audit log
	// already use, so the same grant reads identically in all three places.
	Summary string `json:"summary"`

	// Constraints is the structured form the wizard round-trips.
	Constraints grantConstraintsView `json:"constraints"`

	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	CreatedBy string     `json:"created_by,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`

	// Status is active|expired|revoked, and RemainingSeconds counts down to
	// ExpiresAt for an active grant (0 otherwise).
	Status           string `json:"status"`
	Active           bool   `json:"active"`
	RemainingSeconds int64  `json:"remaining_seconds"`
}

// grantConstraintsView carries every constraint dimension either broker
// understands. Fields are omitempty so a github grant does not ship a wall of
// null Kubernetes fields.
type grantConstraintsView struct {
	Repos       []string `json:"repos,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Namespaces  []string `json:"namespaces,omitempty"`
	Contexts    []string `json:"contexts,omitempty"`
	Hosts       []string `json:"hosts,omitempty"`
	Registries  []string `json:"registries,omitempty"`
	EnvKeys     []string `json:"env_keys,omitempty"`
	// Writable is local_repo-only: true means the bind is read-write.
	Writable bool `json:"writable,omitempty"`

	// egress-only dimensions
	CIDRs             []string `json:"cidrs,omitempty"`
	Ports             []int    `json:"ports,omitempty"`
	Methods           []string `json:"methods,omitempty"`
	MaxBytesUp        int64    `json:"max_bytes_up,omitempty"`
	MaxBytesDown      int64    `json:"max_bytes_down,omitempty"`
	SessionTTLSeconds int64    `json:"session_ttl_seconds,omitempty"`
}

// leaseMaterialView describes one credential inside a lease. It names the
// secret and the constraints it was minimized against — never the material.
type leaseMaterialView struct {
	GrantID    string `json:"grant_id"`
	SecretID   string `json:"secret_id"`
	SecretName string `json:"secret_name"`
	Kind       string `json:"kind"`
	Summary    string `json:"summary,omitempty"`
}

// leaseView is one row of GET /api/leases.
type leaseView struct {
	ID          string `json:"id"`
	ExecutorID  string `json:"executor_id,omitempty"`
	ProjectPath string `json:"project_path,omitempty"`
	// ProjectName is the registry name when the path is a known project, so
	// the table reads as "netgraph" rather than as a filesystem path.
	ProjectName string `json:"project_name,omitempty"`

	IssuedAt         time.Time           `json:"issued_at"`
	ExpiresAt        time.Time           `json:"expires_at"`
	RemainingSeconds int64               `json:"remaining_seconds"`
	Expired          bool                `json:"expired"`
	Materials        []leaseMaterialView `json:"materials"`

	// Revocations is what each remote agent holding this lease reported
	// when it was asked to give the credential back. Empty for a lease that
	// has never been revoked, or one held only by a hub-local executor.
	Revocations []revocationView `json:"revocations,omitempty"`
	// Revocable reports whether every executor holding this lease speaks a
	// protocol new enough to honour a revoke frame. False means a revocation
	// can wipe the hub's copy but cannot reach the device, which the panel
	// has to say out loud rather than offering a button that half works.
	Revocable bool `json:"revocable"`
	// Holders lists the remote executors currently holding this lease.
	Holders []string `json:"holders,omitempty"`
}

// brokerStatusView tells the panel whether the secret store is usable, and
// what to do when it is not.
//
// A hub with no CLOOP_SECRET_KEY is a legitimate, common state — it is every
// install that has not adopted the broker — so the endpoints degrade to
// "egress grants only" with an explanation rather than returning 500 and
// leaving an operator to guess.
type brokerStatusView struct {
	SecretsAvailable bool   `json:"secrets_available"`
	EgressAvailable  bool   `json:"egress_available"`
	Reason           string `json:"reason,omitempty"`
	Remediation      string `json:"remediation,omitempty"`
}

type secretsListResponse struct {
	Secrets []secretView     `json:"secrets"`
	Kinds   []string         `json:"kinds"`
	Broker  brokerStatusView `json:"broker"`
}

type grantsListResponse struct {
	Grants []grantView      `json:"grants"`
	Broker brokerStatusView `json:"broker"`
}

type leasesListResponse struct {
	Leases []leaseView      `json:"leases"`
	Broker brokerStatusView `json:"broker"`
}

// ---------------------------------------------------------------------------
// broker access
// ---------------------------------------------------------------------------

// brokerSet is one open control-plane database with both brokers over it.
//
// They share a handle because they share a database and a request: opening
// two would double the file handles for every panel refresh, and the audit
// rows they emit belong in one chain anyway.
type brokerSet struct {
	db     *statedb.DB
	secret *secretbroker.Broker
	egress *egressbroker.Broker
	status brokerStatusView
	close  func()
}

// openBrokers builds both brokers over the control plane's database.
//
// The secret broker may legitimately be nil while the egress broker is not:
// egress grants carry no sealed payload, so they work without
// CLOOP_SECRET_KEY. Every caller must therefore check bs.secret rather than
// assume it, which is why status carries the reason and remediation to show.
//
// Grants live in the control plane's own database rather than in a managed
// project's, for the same reason executor bindings do: a tenant must not be
// able to grant itself credentials by writing to a database it owns.
func (s *Server) openBrokers() (*brokerSet, error) { return openBrokersAt(s.WorkDir) }

// openBrokersAt is openBrokers without a Server, for the workload-start path.
//
// That path is package-level (startWorkload/runWorkload are functions, not
// methods) because a workload outlives the request that started it and must
// not capture the Server that handled it. Splitting the constructor is cheaper
// than threading a Server through, and keeps one implementation of the rule
// that grants live in the control plane's database.
func openBrokersAt(controlPlaneWorkDir string) (*brokerSet, error) {
	dbPath := state.DBPath(controlPlaneWorkDir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("the control plane has no state database at %s yet", dbPath)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open control-plane database: %w", err)
	}

	bs := &brokerSet{db: db, close: func() { _ = db.Close() }}
	auditor := secretstore.NewAuditor(db)

	if store, serr := secretstore.New(db); serr == nil {
		if broker, berr := secretbroker.New(store, secretbroker.WithAuditor(auditor)); berr == nil {
			bs.secret = broker
			bs.status.SecretsAvailable = true
		} else {
			bs.status.Reason, bs.status.Remediation = brokerUnavailableReason(berr)
		}
	} else {
		bs.status.Reason, bs.status.Remediation = brokerUnavailableReason(serr)
	}

	if estore, eerr := secretstore.NewEgressStore(db); eerr == nil {
		if ebroker, berr := egressbroker.New(estore, egressbroker.WithAuditor(auditor)); berr == nil {
			bs.egress = ebroker
			bs.status.EgressAvailable = true
		}
	}
	return bs, nil
}

// brokerUnavailableReason turns a construction failure into something an
// operator can act on. The unset-key case is by far the most common and is
// not a fault, so it gets a concrete instruction rather than a stack of Go
// error text.
func brokerUnavailableReason(err error) (reason, remediation string) {
	if errors.Is(err, secretbroker.ErrNoKey) {
		return "the secret store is not configured on this hub",
			"Set CLOOP_SECRET_KEY in the hub's environment and restart. It is the passphrase " +
				"every stored payload is sealed with; without it cloop can neither store nor " +
				"open a credential. Egress grants need no key and keep working."
	}
	return "the secret store is unavailable: " + err.Error(),
		"Check the hub's log for the underlying error."
}

// requireSecretBroker resolves the secret broker or writes the 503 that says
// why it could not, reporting whether the caller may proceed.
func (bs *brokerSet) requireSecretBroker(w http.ResponseWriter) bool {
	if bs.secret != nil {
		return true
	}
	apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, bs.status.Reason).
		WithDetails(map[string]any{"remediation": bs.status.Remediation}))
	return false
}

// openBrokersOr writes the error response itself when the database cannot be
// opened at all, which is the one failure neither broker can degrade around.
func (s *Server) openBrokersOr(w http.ResponseWriter) (*brokerSet, bool) {
	bs, err := s.openBrokers()
	if err != nil {
		s.log().Error(logger.EventAuthz, 0, "secrets: open control-plane brokers",
			map[string]interface{}{"error": err.Error()})
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return nil, false
	}
	return bs, true
}

// ---------------------------------------------------------------------------
// secrets
// ---------------------------------------------------------------------------

// secretFingerprint digests the sealed bytes. See secretView.Fingerprint for
// why it is the ciphertext and not the value.
func secretFingerprint(sealed []byte) string {
	if len(sealed) == 0 {
		return ""
	}
	sum := sha256.Sum256(sealed)
	return "sha256:" + hex.EncodeToString(sum[:])[:secretFingerprintHexLen]
}

// handleSecretsList serves GET /api/secrets.
func (s *Server) handleSecretsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apierror.WriteError(w, apierror.New(apierror.CodeMethodNotAllowed, "GET required"))
		return
	}
	bs, ok := s.openBrokersOr(w)
	if !ok {
		return
	}
	defer bs.close()

	resp := secretsListResponse{
		Secrets: []secretView{},
		Kinds:   kindNames(),
		Broker:  bs.status,
	}
	if bs.secret == nil {
		// Not an error: an un-adopted broker has no secrets, and saying so
		// with the remediation attached beats a 503 the panel cannot explain.
		jsonOK(w, resp)
		return
	}

	secrets, err := bs.secret.ListSecrets()
	if err != nil {
		s.log().Error(logger.EventAuthz, 0, "secrets: list",
			map[string]interface{}{"error": err.Error()})
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, "could not read the secret store"))
		return
	}

	// One grant listing, then a count per secret: the alternative is a
	// ListGrants call inside the loop, which is the same read N times.
	total := map[string]int{}
	active := map[string]int{}
	if grants, gerr := bs.secret.ListGrants(secretbroker.GrantFilter{}); gerr == nil {
		now := time.Now()
		for _, g := range grants {
			total[g.SecretID]++
			if g.Active(now) {
				active[g.SecretID]++
			}
		}
	}

	for _, sec := range secrets {
		resp.Secrets = append(resp.Secrets, secretView{
			ID:           sec.ID,
			Name:         sec.Name,
			Kind:         string(sec.Kind),
			Fingerprint:  secretFingerprint(sec.Sealed),
			Metadata:     sec.Metadata,
			CreatedAt:    sec.CreatedAt,
			CreatedBy:    sec.CreatedBy,
			Grants:       total[sec.ID],
			ActiveGrants: active[sec.ID],
		})
	}
	jsonOK(w, resp)
}

func kindNames() []string {
	kinds := secretbroker.Kinds()
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, string(k))
	}
	return out
}

// createSecretRequest is the POST /api/secrets body.
type createSecretRequest struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Payload is the credential. It travels in one direction only: it is
	// sealed on arrival and no endpoint in this file can return it.
	Payload  string            `json:"payload"`
	Metadata map[string]string `json:"metadata"`
}

// handleSecretCreate serves POST /api/secrets.
func (s *Server) handleSecretCreate(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req createSecretRequest
	if !decodeSecretsBody(w, r, &req) {
		return
	}
	kind, err := secretbroker.ParseKind(req.Kind)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}
	if len(req.Payload) == 0 {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"payload is required — a secret with no value cannot be brokered"))
		return
	}
	if len(req.Payload) > secretPayloadMaxBytes {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			fmt.Sprintf("payload exceeds %d bytes", secretPayloadMaxBytes)))
		return
	}
	if err := secretbroker.ValidateName(req.Name); err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}
	// A local_repo payload is a path on this host, so it is the one kind whose
	// validity is knowable now. Checking it here turns a typo into a message in
	// the dialog the operator is still looking at, instead of a lease failure
	// during someone else's run an hour later.
	if kind == secretbroker.KindLocalRepo {
		if _, err := secretbroker.ParseLocalRepoRoot([]byte(req.Payload)); err != nil {
			apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
			return
		}
	}

	bs, ok := s.openBrokersOr(w)
	if !ok {
		return
	}
	defer bs.close()
	if !bs.requireSecretBroker(w) {
		return
	}

	// Mint zeroes the slice it is handed, so the plaintext is gone from this
	// buffer before the response is written. The decoded string it was copied
	// from is not zeroable in Go and lives until the collector reclaims it —
	// which is exactly why nothing here logs the request body.
	payload := []byte(req.Payload)
	sec, err := bs.secret.Mint(r.Context(), secretbroker.MintRequest{
		Name:     strings.TrimSpace(req.Name),
		Kind:     kind,
		Payload:  payload,
		Metadata: req.Metadata,
		Actor:    s.auditActor(r),
	})
	if err != nil {
		writeBrokerError(w, err, "mint secret")
		return
	}

	// Mint already wrote the audit row through the broker's auditor; this
	// only tells open dashboards the trail grew.
	s.broadcastAuditAppend(string(secretbroker.ActionMint))
	s.broadcastSecretsUpdate("secret_created", sec.ID)
	jsonOK(w, secretView{
		ID:          sec.ID,
		Name:        sec.Name,
		Kind:        string(sec.Kind),
		Fingerprint: secretFingerprint(sec.Sealed),
		Metadata:    sec.Metadata,
		CreatedAt:   sec.CreatedAt,
		CreatedBy:   sec.CreatedBy,
	})
}

// handleSecretDelete serves DELETE /api/secrets/{id}.
//
// The broker revokes every grant pointing at the secret as part of the
// delete, so this is a revocation in the RBAC sense and is gated on
// secret.revoke rather than secret.grant.
func (s *Server) handleSecretDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "secret id is required"))
		return
	}
	bs, ok := s.openBrokersOr(w)
	if !ok {
		return
	}
	defer bs.close()
	if !bs.requireSecretBroker(w) {
		return
	}

	if err := bs.secret.DeleteSecret(r.Context(), id, s.auditActor(r)); err != nil {
		writeBrokerError(w, err, "delete secret")
		return
	}
	s.broadcastAuditAppend(string(secretbroker.ActionDeleteSec))
	s.broadcastSecretsUpdate("secret_deleted", id)
	jsonOK(w, map[string]any{"ok": true, "id": id, "deleted": true})
}

// ---------------------------------------------------------------------------
// grants
// ---------------------------------------------------------------------------

// handleGrantsList serves GET /api/grants, unioning both brokers.
//
// ?active=1 drops expired and revoked rows. The default is to include them:
// "who could reach this repository last month" is a question the panel should
// be able to answer, and it is the reason revocation is a stamp rather than a
// delete in both stores.
func (s *Server) handleGrantsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apierror.WriteError(w, apierror.New(apierror.CodeMethodNotAllowed, "GET required"))
		return
	}
	bs, ok := s.openBrokersOr(w)
	if !ok {
		return
	}
	defer bs.close()

	activeOnly := isTruthyParam(r.URL.Query().Get("active"))
	subject := strings.TrimSpace(r.URL.Query().Get("subject"))
	now := time.Now()
	resp := grantsListResponse{Grants: []grantView{}, Broker: bs.status}

	if bs.secret != nil {
		names := map[string]secretbroker.Secret{}
		if secrets, serr := bs.secret.ListSecrets(); serr == nil {
			for _, sec := range secrets {
				names[sec.ID] = sec
			}
		}
		grants, err := bs.secret.ListGrants(secretbroker.GrantFilter{
			Subject:    subject,
			ActiveOnly: activeOnly,
		})
		if err != nil {
			s.log().Error(logger.EventAuthz, 0, "secrets: list grants",
				map[string]interface{}{"error": err.Error()})
			apierror.WriteError(w, apierror.New(apierror.CodeInternal, "could not read grants"))
			return
		}
		for _, g := range grants {
			resp.Grants = append(resp.Grants, secretGrantView(g, names[g.SecretID], now))
		}
	}

	if bs.egress != nil {
		grants, err := bs.egress.ListGrants(egressbroker.GrantFilter{
			Subject:    subject,
			ActiveOnly: activeOnly,
		})
		if err != nil {
			s.log().Warn(logger.EventAuthz, 0, "secrets: list egress grants",
				map[string]interface{}{"error": err.Error()})
		}
		for _, g := range grants {
			resp.Grants = append(resp.Grants, egressGrantView(g, now))
		}
	}

	// Newest first across both sources, so the union reads as one table
	// rather than as two concatenated ones.
	sort.SliceStable(resp.Grants, func(i, j int) bool {
		return resp.Grants[i].CreatedAt.After(resp.Grants[j].CreatedAt)
	})
	jsonOK(w, resp)
}

// grantStatus renders the three states a grant can be in. Expiry and
// revocation are distinct on purpose: one is the design working, the other is
// somebody having intervened.
func grantStatus(revokedAt, expiresAt time.Time, now time.Time) (status string, active bool, remaining int64) {
	switch {
	case !revokedAt.IsZero() && !now.Before(revokedAt):
		return "revoked", false, 0
	case !expiresAt.IsZero() && !now.Before(expiresAt):
		return "expired", false, 0
	}
	if !expiresAt.IsZero() {
		remaining = int64(expiresAt.Sub(now) / time.Second)
	}
	return "active", true, remaining
}

func secretGrantView(g secretbroker.Grant, sec secretbroker.Secret, now time.Time) grantView {
	status, active, remaining := grantStatus(g.RevokedAt, g.ExpiresAt, now)
	v := grantView{
		ID:         g.ID,
		Source:     "secret",
		Kind:       string(sec.Kind),
		SecretID:   g.SecretID,
		SecretName: sec.Name,
		Scope:      g.Scope,
		Subject:    g.Subject.String(),
		Summary:    g.Constraints.Summary(),
		Constraints: grantConstraintsView{
			Repos:       g.Constraints.Repos,
			Permissions: g.Constraints.Permissions,
			Namespaces:  g.Constraints.Namespaces,
			Contexts:    g.Constraints.Contexts,
			Hosts:       g.Constraints.Hosts,
			Registries:  g.Constraints.Registries,
			EnvKeys:     g.Constraints.EnvKeys,
			Writable:    g.Constraints.Writable,
		},
		CreatedAt:        g.CreatedAt,
		CreatedBy:        g.CreatedBy,
		Status:           status,
		Active:           active,
		RemainingSeconds: remaining,
	}
	if !g.ExpiresAt.IsZero() {
		exp := g.ExpiresAt
		v.ExpiresAt = &exp
	}
	if !g.RevokedAt.IsZero() {
		rev := g.RevokedAt
		v.RevokedAt = &rev
	}
	return v
}

func egressGrantView(g egressbroker.Grant, now time.Time) grantView {
	status, active, remaining := grantStatus(g.RevokedAt, g.ExpiresAt, now)
	v := grantView{
		ID:      g.ID,
		Source:  "egress",
		Kind:    "egress",
		Scope:   g.Scope,
		Subject: g.Subject.String(),
		Summary: g.Summary(),
		Constraints: grantConstraintsView{
			Hosts:             g.Hosts,
			CIDRs:             g.CIDRs,
			Ports:             g.Ports,
			Methods:           g.Methods,
			MaxBytesUp:        g.MaxBytesUp,
			MaxBytesDown:      g.MaxBytesDown,
			SessionTTLSeconds: int64(g.SessionTTL / time.Second),
		},
		CreatedAt:        g.CreatedAt,
		CreatedBy:        g.CreatedBy,
		Status:           status,
		Active:           active,
		RemainingSeconds: remaining,
	}
	if !g.ExpiresAt.IsZero() {
		exp := g.ExpiresAt
		v.ExpiresAt = &exp
	}
	if !g.RevokedAt.IsZero() {
		rev := g.RevokedAt
		v.RevokedAt = &rev
	}
	return v
}

// createGrantRequest is the POST /api/grants body.
//
// One shape covers both brokers, discriminated by Source. The alternative —
// two endpoints — would make the wizard's kind selector switch URLs as well
// as fields, and would put the "which broker owns this kind" decision in the
// frontend where it cannot be tested.
type createGrantRequest struct {
	// Source is "secret" (default) or "egress".
	Source string `json:"source"`
	// SecretRef is a secret ID or name. Required for Source "secret".
	SecretRef string `json:"secret_ref"`
	// Subject is the CLI's --to syntax: project:/srv/app, executor:edge-01,
	// label:region=eu, or any.
	Subject string `json:"subject"`
	Scope   string `json:"scope"`
	// TTLMinutes is the grant's lifetime.
	TTLMinutes int `json:"ttl_minutes"`

	Repos       []string `json:"repos"`
	Permissions []string `json:"permissions"`
	Namespaces  []string `json:"namespaces"`
	Contexts    []string `json:"contexts"`
	Hosts       []string `json:"hosts"`
	Registries  []string `json:"registries"`
	EnvKeys     []string `json:"env_keys"`
	// Writable makes a local_repo grant read-write. Absent means read-only,
	// which is both the safe reading and the common one.
	Writable bool `json:"writable"`

	CIDRs             []string `json:"cidrs"`
	Ports             []int    `json:"ports"`
	Methods           []string `json:"methods"`
	MaxBytesUp        int64    `json:"max_bytes_up"`
	MaxBytesDown      int64    `json:"max_bytes_down"`
	SessionTTLMinutes int      `json:"session_ttl_minutes"`
}

// handleGrantCreate serves POST /api/grants.
func (s *Server) handleGrantCreate(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req createGrantRequest
	if !decodeSecretsBody(w, r, &req) {
		return
	}

	subject, err := secretbroker.ParseSubject(req.Subject)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}
	ttl, err := grantTTL(req.TTLMinutes)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}

	bs, ok := s.openBrokersOr(w)
	if !ok {
		return
	}
	defer bs.close()

	actor := s.auditActor(r)
	if strings.EqualFold(strings.TrimSpace(req.Source), "egress") {
		s.createEgressGrant(w, r, bs, req, subject, ttl, actor)
		return
	}
	if !bs.requireSecretBroker(w) {
		return
	}

	// Constraints are handed to the broker unchecked on purpose: Grant calls
	// Constraints.ValidateFor(kind), which is the single definition of "does
	// this allowlist actually gate this kind of credential". Re-implementing
	// that check here would create a second, drifting copy of the rule that
	// rejects a github grant with no repo allowlist.
	grant, err := bs.secret.Grant(r.Context(), secretbroker.GrantRequest{
		SecretRef: strings.TrimSpace(req.SecretRef),
		Subject:   subject,
		Scope:     strings.TrimSpace(req.Scope),
		TTL:       ttl,
		Actor:     actor,
		Constraints: secretbroker.Constraints{
			Repos:       cleanList(req.Repos),
			Permissions: cleanList(req.Permissions),
			Namespaces:  cleanList(req.Namespaces),
			Contexts:    cleanList(req.Contexts),
			Hosts:       cleanList(req.Hosts),
			Registries:  cleanList(req.Registries),
			EnvKeys:     cleanList(req.EnvKeys),
			Writable:    req.Writable,
		},
	})
	if err != nil {
		writeBrokerError(w, err, "create grant")
		return
	}

	var sec secretbroker.Secret
	if got, gerr := bs.secret.ListSecrets(); gerr == nil {
		for _, candidate := range got {
			if candidate.ID == grant.SecretID {
				sec = candidate
				break
			}
		}
	}
	s.broadcastAuditAppend(string(secretbroker.ActionGrant))
	s.broadcastSecretsUpdate("grant_created", grant.ID)
	jsonOK(w, secretGrantView(grant, sec, time.Now()))
}

// createEgressGrant handles the egress branch of POST /api/grants.
func (s *Server) createEgressGrant(
	w http.ResponseWriter,
	r *http.Request,
	bs *brokerSet,
	req createGrantRequest,
	subject secretbroker.Subject,
	ttl time.Duration,
	actor string,
) {
	if bs.egress == nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable,
			"the egress broker is unavailable on this hub"))
		return
	}
	grant, err := bs.egress.Grant(r.Context(), egressbroker.GrantRequest{
		Subject:      subject,
		Scope:        strings.TrimSpace(req.Scope),
		Hosts:        cleanList(req.Hosts),
		CIDRs:        cleanList(req.CIDRs),
		Ports:        req.Ports,
		Methods:      cleanList(req.Methods),
		MaxBytesUp:   req.MaxBytesUp,
		MaxBytesDown: req.MaxBytesDown,
		SessionTTL:   time.Duration(req.SessionTTLMinutes) * time.Minute,
		TTL:          ttl,
		Actor:        actor,
	})
	if err != nil {
		writeBrokerError(w, err, "create egress grant")
		return
	}
	s.broadcastAuditAppend(string(secretbroker.ActionEgressGrant))
	s.broadcastSecretsUpdate("grant_created", grant.ID)
	jsonOK(w, egressGrantView(grant, time.Now()))
}

// handleGrantDelete serves DELETE /api/grants/{id}: revoke a grant.
//
// The ID prefix decides which broker owns it — secretbroker mints "grant_…"
// and egressbroker mints "egress_…". Routing on the ID rather than on a query
// parameter means a stale panel cannot revoke the wrong row by sending the
// wrong source, and a caller cannot use the parameter to probe one store for
// IDs it learned from the other.
func (s *Server) handleGrantDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "grant id is required"))
		return
	}
	bs, ok := s.openBrokersOr(w)
	if !ok {
		return
	}
	defer bs.close()

	actor := s.auditActor(r)
	if strings.HasPrefix(id, "egress_") {
		if bs.egress == nil {
			apierror.WriteError(w, apierror.New(apierror.CodeUnavailable,
				"the egress broker is unavailable on this hub"))
			return
		}
		// Revoking an egress grant also tears down its live proxy sessions,
		// so unlike a PAT this takes effect mid-connection.
		if err := bs.egress.Revoke(r.Context(), id, actor); err != nil {
			writeBrokerError(w, err, "revoke egress grant")
			return
		}
		s.broadcastAuditAppend(string(secretbroker.ActionEgressRevoke))
		s.broadcastSecretsUpdate("grant_revoked", id)
		jsonOK(w, map[string]any{"ok": true, "id": id, "revoked": true, "source": "egress"})
		return
	}

	if !bs.requireSecretBroker(w) {
		return
	}
	if err := bs.secret.Revoke(r.Context(), id, actor); err != nil {
		writeBrokerError(w, err, "revoke grant")
		return
	}
	s.broadcastAuditAppend(string(secretbroker.ActionRevoke))
	s.broadcastSecretsUpdate("grant_revoked", id)
	// The honest note: revocation lands on the next Lease or Renew, so a
	// workload already holding materials keeps them until its lease expires.
	// The lease table below is where an operator takes those away now.
	jsonOK(w, map[string]any{
		"ok": true, "id": id, "revoked": true, "source": "secret",
		"note": "Takes effect on the next lease or renewal. Credentials already " +
			"materialised into a running workload persist until their lease expires — " +
			"revoke the lease to remove them now.",
	})
}

// ---------------------------------------------------------------------------
// leases
// ---------------------------------------------------------------------------

// handleLeasesList serves GET /api/leases: what is outstanding right now.
func (s *Server) handleLeasesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apierror.WriteError(w, apierror.New(apierror.CodeMethodNotAllowed, "GET required"))
		return
	}

	// Resolve project paths to registry names once, so the table can show a
	// project rather than a path without a lookup per row.
	names := map[string]string{}
	for _, entry := range s.allProjectEntries() {
		names[entry.Path] = entry.Name
	}

	now := time.Now()
	resp := leasesListResponse{Leases: []leaseView{}}
	resp.Broker.SecretsAvailable = true
	resp.Broker.EgressAvailable = true

	// Indexed once for the whole table rather than per row: the fleet log is
	// a single in-memory snapshot, and asking the hub per lease would turn an
	// O(1) read into O(leases × executors).
	revocations := s.fleetRevocations()

	for _, sl := range liveLeases.snapshot() {
		l := sl.lease
		if l == nil {
			continue
		}
		view := leaseView{
			ID:          l.ID,
			ExecutorID:  l.ExecutorID,
			ProjectPath: l.ProjectID,
			ProjectName: names[l.ProjectID],
			IssuedAt:    l.IssuedAt,
			ExpiresAt:   l.ExpiresAt,
			Expired:     l.Expired(now),
			Materials:   []leaseMaterialView{},
		}
		view.RemainingSeconds = int64(l.TTL(now) / time.Second)
		view.Revocations = revocations[l.ID]
		view.Holders, view.Revocable = s.leaseHolders(l.ID)
		for _, m := range l.Materials {
			// Material.Env and Material.Files carry the plaintext and are
			// json:"-"; only these five metadata fields are copied, so the
			// credential has no path into the response even if Material grows
			// a new serialisable field later.
			view.Materials = append(view.Materials, leaseMaterialView{
				GrantID:    m.GrantID,
				SecretID:   m.SecretID,
				SecretName: m.SecretName,
				Kind:       string(m.Kind),
				Summary:    m.Summary,
			})
		}
		resp.Leases = append(resp.Leases, view)
	}
	jsonOK(w, resp)
}

// handleLeaseRevoke serves POST /api/leases/{id}/revoke.
//
// This is the one revocation in the system that is immediate for a secret:
// it wipes the tmpfs directory the workload's credentials live in, rather
// than waiting for the lease to lapse. A process that has already read a file
// into its own memory keeps what it read — no control plane can reach into
// another process's heap — so what this guarantees is that nothing further
// can be read, and that a renewal will not re-issue.
func (s *Server) handleLeaseRevoke(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "lease id is required"))
		return
	}

	var req leaseRevokeRequest
	// An absent body is fine here, unlike everywhere else in this file: the
	// panel's ordinary Revoke button sends none, and the default (scrub, no
	// reason) is the conservative action rather than a guess about intent.
	if r.ContentLength > 0 && !decodeSecretsBody(w, r, &req) {
		return
	}
	action, err := parseRevokeAction(req.Action)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}

	// Snapshot before the revocation: revokeLeaseEverywhere removes the lease
	// from the registry, and these fields are what the response and the audit
	// row are built from.
	executorID, projectID, secretNames := "", "", []string(nil)
	for _, sl := range liveLeases.snapshot() {
		if sl.lease != nil && sl.lease.ID == id {
			executorID, projectID = sl.lease.ExecutorID, sl.lease.ProjectID
			secretNames = sl.lease.SecretNames()
			break
		}
	}
	holders, _ := s.leaseHolders(id)

	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "revoked from the Secrets panel"
	}
	result := s.revokeLeaseEverywhere(r.Context(), id, strings.TrimSpace(req.GrantID),
		reason, action, s.auditActor(r))

	if !result.WipedLocally && len(result.Remote) == 0 {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound,
			"no lease with that id is open on this hub and no connected agent is holding it — "+
				"it may have already expired, been wiped, or been revoked"))
		return
	}

	// The broker's own Release event names the executor as actor. Record a
	// second row naming the human who pressed the button: "who took this
	// credential away" is the question the trail is for, and the executor's
	// ID does not answer it.
	s.auditLeaseRevoke(r, id, executorID, projectID, secretNames)
	s.broadcastSecretsUpdate("lease_revoked", id)
	jsonOK(w, map[string]any{
		"ok": true, "id": id, "revoked": true,
		"executor_id":   executorID,
		"secrets":       secretNames,
		"action":        string(action),
		"state":         string(result.State),
		"wiped_locally": result.WipedLocally,
		"holders":       holders,
		"remote":        result.Remote,
		"note":          revokeNote(result),
	})
}

// leaseRevokeRequest is the optional body of POST /api/leases/{id}/revoke.
type leaseRevokeRequest struct {
	// Action is "scrub" (default) or "kill".
	Action string `json:"action"`
	// GrantID narrows the revocation to one grant within the lease.
	GrantID string `json:"grant_id"`
	// Reason is carried to the device and into the audit trail.
	Reason string `json:"reason"`
}

// leaseHolders reports which remote executors hold a lease and whether every
// one of them can honour a revoke frame.
//
// The second value is what stops the panel promising more than the fleet can
// deliver: an agent too old to understand the frame will never be sent a
// revocable workload in the first place (remote.Executor.Start refuses it),
// but a device downgraded after a placement, or one enrolled before the
// binding existed, can still turn up here.
func (s *Server) leaseHolders(leaseID string) (holders []string, revocable bool) {
	hub, err := s.remoteHub()
	if err != nil || hub == nil {
		// No remote fleet. The hub's own mount is the only copy, and wiping
		// it is unconditionally within this process's power.
		return nil, true
	}
	holders = hub.LeaseHolders(leaseID)
	revocable = true
	for _, id := range holders {
		ex, ok := hub.Executor(id)
		if !ok || !ex.SupportsRevocation() {
			revocable = false
		}
	}
	return holders, revocable
}

// revokeNote states, in the operator's terms, what the revocation achieved —
// and what it did not.
//
// The distinction it draws is the one the whole feature turns on. Scrubbing
// removes files and allowlist entries for good, but an environment variable
// already handed to a running process cannot be taken out of that process's
// memory by anyone. Saying "revoked" without that caveat would let an operator
// close an incident believing a token is dead when the task holding it is
// still using it.
func revokeNote(result leaseRevocation) string {
	switch result.State {
	case remote.RevokeStateUnreachable:
		return "The hub's copy is wiped, but at least one agent holding this lease is offline. " +
			"The revocation is queued and will be delivered the moment it reconnects — until then, " +
			"treat the credential as live and revoke the grant itself if it is compromised."
	case remote.RevokeStateFailed:
		return "At least one agent could not complete the scrub. Check the per-executor detail; " +
			"treat the credential as live until it reports revoked."
	case remote.RevokeStatePending:
		return "Sent; waiting for the agent to acknowledge."
	default:
		if len(result.Remote) == 0 {
			return "Credential files wiped. A process that already read one keeps what it read."
		}
		return "Credential files removed and egress allowlist entries dropped on every holder. " +
			"Environment variables were dropped from each agent's memory, but a running task that " +
			"already has one in its own environment keeps it — revoke with action=kill to stop those tasks."
	}
}

// auditLeaseRevoke records an operator-initiated lease revocation.
//
// Best-effort, matching every other emitter in the hub: a wedged journal must
// not stop an operator from pulling a credential.
func (s *Server) auditLeaseRevoke(r *http.Request, leaseID, executorID, projectID string, secrets []string) {
	db, err := s.controlPlaneDB()
	if err != nil {
		s.log().Warn(logger.EventAuthz, 0, "secrets: open control-plane db for lease revoke event",
			map[string]interface{}{"error": err.Error(), "lease_id": leaseID})
		return
	}
	defer db.Close()

	statedb.AuditSecretDecision(db, statedb.SecretAuditInput{
		Actor:     s.auditActor(r),
		EventType: string(secretbroker.ActionRelease),
		EntityID:  leaseID,
		Payload: map[string]any{
			"decision":    string(secretbroker.DecisionAllow),
			"lease_id":    leaseID,
			"executor_id": executorID,
			"project_id":  projectID,
			"secrets":     strings.Join(secrets, ","),
			"reason":      "revoked from the Secrets panel",
		},
	})
	s.broadcastAuditAppend(string(secretbroker.ActionRelease))
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

// decodeSecretsBody decodes a required JSON body.
//
// Unlike the executor handlers, an empty body is rejected rather than treated
// as "use the defaults": every route here creates or changes access, and
// there is no safe default for "which repositories may this token touch".
func decodeSecretsBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"invalid JSON body: "+err.Error()))
		return false
	}
	return true
}

// grantTTL validates the requested lifetime, defaulting to the broker's own.
func grantTTL(minutes int) (time.Duration, error) {
	if minutes == 0 {
		return secretbroker.DefaultGrantTTL, nil
	}
	if minutes < secretGrantTTLMinMinutes || minutes > secretGrantTTLMaxMinutes {
		return 0, fmt.Errorf("ttl_minutes must be between %d and %d (got %d)",
			secretGrantTTLMinMinutes, secretGrantTTLMaxMinutes, minutes)
	}
	return time.Duration(minutes) * time.Minute, nil
}

// cleanList trims and drops empty entries, returning nil for an empty result.
//
// Nil rather than an empty slice matters: Constraints.ValidateFor rejects an
// empty allowlist on a gating dimension, and a []string{} that arrived from
// an untouched wizard field must reach it as "not set" so that rejection
// actually fires.
func cleanList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// isTruthyParam reads the query-string booleans the panel sends.
func isTruthyParam(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// writeBrokerError maps a broker sentinel onto an HTTP status.
//
// Every branch returns err.Error() verbatim, which is safe because the broker
// constructs its messages from allowlist patterns, names, and IDs, and routes
// user-supplied references through SafeRef — never through the payload. The
// non-disclosure suite asserts this by seeding a credential and driving the
// error paths.
func writeBrokerError(w http.ResponseWriter, err error, action string) {
	switch {
	case errors.Is(err, secretbroker.ErrSecretNotFound),
		errors.Is(err, secretbroker.ErrGrantNotFound),
		errors.Is(err, egressbroker.ErrGrantNotFound):
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, err.Error()))
	case errors.Is(err, secretbroker.ErrDuplicateName):
		apierror.WriteError(w, apierror.New(apierror.CodeConflict, err.Error()))
	case errors.Is(err, secretbroker.ErrInvalidKind),
		errors.Is(err, secretbroker.ErrInvalidSecret),
		errors.Is(err, secretbroker.ErrInvalidGrant),
		errors.Is(err, secretbroker.ErrInvalidSubject),
		errors.Is(err, secretbroker.ErrInvalidConstraint),
		errors.Is(err, egressbroker.ErrInvalidGrant):
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
	case errors.Is(err, secretbroker.ErrNoKey):
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "request cancelled"))
	default:
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, action+": "+err.Error()))
	}
}

// broadcastSecretsUpdate tells connected dashboards that the credential
// surface changed, so the panel refreshes without polling.
//
// Like audit_append and executor_update, the envelope carries only the fact
// and an ID — never a grant's contents. A WebSocket fans out to every
// connected client regardless of role, so putting row data in it would hand
// the credential inventory to a viewer who cannot reach GET /api/grants.
//
// Scope: hub-global, deliberately (audited under Task 20189). The secret and
// grant tables are hub-wide, so there is no project room to send this to.
// That the fan-out is wider than the read permission is exactly why the
// envelope is an event verb plus an opaque id and nothing else.
func (s *Server) broadcastSecretsUpdate(event, id string) {
	payload, err := json.Marshal(map[string]any{"event": event, "id": id})
	if err != nil {
		return
	}
	msg := wsMessage{Type: "secrets_update", Data: json.RawMessage(payload)}

	s.hubMu.Lock()
	for _, clients := range s.hubClients {
		for hc := range clients {
			s.sendOrLag(hc, msg)
		}
	}
	s.hubMu.Unlock()
}
