package ui

// githubapp_api.go is the GitHub App surface: connecting one to the hub, and
// assigning the repositories it reaches to a project.
//
// The split matters. Connecting an App is a hub-wide, admin-shaped act — it
// stores a signing key — so those routes are scopeGlobal and gated on
// secret.grant like every other credential write. Assigning repositories is
// per-project and is evaluated against that project's scope, so a maintainer
// of one project cannot widen another's access by guessing an index.
//
// Between the two sits the thing that makes this usable at all: the hub asks
// GitHub which installations exist and which repositories each covers, so the
// operator picks from lists instead of transcribing numbers out of a browser
// address bar. See pkg/secretbroker/githubapp_discover.go.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// githubAppKeyMaxBytes bounds a connect request body.
//
// A 4096-bit PKCS#8 key in PEM is a little over 3 KiB, so 32 KiB is generous
// for the key plus the JSON around it while still refusing a body that is not
// a key at all. The bound exists because this handler is reached before
// anything has validated the payload's shape.
const githubAppKeyMaxBytes = 32 << 10

// githubAppDiscoveryTimeout bounds the outbound calls to GitHub.
//
// Separate from the request context so a browser that gives up does not leave
// the hub holding a connection, and short enough that a wrong base_url fails in
// front of the operator rather than hanging the dialog.
const githubAppDiscoveryTimeout = 30 * time.Second

// ---------------------------------------------------------------------------
// Connect: discovery
// ---------------------------------------------------------------------------

// connectGitHubAppRequest is what the Connect dialog posts.
//
// It carries a private key, which is why nothing in this file logs a request
// body and why the struct is never echoed back in a response.
type connectGitHubAppRequest struct {
	AppID      json.Number `json:"app_id"`
	PrivateKey string      `json:"private_key"`
	BaseURL    string      `json:"base_url,omitempty"`
}

// installationView is one discovered installation, as the dialog renders it.
// Every field is a public identifier.
type installationView struct {
	ID                  int64  `json:"id"`
	AppID               int64  `json:"app_id"`
	Account             string `json:"account"`
	AccountType         string `json:"account_type"`
	RepositorySelection string `json:"repository_selection"`
}

// handleGitHubAppInstallations serves POST /api/github-app/installations.
//
// It answers "where is this App installed?" for a key the operator has just
// pasted and the hub has not stored. Nothing is persisted: the caller picks an
// installation and then mints a github_app secret through the normal
// POST /api/secrets path with that ID filled in.
func (s *Server) handleGitHubAppInstallations(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req connectGitHubAppRequest
	limitJSONBody(w, r, githubAppKeyMaxBytes)
	if !decodeSecretsBody(w, r, &req) {
		return
	}
	appID := strings.TrimSpace(req.AppID.String())
	if appID == "" || appID == "0" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"app_id is required — it is on the App's settings page on GitHub"))
		return
	}
	if strings.TrimSpace(req.PrivateKey) == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"private_key is required — generate one on the App's settings page and paste the "+
				"whole PEM file, including the BEGIN and END lines"))
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

	// Rebuilt rather than forwarded so the payload the broker parses is one
	// this handler constructed: a client that sent extra fields cannot reach
	// ParseGitHubAppConnection's DisallowUnknownFields with them.
	payload, err := json.Marshal(map[string]any{
		"app_id":      json.RawMessage(appID),
		"private_key": req.PrivateKey,
		"base_url":    strings.TrimSpace(req.BaseURL),
	})
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "app_id is not a number"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), githubAppDiscoveryTimeout)
	defer cancel()
	installs, err := bs.secret.DiscoverGitHubAppInstallations(ctx, payload)
	if err != nil {
		// The broker's messages are written for this dialog — they name the
		// App, say when it is installed nowhere, and never quote the key.
		writeBrokerError(w, err, "discover GitHub App installations")
		return
	}

	out := make([]installationView, 0, len(installs))
	for _, in := range installs {
		out = append(out, installationView{
			ID:                  in.ID,
			AppID:               in.AppID,
			Account:             in.Account,
			AccountType:         in.AccountType,
			RepositorySelection: in.RepositorySelection,
		})
	}
	jsonOK(w, map[string]any{"installations": out})
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

// repositoryView is one repository an installation covers.
type repositoryView struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
}

// handleGitHubAppRepositories serves
// GET /api/projects/{idx}/repositories/available.
//
// The secret is named by ?secret=<id-or-name>. This is what turns assigning
// repositories into picking from a list: the names come from the installation's
// own inventory, so one that is offered is one GitHub has already confirmed the
// App can reach.
//
// It is scoped to a project rather than global, even though an installation's
// inventory is hub-wide, because the caller who needs it is the one about to
// assign from it. A binding pinned to a project never satisfies a global
// request — holding maintainer on one project must not confer it fleet-wide —
// so a global route here would have let a project's maintainer create the grant
// while refusing to show them the list they were choosing from.
func (s *Server) handleGitHubAppRepositories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Resolved for its authorization side effect: an index naming no visible
	// project is refused before any stored credential is opened.
	if _, ok := s.projectEntryFromPath(w, r); !ok {
		return
	}
	ref := strings.TrimSpace(r.URL.Query().Get("secret"))
	if ref == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"secret is required — name the stored github_app credential to enumerate"))
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

	ctx, cancel := context.WithTimeout(r.Context(), githubAppDiscoveryTimeout)
	defer cancel()
	repos, err := bs.secret.GitHubAppRepositories(ctx, ref)
	if err != nil {
		writeBrokerError(w, err, "list GitHub App repositories")
		return
	}
	out := make([]repositoryView, 0, len(repos))
	for _, rp := range repos {
		out = append(out, repositoryView{ID: rp.ID, FullName: rp.FullName, Private: rp.Private})
	}
	jsonOK(w, map[string]any{"repositories": out})
}

// ---------------------------------------------------------------------------
// Per-project assignment
// ---------------------------------------------------------------------------

// projectRepoAssignment is one live grant of repositories to a project.
type projectRepoAssignment struct {
	GrantID    string    `json:"grant_id"`
	SecretID   string    `json:"secret_id"`
	SecretName string    `json:"secret_name"`
	Kind       string    `json:"kind"`
	Repos      []string  `json:"repos"`
	Access     string    `json:"access"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
	CreatedBy  string    `json:"created_by,omitempty"`
}

// githubAppChoice is a stored App a caller may assign repositories from.
type githubAppChoice struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// handleProjectRepositories serves GET /api/projects/{idx}/repositories.
//
// It answers, for one project, both halves of the picture the assignment panel
// needs: which GitHub Apps this hub has, and which repositories the project can
// already reach through them.
func (s *Server) handleProjectRepositories(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.projectEntryFromPath(w, r)
	if !ok {
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

	secrets, err := bs.secret.ListSecrets()
	if err != nil {
		writeBrokerError(w, err, "list secrets")
		return
	}
	byID := make(map[string]secretbroker.Secret, len(secrets))
	apps := make([]githubAppChoice, 0, 4)
	for _, sec := range secrets {
		byID[sec.ID] = sec
		if sec.Kind == secretbroker.KindGitHubApp {
			apps = append(apps, githubAppChoice{ID: sec.ID, Name: sec.Name})
		}
	}

	grants, err := bs.secret.ListGrants(secretbroker.GrantFilter{ActiveOnly: true})
	if err != nil {
		writeBrokerError(w, err, "list grants")
		return
	}
	assignments := make([]projectRepoAssignment, 0, 4)
	for _, g := range grants {
		sec, known := byID[g.SecretID]
		if !known {
			continue
		}
		switch sec.Kind {
		case secretbroker.KindGitHubApp, secretbroker.KindGitHubPAT:
		default:
			continue
		}
		// Only grants issued to *this* project. A wildcard subject reaches it
		// too, and is shown, because an operator asking "what can this project
		// see" needs the honest answer rather than the narrow one.
		if !g.Subject.Matches(secretbroker.Requester{ProjectID: entry.Path}) {
			continue
		}
		assignments = append(assignments, projectRepoAssignment{
			GrantID:    g.ID,
			SecretID:   g.SecretID,
			SecretName: sec.Name,
			Kind:       string(sec.Kind),
			Repos:      g.Constraints.Repos,
			Access:     repoAccessLabel(g.Constraints),
			ExpiresAt:  g.ExpiresAt,
			CreatedAt:  g.CreatedAt,
			CreatedBy:  g.CreatedBy,
		})
	}

	jsonOK(w, map[string]any{
		"project":     entry.Name,
		"apps":        apps,
		"assignments": assignments,
	})
}

// assignRepositoriesRequest is what the assignment panel posts.
type assignRepositoriesRequest struct {
	Secret     string   `json:"secret"`
	Repos      []string `json:"repos"`
	Access     string   `json:"access"`
	TTLMinutes int      `json:"ttl_minutes,omitempty"`
}

// handleProjectRepositoriesAssign serves POST /api/projects/{idx}/repositories.
//
// It is a narrow front end to the same broker call POST /api/grants makes. The
// point of having it is that the general grant dialog asks for a subject, a
// kind, and a free-text constraint set, none of which a person assigning two
// repositories to a project should have to compose — and every one of which is
// a chance to widen the grant by accident. Here the subject is the project in
// the path, and access is one of two words.
func (s *Server) handleProjectRepositoriesAssign(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.projectEntryFromPath(w, r)
	if !ok {
		return
	}
	var req assignRepositoriesRequest
	if !decodeSecretsBody(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Secret) == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"secret is required — choose the GitHub App to grant from"))
		return
	}
	repos := make([]string, 0, len(req.Repos))
	for _, rp := range req.Repos {
		if t := strings.TrimSpace(rp); t != "" {
			repos = append(repos, t)
		}
	}
	if len(repos) == 0 {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"choose at least one repository — a grant with no allowlist would authorise nothing"))
		return
	}
	perms, err := repoAccessPermissions(req.Access)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
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

	grant, err := bs.secret.Grant(r.Context(), secretbroker.GrantRequest{
		SecretRef: strings.TrimSpace(req.Secret),
		// The subject is the project this route resolved, never a value from
		// the body: the caller's authority was checked against that project and
		// nothing else.
		Subject: secretbroker.Subject{
			Type:  secretbroker.SubjectProject,
			Value: entry.Path,
		},
		Constraints: secretbroker.Constraints{Repos: repos, Permissions: perms},
		TTL:         time.Duration(req.TTLMinutes) * time.Minute,
		Actor:       s.auditActor(r),
	})
	if err != nil {
		writeBrokerError(w, err, "grant repositories to project")
		return
	}

	s.broadcastAuditAppend(string(secretbroker.ActionGrant))
	s.broadcastSecretsUpdate("grant_created", grant.ID)
	jsonOK(w, projectRepoAssignment{
		GrantID:   grant.ID,
		SecretID:  grant.SecretID,
		Repos:     grant.Constraints.Repos,
		Access:    repoAccessLabel(grant.Constraints),
		ExpiresAt: grant.ExpiresAt,
		CreatedAt: grant.CreatedAt,
		CreatedBy: grant.CreatedBy,
	})
}

// handleProjectRepositoriesRevoke serves DELETE /api/projects/{idx}/repositories.
//
// The grant is named by ?grant=<id>. It is re-checked against this project
// before being revoked, so a grant ID belonging to another project cannot be
// revoked through an index the caller does happen to hold.
func (s *Server) handleProjectRepositoriesRevoke(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.projectEntryFromPath(w, r)
	if !ok {
		return
	}
	grantID := strings.TrimSpace(r.URL.Query().Get("grant"))
	if grantID == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "grant is required"))
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

	grants, err := bs.secret.ListGrants(secretbroker.GrantFilter{})
	if err != nil {
		writeBrokerError(w, err, "list grants")
		return
	}
	var found *secretbroker.Grant
	for i := range grants {
		if grants[i].ID == grantID {
			found = &grants[i]
			break
		}
	}
	if found == nil {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "no such grant"))
		return
	}
	// A wildcard grant reaches this project but is not *its* grant to revoke:
	// withdrawing it would silently cut off every other project too. Refused
	// here, with the reason, rather than in the Secrets panel's error text.
	if found.Subject.Type != secretbroker.SubjectProject || found.Subject.Value != entry.Path {
		apierror.WriteError(w, apierror.New(apierror.CodeForbidden,
			fmt.Sprintf("grant %s is not scoped to this project; revoke it from the Secrets panel",
				grantID)))
		return
	}

	if err := bs.secret.Revoke(r.Context(), grantID, s.auditActor(r)); err != nil {
		writeBrokerError(w, err, "revoke grant")
		return
	}
	s.broadcastAuditAppend(string(secretbroker.ActionRevoke))
	s.broadcastSecretsUpdate("grant_revoked", grantID)
	jsonOK(w, map[string]any{"ok": true, "grant_id": grantID})
}

// ---------------------------------------------------------------------------
// Access levels
// ---------------------------------------------------------------------------

// repoAccessPermissions maps the panel's two-word access level onto a GitHub
// permission set.
//
// Two words rather than a permission editor, because the choice that matters to
// the person assigning a repository is "may cloop push to it". The write set
// includes pull_requests so an agent can open one — a write-back that can
// commit but not propose is the shape nobody wants — and deliberately nothing
// else: no administration, no workflows, no secrets.
func repoAccessPermissions(access string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(access)) {
	case "", "read":
		return []string{"contents:read"}, nil
	case "write":
		return []string{"contents:write", "pull_requests:write"}, nil
	default:
		return nil, fmt.Errorf("access %q is not recognised (want read or write)", access)
	}
}

// repoAccessLabel is the inverse, for rendering an existing grant.
func repoAccessLabel(c secretbroker.Constraints) string {
	if c.AllowsPermission("contents:write") {
		return "write"
	}
	return "read"
}
