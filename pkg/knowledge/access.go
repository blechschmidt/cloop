package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Access is a Service acting for one principal. Who may do what:
//
//	list or read sources     knowledge.admin: every source. secret.own: the
//	                         organisation's, and their own personal ones.
//	create, change, delete   an org source: knowledge.admin. A personal one:
//	                         its owner (secret.own); an admin may delete one,
//	                         never change it — changing where it points would
//	                         send its owner's credential somewhere else.
//	bind to a project        project.write on the project, and the source is
//	                         the organisation's and the caller holds
//	                         knowledge.admin, or it is the caller's own.
//	unbind                   project.write on the project.
//	search, list bound ones  project.read on the project.
//
// A source the caller may not see is reported not found, never forbidden, so
// that whether someone else's personal source exists is not an answer.
type Access struct {
	s *Service
	p Principal
}

// Principal returns who this Access acts for.
func (a *Access) Principal() Principal { return a.p }

// Service returns the Service this Access acts through.
func (a *Access) Service() *Service { return a.s }

func (a *Access) isAdmin() bool { return a.p.allows(authz.PermKnowledgeAdmin, authz.GlobalScope) }

func (a *Access) mayOwn() bool { return a.p.allows(authz.PermSecretOwn, authz.GlobalScope) }

// owns reports whether row is the caller's own personal source.
func (a *Access) owns(row statedb.KnowledgeSourceRow) bool {
	return row.Scope == ScopePersonal && a.p.Identity != "" && row.Owner == a.p.Identity && a.mayOwn()
}

// canSee reports whether the caller may know row exists.
func (a *Access) canSee(row statedb.KnowledgeSourceRow) bool {
	switch {
	case a.isAdmin():
		return true
	case row.Scope == ScopePersonal:
		return a.owns(row)
	}
	return a.mayOwn()
}

// CanManage reports whether the caller may change src: its configuration, its
// credential reference, its bindings. The hub shows a source's secret
// reference only to a caller who can.
func (a *Access) CanManage(src Source) bool {
	return a.canManage(statedb.KnowledgeSourceRow{Scope: src.Scope, Owner: src.Owner})
}

func (a *Access) canManage(row statedb.KnowledgeSourceRow) bool {
	if row.Scope == ScopePersonal {
		return a.owns(row)
	}
	return a.isAdmin()
}

// manageDenied explains why the caller may not change row, which it can see.
func (a *Access) manageDenied(row statedb.KnowledgeSourceRow, verb string) error {
	if row.Scope == ScopePersonal {
		return forbidden(authz.PermSecretOwn, "only %s may %s a personal source", row.Owner, verb)
	}
	return forbidden(authz.PermKnowledgeAdmin, "only an administrator may %s an organisation source", verb)
}

// visible returns source id if the caller may see it, else ErrNotFound.
func (a *Access) visible(id int64) (statedb.KnowledgeSourceRow, error) {
	row, err := a.s.db.GetKnowledgeSource(id)
	if errors.Is(err, statedb.ErrKnowledgeSourceNotFound) {
		return row, fmt.Errorf("%w: source %d", ErrNotFound, id)
	}
	if err != nil {
		return row, err
	}
	if !a.canSee(row) {
		return row, fmt.Errorf("%w: source %d", ErrNotFound, id)
	}
	return row, nil
}

func sourceFromRow(row statedb.KnowledgeSourceRow) Source {
	return Source{
		ID: row.ID, Kind: row.Kind, Name: row.Name, Scope: row.Scope, Owner: row.Owner,
		Config: json.RawMessage(row.Config), SecretRef: row.SecretRef, Enabled: row.Enabled,
		Sync: SyncState{
			Status: row.SyncStatus, Error: row.SyncError, At: row.SyncedAt, Resumes: row.SyncCursor != "",
			ReconciledAt: row.ReconciledAt,
		},
		CreatedAt: row.CreatedAt, CreatedBy: row.CreatedBy, UpdatedAt: row.UpdatedAt, UpdatedBy: row.UpdatedBy,
	}
}

func bindingFromRow(row statedb.KnowledgeBindingRow) Binding {
	return Binding{
		ID: row.ID, SourceID: row.SourceID, Project: row.ProjectPath,
		Filter:     Filter{Spaces: row.Spaces, Query: row.Query},
		NarrowedAt: row.NarrowedAt,
		CreatedAt:  row.CreatedAt, CreatedBy: row.CreatedBy, UpdatedAt: row.UpdatedAt, UpdatedBy: row.UpdatedBy,
	}
}

// requireListing refuses a caller who may connect no source at all.
func (a *Access) requireListing() error {
	if a.isAdmin() || a.mayOwn() {
		return nil
	}
	return forbidden(authz.PermSecretOwn, "listing knowledge sources is for the people who connect them")
}

// Sources lists the sources the caller may see, with what each holds.
func (a *Access) Sources(ctx context.Context) ([]Source, error) {
	if err := a.requireListing(); err != nil {
		return nil, err
	}
	rows, err := a.s.db.ListKnowledgeSources()
	if err != nil {
		return nil, err
	}
	counts, err := a.s.db.CountKnowledge()
	if err != nil {
		return nil, err
	}
	out := []Source{}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !a.canSee(row) {
			continue
		}
		src := sourceFromRow(row)
		c := counts[row.ID]
		src.Counts = Counts{Documents: c.Documents, Chunks: c.Chunks, Bindings: c.Bindings}
		out = append(out, src)
	}
	return out, nil
}

// Source returns one source, and — to a caller who may manage it — its
// bindings.
func (a *Access) Source(ctx context.Context, id int64) (Source, []Binding, error) {
	if err := a.requireListing(); err != nil {
		return Source{}, nil, err
	}
	row, err := a.visible(id)
	if err != nil {
		return Source{}, nil, err
	}
	src := sourceFromRow(row)
	counts, err := a.s.db.CountKnowledge(row.ID)
	if err != nil {
		return Source{}, nil, err
	}
	c := counts[row.ID]
	src.Counts = Counts{Documents: c.Documents, Chunks: c.Chunks, Bindings: c.Bindings}
	if !a.canManage(row) && !a.isAdmin() {
		// Where a source is bound names projects; a caller who cannot manage
		// the source may not be able to see them.
		return src, nil, ctx.Err()
	}
	rows, err := a.s.db.ListKnowledgeBindings(statedb.KnowledgeBindingFilter{SourceID: id})
	if err != nil {
		return Source{}, nil, err
	}
	bindings := make([]Binding, 0, len(rows))
	for _, b := range rows {
		bindings = append(bindings, bindingFromRow(b))
	}
	return src, bindings, ctx.Err()
}

// SourceInput is a new source.
type SourceInput struct {
	Kind string
	Name string
	// Scope is ScopeOrg or ScopePersonal; empty means personal for a caller
	// with an identity to own it, and org otherwise — the direction that, if
	// it is wrong, shares the source with one person too few.
	Scope     string
	Config    json.RawMessage
	SecretRef string
	// Enabled defaults to true.
	Enabled *bool
}

// CreateSource connects a new source.
func (a *Access) CreateSource(ctx context.Context, in SourceInput) (Source, error) {
	scope := strings.TrimSpace(in.Scope)
	if scope == "" {
		scope = ScopeOrg
		if a.p.Identity != "" {
			scope = ScopePersonal
		}
	}
	owner := ""
	switch scope {
	case ScopeOrg:
		if !a.isAdmin() {
			return Source{}, forbidden(authz.PermKnowledgeAdmin, "only an administrator may connect an organisation source")
		}
	case ScopePersonal:
		if a.p.Identity == "" {
			return Source{}, invalid("a personal source needs a signed-in person to own it; this request has none, " +
				"so connect an organisation source instead")
		}
		if !a.mayOwn() {
			return Source{}, forbidden(authz.PermSecretOwn, "connecting a personal source needs secret.own")
		}
		owner = a.p.Identity
	default:
		return Source{}, invalid("a source's scope is %q or %q", ScopeOrg, ScopePersonal)
	}
	name, err := cleanName(in.Name)
	if err != nil {
		return Source{}, err
	}
	kind := strings.TrimSpace(in.Kind)
	conn, ok := a.s.registry.Lookup(kind)
	if !ok {
		return Source{}, a.unknownKind(kind)
	}
	config, err := a.s.validateConfig(conn, scope, in.Config)
	if err != nil {
		return Source{}, err
	}
	ref, err := a.s.checkSecretRef(in.SecretRef, owner)
	if err != nil {
		return Source{}, err
	}
	enabled := in.Enabled == nil || *in.Enabled
	if err := ctx.Err(); err != nil {
		return Source{}, err
	}
	row, err := a.s.db.CreateKnowledgeSource(statedb.KnowledgeSourceRow{
		Kind: kind, Name: name, Scope: scope, Owner: owner, Config: string(config), SecretRef: ref, Enabled: enabled,
	}, a.p.Actor)
	if errors.Is(err, statedb.ErrKnowledgeSourceNameTaken) {
		return Source{}, fmt.Errorf("%w: a source named %q already exists", ErrConflict, name)
	}
	if err != nil {
		return Source{}, err
	}
	return sourceFromRow(row), nil
}

func (a *Access) unknownKind(kind string) error {
	kinds := a.s.registry.Kinds()
	if len(kinds) == 0 {
		return fmt.Errorf("%w: there is no connector of kind %q, and this build has no connectors registered",
			ErrUnavailable, kind)
	}
	return invalid("there is no connector of kind %q; this build has %s", kind, strings.Join(kinds, ", "))
}

// validateConfig runs the framework's checks, then the connector's, for a
// source of scope.
func (s *Service) validateConfig(conn Connector, scope string, raw json.RawMessage) (json.RawMessage, error) {
	config, err := cleanConfig(raw)
	if err != nil {
		return nil, err
	}
	if err := conn.Validate(ValidateRequest{Config: config, Scope: scope}); err != nil {
		if errors.Is(err, ErrInvalid) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %s configuration: %v", ErrInvalid, conn.Kind(), err)
	}
	return config, nil
}

// checkSecretRef checks a reference's shape and that a source of owner may
// sign in with it.
func (s *Service) checkSecretRef(raw, owner string) (string, error) {
	ref, err := cleanSecretRef(raw)
	if err != nil || ref == "" {
		return ref, err
	}
	if s.credentials == nil {
		return "", fmt.Errorf("%w: this hub has no secret store, so a source cannot name a secret to sign in with",
			ErrUnavailable)
	}
	if err := s.credentials.CheckSourceCredential(ref, owner); err != nil {
		return "", fmt.Errorf("%w: secret reference %q: %v", ErrInvalid, ref, err)
	}
	return ref, nil
}

// SourceUpdate is a change to a source; a nil field is left as it is.
type SourceUpdate struct {
	Name      *string
	Config    json.RawMessage
	SecretRef *string
	Enabled   *bool
}

// UpdateSource changes a source. A new configuration makes the next sync list
// the source from the beginning.
func (a *Access) UpdateSource(ctx context.Context, id int64, in SourceUpdate) (Source, error) {
	if err := a.requireListing(); err != nil {
		return Source{}, err
	}
	row, err := a.visible(id)
	if err != nil {
		return Source{}, err
	}
	if !a.canManage(row) {
		return Source{}, a.manageDenied(row, "change")
	}
	u := statedb.KnowledgeSourceUpdate{Name: row.Name, Config: row.Config, SecretRef: row.SecretRef, Enabled: row.Enabled,
		ExpectUpdatedAt: row.UpdatedAt}
	if in.Name != nil {
		name, err := cleanName(*in.Name)
		if err != nil {
			return Source{}, err
		}
		if name != row.Name {
			u.Name = name
			u.Changed = append(u.Changed, "name")
		}
	}
	if in.Config != nil {
		conn, ok := a.s.registry.Lookup(row.Kind)
		if !ok {
			return Source{}, a.unknownKind(row.Kind)
		}
		config, err := a.s.validateConfig(conn, row.Scope, in.Config)
		if err != nil {
			return Source{}, err
		}
		if string(config) != row.Config {
			u.Config = string(config)
			u.Changed = append(u.Changed, "config")
			u.Resync = true
		}
	}
	if in.SecretRef != nil {
		ref, err := cleanSecretRef(*in.SecretRef)
		if err != nil {
			return Source{}, err
		}
		if ref != row.SecretRef {
			if ref, err = a.s.checkSecretRef(ref, row.Owner); err != nil {
				return Source{}, err
			}
			u.SecretRef = ref
			u.Changed = append(u.Changed, "secret_ref")
		}
	}
	if in.Enabled != nil && *in.Enabled != row.Enabled {
		u.Enabled = *in.Enabled
		u.Changed = append(u.Changed, "enabled")
	}
	if len(u.Changed) == 0 {
		return sourceFromRow(row), nil
	}
	if err := ctx.Err(); err != nil {
		return Source{}, err
	}
	updated, err := a.s.db.UpdateKnowledgeSource(id, u, a.p.Actor)
	switch {
	case errors.Is(err, statedb.ErrKnowledgeSourceNameTaken):
		return Source{}, fmt.Errorf("%w: a source named %q already exists", ErrConflict, u.Name)
	case errors.Is(err, statedb.ErrKnowledgeSourceChanged):
		return Source{}, fmt.Errorf("%w: the source changed while this change was being made; read it again "+
			"and make the change on what it is now", ErrConflict)
	case errors.Is(err, statedb.ErrKnowledgeSourceNotFound):
		return Source{}, fmt.Errorf("%w: source %d", ErrNotFound, id)
	case err != nil:
		return Source{}, err
	}
	return sourceFromRow(updated), nil
}

// DeleteSource removes a source and everything it indexed.
func (a *Access) DeleteSource(ctx context.Context, id int64) (Source, Counts, error) {
	if err := a.requireListing(); err != nil {
		return Source{}, Counts{}, err
	}
	row, err := a.visible(id)
	if err != nil {
		return Source{}, Counts{}, err
	}
	if !a.canManage(row) && !(row.Scope == ScopePersonal && a.isAdmin()) {
		return Source{}, Counts{}, a.manageDenied(row, "delete")
	}
	if err := ctx.Err(); err != nil {
		return Source{}, Counts{}, err
	}
	deleted, c, err := a.s.db.DeleteKnowledgeSource(id, a.p.Actor)
	if errors.Is(err, statedb.ErrKnowledgeSourceNotFound) {
		return Source{}, Counts{}, fmt.Errorf("%w: source %d", ErrNotFound, id)
	}
	if err != nil {
		return Source{}, Counts{}, err
	}
	return sourceFromRow(deleted), Counts{Documents: c.Documents, Chunks: c.Chunks, Bindings: c.Bindings}, nil
}

// requireProject refuses a caller without perm on project: not found when
// they cannot read it at all, forbidden when they can.
func (a *Access) requireProject(project Project, perm authz.Permission) error {
	if strings.TrimSpace(project.Path) == "" {
		return invalid("a project is named by its path")
	}
	scope := project.scope()
	if a.p.allows(perm, scope) {
		return nil
	}
	if !a.p.allows(authz.PermProjectRead, scope) {
		return fmt.Errorf("%w: project", ErrNotFound)
	}
	return forbidden(perm, "your role on this project does not permit it")
}

// Bind makes source sourceID searchable from project, narrowed by f, or
// changes the narrowing of the binding the pair has. created reports which.
func (a *Access) Bind(ctx context.Context, project Project, sourceID int64, f Filter) (Binding, bool, error) {
	if err := a.requireProject(project, authz.PermProjectWrite); err != nil {
		return Binding{}, false, err
	}
	row, err := a.s.db.GetKnowledgeSource(sourceID)
	if errors.Is(err, statedb.ErrKnowledgeSourceNotFound) || (err == nil && !a.canSee(row)) {
		return Binding{}, false, fmt.Errorf("%w: source %d", ErrNotFound, sourceID)
	}
	if err != nil {
		return Binding{}, false, err
	}
	if !a.canManage(row) {
		return Binding{}, false, a.manageDenied(row, "bind")
	}
	f, err = cleanFilter(f)
	if err != nil {
		return Binding{}, false, err
	}
	if f.Query != "" {
		conn, ok := a.s.registry.Lookup(row.Kind)
		if !ok {
			return Binding{}, false, a.unknownKind(row.Kind)
		}
		narrower, ok := conn.(QueryNarrower)
		if !ok {
			return Binding{}, false, invalid("a %s source cannot be narrowed by a query; narrow it by spaces", row.Kind)
		}
		if err := narrower.ValidateQuery(json.RawMessage(row.Config), f.Query); err != nil {
			return Binding{}, false, fmt.Errorf("%w: query: %v", ErrInvalid, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return Binding{}, false, err
	}
	b, created, err := a.s.db.PutKnowledgeBinding(statedb.KnowledgeBindingRow{
		SourceID: sourceID, ProjectPath: project.Path, Spaces: f.Spaces, Query: f.Query,
	}, a.p.Actor)
	if errors.Is(err, statedb.ErrKnowledgeSourceNotFound) {
		return Binding{}, false, fmt.Errorf("%w: source %d", ErrNotFound, sourceID)
	}
	if err != nil {
		return Binding{}, false, err
	}
	return bindingFromRow(b), created, nil
}

// Unbind takes binding bindingID away from project.
func (a *Access) Unbind(ctx context.Context, project Project, bindingID int64) (Binding, error) {
	if err := a.requireProject(project, authz.PermProjectWrite); err != nil {
		return Binding{}, err
	}
	b, err := a.s.db.GetKnowledgeBinding(bindingID)
	if errors.Is(err, statedb.ErrKnowledgeBindingNotFound) || (err == nil && b.ProjectPath != project.Path) {
		return Binding{}, fmt.Errorf("%w: binding %d", ErrNotFound, bindingID)
	}
	if err != nil {
		return Binding{}, err
	}
	if err := ctx.Err(); err != nil {
		return Binding{}, err
	}
	deleted, err := a.s.db.DeleteKnowledgeBinding(bindingID, a.p.Actor)
	if errors.Is(err, statedb.ErrKnowledgeBindingNotFound) {
		return Binding{}, fmt.Errorf("%w: binding %d", ErrNotFound, bindingID)
	}
	if err != nil {
		return Binding{}, err
	}
	return bindingFromRow(deleted), nil
}

// ForgetProject removes every binding of project, for a project leaving the
// hub: bindings are keyed by its path, and must not serve whatever is
// registered there next. It takes project.write, which removing the project
// already did, and returns how many bindings went.
func (a *Access) ForgetProject(ctx context.Context, project Project) (int, error) {
	if err := a.requireProject(project, authz.PermProjectWrite); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return a.s.db.DeleteKnowledgeBindingsOfProject(project.Path, a.p.Actor, "the project was removed from the hub")
}

// BoundSource is a source as a project's members see it: what it is and how
// it is doing, without its configuration or credential reference.
type BoundSource struct {
	Source  Source
	Binding Binding
}

// ProjectSources lists the sources bound to project.
func (a *Access) ProjectSources(ctx context.Context, project Project) ([]BoundSource, error) {
	if err := a.requireProject(project, authz.PermProjectRead); err != nil {
		return nil, err
	}
	rows, err := a.s.db.ListKnowledgeBindings(statedb.KnowledgeBindingFilter{ProjectPath: project.Path})
	if err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(rows))
	for _, b := range rows {
		ids = append(ids, b.SourceID)
	}
	counts := map[int64]statedb.KnowledgeSourceCounts{}
	if len(ids) > 0 {
		if counts, err = a.s.db.CountKnowledge(ids...); err != nil {
			return nil, err
		}
	}
	out := []BoundSource{}
	for _, b := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row, err := a.s.db.GetKnowledgeSource(b.SourceID)
		if errors.Is(err, statedb.ErrKnowledgeSourceNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		src := sourceFromRow(row)
		src.Config, src.SecretRef = nil, ""
		c := counts[row.ID]
		src.Counts = Counts{Documents: c.Documents, Chunks: c.Chunks, Bindings: c.Bindings}
		out = append(out, BoundSource{Source: src, Binding: bindingFromRow(b)})
	}
	return out, nil
}

// Search bounds. A search reads one shared index, so its cost is everyone's.
const (
	// searchTimeout bounds one search; SQLite is interrupted past it.
	searchTimeout = 10 * time.Second
	// maxConcurrentSearches bounds the searches one hub process runs at once.
	maxConcurrentSearches = 8
)

// searchSlots holds a token for each search in progress in this process.
var searchSlots = make(chan struct{}, maxConcurrentSearches)

// Search returns the k chunks of project's knowledge that best match query,
// best first: only sources bound to project, through each binding's
// narrowing. k <= 0 means DefaultResults; more than MaxResults is cut to it.
//
// A hit says where it ranks, never its BM25 score. FTS5 weighs a term by how
// rare it is across the whole index — every project's sources — so a score,
// read against a chunk the caller can see, would tell them how often a word
// occurs in knowledge bound only to other projects.
func (a *Access) Search(ctx context.Context, project Project, query string, k int) ([]Hit, error) {
	if err := a.requireProject(project, authz.PermProjectRead); err != nil {
		return nil, err
	}
	match, err := MatchExpression(query)
	if err != nil {
		return nil, err
	}
	if k <= 0 {
		k = DefaultResults
	}
	k = min(k, MaxResults)
	ctx, cancel := context.WithTimeout(ctx, searchTimeout)
	defer cancel()
	select {
	case searchSlots <- struct{}{}:
		defer func() { <-searchSlots }()
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: the hub is busy with other searches; try again", ErrUnavailable)
	}
	rows, err := a.s.db.SearchKnowledge(ctx, statedb.KnowledgeSearchQuery{
		ProjectPath: project.Path, Match: match, Limit: k,
		SnippetOpen: SnippetOpen, SnippetClose: SnippetClose, SnippetEllipsis: SnippetEllipsis, SnippetTokens: 32,
	})
	switch {
	case errors.Is(err, statedb.ErrKnowledgeQuery):
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	case err != nil && ctx.Err() != nil:
		return nil, fmt.Errorf("%w: the search took longer than %s; narrow the query", ErrUnavailable, searchTimeout)
	case err != nil:
		return nil, err
	}
	out := make([]Hit, 0, len(rows))
	for i, r := range rows {
		snippet := r.Snippet
		if strings.TrimSpace(snippet) == "" {
			snippet = r.Title
		}
		out = append(out, Hit{
			ChunkID: r.ChunkID, DocumentID: r.DocumentID,
			Source: SourceRef{ID: r.SourceID, Name: r.SourceName, Kind: r.SourceKind},
			Title:  r.Title, URL: r.URL, Space: r.SpaceKey, ExternalID: r.ExternalID, Heading: r.Heading,
			Ancestors: r.Ancestors, Snippet: snippet, Rank: i + 1, Ordinal: r.Ordinal,
		})
	}
	return out, nil
}
