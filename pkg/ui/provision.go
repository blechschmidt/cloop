package ui

// provision.go turns "create a project" into "create a project that can reach
// the things it needs" (Task 20187).
//
// # The scenario
//
// A developer on a shared hub wants a project that builds against a particular
// Kubernetes cluster and three checkouts sitting on the machine, running in a
// sandbox rather than on the host. Every piece of that already existed —
// executor binding, kubeconfig grants, local_repo grants — and the developer
// still could not do it in one go. They had to create the project, switch to
// the Executors panel and find their project in a per-executor dropdown, then
// switch to Secrets and hand-type "project:/srv/projects/thing" as a grant
// subject, twice, without a typo. Three panels, one of them asking for a string
// the UI already knew.
//
// So the access travels with the creation request. What this file adds is not a
// new capability; it is the removal of a gap between capabilities that were
// each finished separately.
//
// # Why the RBAC is re-checked here
//
// POST /api/projects/new needs project.write. Binding an executor needs
// executor.manage and creating a grant needs secret.grant, and those are
// deliberately higher bars — they decide which machine sees your source and
// which credentials reach it. Accepting them as fields on a project.write route
// without re-checking would make this endpoint a way to mint grants that
// POST /api/grants would have refused, which is the classic shape of a
// privilege escalation: not a broken check, a route that never had one.
//
// Each optional section is therefore gated on its own permission, and only when
// the caller actually asks for it — a developer with plain project.write can
// still create an ordinary project.
//
// # Ordering and rollback
//
// Everything that can be validated is validated before anything is created,
// because the cheapest failure is the one that happens before there is state to
// undo. Past that point the sequence is: mkdir, init, bind, grant. Binding
// comes after init on purpose — init writes .cloop/ and must run where the hub
// can read it, not on the remote executor the project is about to be pinned to.
//
// On a failure after init, the grants and the binding are rolled back and the
// registry entry is dropped. The directory is not: this code did not
// necessarily create it, cannot tell whether the files in it predate the
// request, and deleting a developer's tree to tidy up a failed API call is a
// worse outcome than any it would be cleaning up after.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// projectAccessRequest is the access half of a project-creation request: where
// the project runs, and what it may reach from there.
//
// Grants are expressed the way a person picks them rather than the way the
// broker stores them — a secret by name, a cluster's contexts, a list of
// repository names — because the caller is a dialog, not an operator with the
// CLI's --to syntax memorised. The subject is not a field at all: it is always
// this project, which is the whole reason the request can be made here.
type projectAccessRequest struct {
	// ExecutorID pins the project to an executor. Empty leaves it on the
	// hub's default, which is the existing behaviour.
	ExecutorID string `json:"executor_id"`
	// Grants are the credentials the project should hold on creation.
	Grants []projectGrantRequest `json:"grants"`
}

// projectGrantRequest is one credential the new project should hold.
type projectGrantRequest struct {
	// SecretRef is the stored secret's name or ID.
	SecretRef string `json:"secret_ref"`
	// Scope is the operator's free-form label ("build", "deploy").
	Scope string `json:"scope"`
	// TTLMinutes is the grant's lifetime; 0 takes the API default.
	TTLMinutes int `json:"ttl_minutes"`

	// Constraint dimensions, each meaningful for some kinds and ignored for
	// others. ValidateFor is what decides which — see handleGrantCreate.
	Repos       []string `json:"repos"`
	Permissions []string `json:"permissions"`
	Namespaces  []string `json:"namespaces"`
	Contexts    []string `json:"contexts"`
	Hosts       []string `json:"hosts"`
	Registries  []string `json:"registries"`
	EnvKeys     []string `json:"env_keys"`
	Writable    bool     `json:"writable"`
}

// requested reports whether the caller asked for anything at all here, so an
// ordinary creation skips every permission check and database open below.
func (a projectAccessRequest) requested() bool {
	return strings.TrimSpace(a.ExecutorID) != "" || len(a.Grants) > 0
}

// authorizeProjectAccess checks the caller may do each thing they asked for,
// writing the refusal itself when they may not.
//
// Called before the project directory is touched. A developer who is allowed to
// create projects but not to grant secrets finds out now, with nothing created,
// rather than after an init they would have to clean up.
func (s *Server) authorizeProjectAccess(w http.ResponseWriter, r *http.Request, a projectAccessRequest) bool {
	if strings.TrimSpace(a.ExecutorID) != "" {
		if !s.require(w, r, authz.PermExecutorManage, authz.GlobalScope) {
			return false
		}
	}
	if len(a.Grants) > 0 {
		if !s.require(w, r, authz.PermSecretGrant, authz.GlobalScope) {
			return false
		}
	}
	return true
}

// validateProjectAccess checks everything that can be known before the project
// exists: that the executor is real and permitted, and that each grant names a
// secret and carries constraints that gate its kind.
//
// This is where the "straightforward" in the task lives. Without it, a
// mistyped cluster context or a secret name that does not exist would be
// discovered after the directory, the init and the registry entry had all
// happened, and the developer would be left holding a half-provisioned project
// and a 500.
func validateProjectAccess(bs *brokerSet, a projectAccessRequest) error {
	if id := strings.TrimSpace(a.ExecutorID); id != "" {
		ex, err := executor.Get(id)
		if err != nil {
			return fmt.Errorf("executor %q is not available on this control plane: %w", id, err)
		}
		if blocked, reason := blockedFor(ex); blocked {
			return fmt.Errorf("executor %q cannot be used: %s", id, reason)
		}
	}
	if len(a.Grants) == 0 {
		return nil
	}
	if bs == nil || bs.secret == nil {
		return fmt.Errorf("the secret broker is not configured on this hub, so grants cannot be created")
	}
	for i, g := range a.Grants {
		ref := strings.TrimSpace(g.SecretRef)
		if ref == "" {
			return fmt.Errorf("grants[%d]: secret_ref is required", i)
		}
		sec, err := bs.secret.DescribeSecret(ref)
		if err != nil {
			return fmt.Errorf("grants[%d]: %w", i, err)
		}
		// ValidateFor is the single definition of "do these constraints gate
		// this kind"; calling it here rather than restating the rules means a
		// new kind's requirements are enforced on this path the day they are
		// written, without anyone remembering to come back.
		if err := g.constraints().ValidateFor(sec.Kind); err != nil {
			return fmt.Errorf("grants[%d] (%s %q): %w", i, sec.Kind, sec.Name, err)
		}
		if _, err := grantTTL(g.TTLMinutes); err != nil {
			return fmt.Errorf("grants[%d]: %w", i, err)
		}
	}
	return nil
}

// constraints projects the request onto the broker's shape.
func (g projectGrantRequest) constraints() secretbroker.Constraints {
	return secretbroker.Constraints{
		Repos:       cleanList(g.Repos),
		Permissions: cleanList(g.Permissions),
		Namespaces:  cleanList(g.Namespaces),
		Contexts:    cleanList(g.Contexts),
		Hosts:       cleanList(g.Hosts),
		Registries:  cleanList(g.Registries),
		EnvKeys:     cleanList(g.EnvKeys),
		Writable:    g.Writable,
	}
}

// applyProjectAccess binds the executor and creates the grants for a project
// that now exists.
//
// It returns a rollback function alongside the error so the caller can undo a
// partial application. The rollback is returned even on success, because the
// caller may still fail afterwards — registering the project, for instance —
// and a project that failed to be created should not leave live grants behind
// naming a path nobody can see.
func (s *Server) applyProjectAccess(r *http.Request, bs *brokerSet, projectPath string, a projectAccessRequest) (rollback func(), err error) {
	var undo []func()
	rollback = func() {
		// Reverse order: the binding was made first, so it is undone last.
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}

	actor := s.auditActor(r)

	if id := strings.TrimSpace(a.ExecutorID); id != "" {
		db, dbErr := s.controlPlaneDB()
		if dbErr != nil {
			return rollback, fmt.Errorf("bind executor: %w", dbErr)
		}
		defer db.Close()

		if bindErr := db.BindProjectExecutor(projectPath, id, s.sessionIdentity(r).OwnerKey()); bindErr != nil {
			return rollback, fmt.Errorf("bind executor %s: %w", id, bindErr)
		}
		undo = append(undo, func() {
			// A fresh handle, deliberately: this closure runs in the caller,
			// after the deferred Close above has already fired. Capturing db
			// would make every rollback a no-op against a closed database and
			// leave the binding behind — so a later project at the same path
			// would silently inherit an executor nobody chose.
			db2, dbErr := s.controlPlaneDB()
			if dbErr != nil {
				fmt.Fprintf(os.Stderr, "ui: rollback unbind %s: reopen: %v\n", projectPath, dbErr)
			} else {
				defer db2.Close()
				if uErr := db2.UnbindProjectExecutor(projectPath); uErr != nil {
					fmt.Fprintf(os.Stderr, "ui: rollback unbind %s: %v\n", projectPath, uErr)
				}
			}
			executor.DefaultRegistry.Unbind(projectPath)
		})
		// Mirror into the in-memory registry so the first run honours it
		// without waiting for the persistent lookup's next read.
		if memErr := executor.Bind(projectPath, id); memErr != nil {
			fmt.Fprintf(os.Stderr, "ui: in-memory bind of %s to %s: %v\n", projectPath, id, memErr)
		}
		// Where a project's code runs is the most consequential setting on
		// this hub, and it is no less so for having been chosen in the
		// creation dialog rather than the Executors panel.
		statedb.AuditExecutorLifecycle(db, statedb.ExecutorAuditInput{
			Action:     "bind",
			ExecutorID: id,
			Actor:      actor,
			Detail: map[string]any{
				"project_path": projectPath,
				"via":          "project-new",
			},
		})
	}

	subject := secretbroker.Subject{
		Type:  secretbroker.SubjectProject,
		Value: secretbroker.NormalizeProjectID(projectPath),
	}
	for i, g := range a.Grants {
		ttl, ttlErr := grantTTL(g.TTLMinutes)
		if ttlErr != nil {
			return rollback, fmt.Errorf("grants[%d]: %w", i, ttlErr)
		}
		grant, gErr := bs.secret.Grant(r.Context(), secretbroker.GrantRequest{
			SecretRef:   strings.TrimSpace(g.SecretRef),
			Subject:     subject,
			Scope:       strings.TrimSpace(g.Scope),
			TTL:         ttl,
			Actor:       actor,
			Constraints: g.constraints(),
		})
		if gErr != nil {
			return rollback, fmt.Errorf("grants[%d] (%s): %w", i, g.SecretRef, gErr)
		}
		id := grant.ID
		undo = append(undo, func() {
			if rErr := bs.secret.Revoke(context.WithoutCancel(r.Context()), id, actor); rErr != nil {
				fmt.Fprintf(os.Stderr, "ui: rollback revoke grant %s: %v\n", id, rErr)
			}
		})
	}
	return rollback, nil
}
