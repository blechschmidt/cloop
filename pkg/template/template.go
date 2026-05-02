// Package template provides a built-in library of project templates for cloop init.
// Templates pre-populate goal and tasks, skipping AI decomposition.
package template

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// TemplateTask describes a single task within a template.
type TemplateTask struct {
	Title            string
	Description      string
	Priority         int
	Role             pm.AgentRole
	DependsOn        []int // 1-based indices into the template task list
	EstimatedMinutes int
}

// Template is a named, reusable project scaffold.
type Template struct {
	Name        string
	Description string
	Goal        string
	Tasks       []TemplateTask
}

// ToPlan converts the template into a pm.Plan ready for execution.
func (t *Template) ToPlan() *pm.Plan {
	plan := pm.NewPlan(t.Goal)
	for i, tt := range t.Tasks {
		task := &pm.Task{
			ID:               i + 1,
			Title:            tt.Title,
			Description:      tt.Description,
			Priority:         tt.Priority,
			Status:           pm.TaskPending,
			Role:             tt.Role,
			DependsOn:        tt.DependsOn,
			EstimatedMinutes: tt.EstimatedMinutes,
		}
		plan.Tasks = append(plan.Tasks, task)
	}
	return plan
}

// registry holds all built-in templates by name.
var registry = map[string]*Template{}

func register(t *Template) {
	registry[t.Name] = t
}

func init() {
	register(webApp)
	register(cliTool)
	register(dataPipeline)
	register(apiService)
	register(refactor)
	register(securityAudit)
}

// Get returns the named template, or an error if not found.
func Get(name string) (*Template, error) {
	t, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown template %q — run 'cloop templates' to list available templates", name)
	}
	return t, nil
}

// All returns all built-in templates in a stable order.
func All() []*Template {
	names := []string{"web-app", "cli-tool", "data-pipeline", "api-service", "refactor", "security-audit"}
	out := make([]*Template, 0, len(names))
	for _, n := range names {
		if t, ok := registry[n]; ok {
			out = append(out, t)
		}
	}
	return out
}

// Names returns just the template names.
func Names() []string {
	all := All()
	names := make([]string, len(all))
	for i, t := range all {
		names[i] = t.Name
	}
	return names
}

// NamesString returns a comma-separated list of template names for help text.
func NamesString() string {
	return strings.Join(Names(), ", ")
}

// ─── Built-in templates ───────────────────────────────────────────────────────

var webApp = &Template{
	Name:        "web-app",
	Description: "Full-stack web application with frontend, backend, database, and deployment",
	Goal:        "Build a full-stack web application with a responsive frontend, REST API backend, relational database, and production deployment",
	Tasks: []TemplateTask{
		{
			Title:            "Set up project structure and tooling",
			Description:      "Initialise the repository layout, dependency manifests, linters, formatters, and shared configuration files for both frontend and backend.",
			Priority:         1,
			Role:             pm.RoleDevOps,
			EstimatedMinutes: 30,
		},
		{
			Title:            "Implement database schema and migrations",
			Description:      "Design and create the relational schema, write migration scripts, and seed development data. Document the entity-relationship model.",
			Priority:         2,
			Role:             pm.RoleData,
			DependsOn:        []int{1},
			EstimatedMinutes: 60,
		},
		{
			Title:            "Build REST API backend",
			Description:      "Implement CRUD endpoints, request validation, error handling, and middleware (auth, logging, CORS). Write OpenAPI/Swagger docs.",
			Priority:         3,
			Role:             pm.RoleBackend,
			DependsOn:        []int{2},
			EstimatedMinutes: 120,
		},
		{
			Title:            "Develop frontend UI",
			Description:      "Create responsive pages/components that consume the API. Implement routing, state management, and form validation. Ensure accessibility (WCAG AA).",
			Priority:         4,
			Role:             pm.RoleFrontend,
			DependsOn:        []int{3},
			EstimatedMinutes: 120,
		},
		{
			Title:            "Write tests (unit + integration + e2e)",
			Description:      "Add unit tests for business logic, integration tests for API endpoints, and end-to-end tests for critical user flows. Target >80% coverage.",
			Priority:         5,
			Role:             pm.RoleTesting,
			DependsOn:        []int{3, 4},
			EstimatedMinutes: 90,
		},
		{
			Title:            "Set up CI/CD pipeline and deployment",
			Description:      "Configure GitHub Actions (or equivalent) for build/test/deploy. Containerise with Docker. Write deployment runbook and environment variable docs.",
			Priority:         6,
			Role:             pm.RoleDevOps,
			DependsOn:        []int{5},
			EstimatedMinutes: 60,
		},
	},
}

var cliTool = &Template{
	Name:        "cli-tool",
	Description: "Command-line tool with core logic, tests, documentation, and release pipeline",
	Goal:        "Build a polished, well-tested CLI tool with comprehensive documentation and automated release packaging",
	Tasks: []TemplateTask{
		{
			Title:            "Design CLI interface and argument schema",
			Description:      "Define commands, subcommands, flags, and output formats. Write a brief UX spec covering help text, error messages, and exit codes.",
			Priority:         1,
			Role:             pm.RoleBackend,
			EstimatedMinutes: 30,
		},
		{
			Title:            "Implement core functionality",
			Description:      "Build the main business logic behind each command. Keep I/O concerns separate from logic so the core is unit-testable.",
			Priority:         2,
			Role:             pm.RoleBackend,
			DependsOn:        []int{1},
			EstimatedMinutes: 120,
		},
		{
			Title:            "Write unit and integration tests",
			Description:      "Cover all command paths, error cases, and edge conditions. Use table-driven tests where appropriate. Run tests in CI.",
			Priority:         3,
			Role:             pm.RoleTesting,
			DependsOn:        []int{2},
			EstimatedMinutes: 60,
		},
		{
			Title:            "Write documentation (README, man page, examples)",
			Description:      "Create a comprehensive README with installation, quickstart, and full command reference. Add example scripts and a CONTRIBUTING guide.",
			Priority:         4,
			Role:             pm.RoleDocs,
			DependsOn:        []int{2},
			EstimatedMinutes: 45,
		},
		{
			Title:            "Set up release pipeline",
			Description:      "Configure goreleaser (or equivalent) to build cross-platform binaries, generate changelogs, and publish GitHub Releases. Add Homebrew/Scoop tap if applicable.",
			Priority:         5,
			Role:             pm.RoleDevOps,
			DependsOn:        []int{3, 4},
			EstimatedMinutes: 45,
		},
	},
}

var dataPipeline = &Template{
	Name:        "data-pipeline",
	Description: "Data pipeline with ingestion, transformation, validation, and export stages",
	Goal:        "Build a reliable, observable data pipeline that ingests raw data, transforms and validates it, and exports to the target destination",
	Tasks: []TemplateTask{
		{
			Title:            "Define data contracts and source schema",
			Description:      "Document source data format, field types, expected volumes, and SLAs. Define the canonical internal schema that all downstream stages consume.",
			Priority:         1,
			Role:             pm.RoleData,
			EstimatedMinutes: 45,
		},
		{
			Title:            "Implement ingestion layer",
			Description:      "Build connectors for each data source (API, file, stream, DB). Handle retries, back-pressure, and idempotent checkpointing.",
			Priority:         2,
			Role:             pm.RoleBackend,
			DependsOn:        []int{1},
			EstimatedMinutes: 90,
		},
		{
			Title:            "Build transformation logic",
			Description:      "Implement cleaning, enrichment, aggregation, and mapping steps. Keep transformations pure and unit-testable. Document transformation rules.",
			Priority:         3,
			Role:             pm.RoleData,
			DependsOn:        []int{2},
			EstimatedMinutes: 90,
		},
		{
			Title:            "Add data validation and quality checks",
			Description:      "Enforce schema constraints, range checks, referential integrity, and business rules. Emit metrics and alerts on quality failures. Log rejected records.",
			Priority:         4,
			Role:             pm.RoleData,
			DependsOn:        []int{3},
			EstimatedMinutes: 60,
		},
		{
			Title:            "Implement export / sink layer",
			Description:      "Write validated data to the destination (data warehouse, object store, API, etc.). Ensure atomic writes and support for incremental/full-refresh modes.",
			Priority:         5,
			Role:             pm.RoleBackend,
			DependsOn:        []int{4},
			EstimatedMinutes: 60,
		},
		{
			Title:            "Observability, scheduling, and deployment",
			Description:      "Add structured logging, metrics, and alerting. Schedule pipeline runs (cron/Airflow/etc.). Containerise and document operational runbook.",
			Priority:         6,
			Role:             pm.RoleDevOps,
			DependsOn:        []int{5},
			EstimatedMinutes: 60,
		},
	},
}

var apiService = &Template{
	Name:        "api-service",
	Description: "Production-ready API service with design, implementation, auth, tests, and docs",
	Goal:        "Design and implement a production-ready API service with authentication, comprehensive tests, and developer documentation",
	Tasks: []TemplateTask{
		{
			Title:            "API design and OpenAPI specification",
			Description:      "Define resources, endpoints, request/response schemas, error formats, and versioning strategy. Publish an OpenAPI 3 spec before writing any code.",
			Priority:         1,
			Role:             pm.RoleBackend,
			EstimatedMinutes: 60,
		},
		{
			Title:            "Implement core API endpoints",
			Description:      "Build CRUD handlers, business logic, and data access layer. Follow the OpenAPI spec exactly. Apply input validation and consistent error responses.",
			Priority:         2,
			Role:             pm.RoleBackend,
			DependsOn:        []int{1},
			EstimatedMinutes: 120,
		},
		{
			Title:            "Add authentication and authorisation",
			Description:      "Implement JWT (or OAuth2) auth, role-based access control, token refresh, and logout. Protect all non-public endpoints. Document auth flows.",
			Priority:         3,
			Role:             pm.RoleSecurity,
			DependsOn:        []int{2},
			EstimatedMinutes: 90,
		},
		{
			Title:            "Write unit, integration, and contract tests",
			Description:      "Unit-test business logic; integration-test each endpoint against a real DB. Add contract tests against the OpenAPI spec. Aim for >85% coverage.",
			Priority:         4,
			Role:             pm.RoleTesting,
			DependsOn:        []int{3},
			EstimatedMinutes: 90,
		},
		{
			Title:            "Write developer documentation",
			Description:      "Create a getting-started guide, authentication walkthrough, endpoint reference (auto-generated from OpenAPI), and SDK/client code examples.",
			Priority:         5,
			Role:             pm.RoleDocs,
			DependsOn:        []int{4},
			EstimatedMinutes: 60,
		},
	},
}

var refactor = &Template{
	Name:        "refactor",
	Description: "Structured codebase refactor: audit, plan, execute, and verify",
	Goal:        "Improve codebase quality through systematic auditing, targeted refactoring, and rigorous verification",
	Tasks: []TemplateTask{
		{
			Title:            "Audit codebase and identify problems",
			Description:      "Analyse the codebase for code smells, duplication, unclear naming, architectural violations, and test coverage gaps. Produce a prioritised findings report.",
			Priority:         1,
			Role:             pm.RoleReview,
			EstimatedMinutes: 60,
		},
		{
			Title:            "Create refactoring plan",
			Description:      "Translate audit findings into a concrete plan: which modules change, in what order, with what approach (rename, extract, inline, restructure). Identify risk areas.",
			Priority:         2,
			Role:             pm.RoleReview,
			DependsOn:        []int{1},
			EstimatedMinutes: 45,
		},
		{
			Title:            "Improve test coverage before refactoring",
			Description:      "Add or strengthen tests for the modules identified in the plan so that regressions are caught during refactoring. Do not change production behaviour here.",
			Priority:         3,
			Role:             pm.RoleTesting,
			DependsOn:        []int{2},
			EstimatedMinutes: 90,
		},
		{
			Title:            "Execute refactoring changes",
			Description:      "Apply the planned changes incrementally: rename, extract, simplify, and restructure. Commit each logical change separately to keep the diff reviewable.",
			Priority:         4,
			Role:             pm.RoleReview,
			DependsOn:        []int{3},
			EstimatedMinutes: 120,
		},
		{
			Title:            "Verify correctness and update documentation",
			Description:      "Run the full test suite, check for regressions, update README and inline comments to reflect new structure. Produce a before/after quality summary.",
			Priority:         5,
			Role:             pm.RoleReview,
			DependsOn:        []int{4},
			EstimatedMinutes: 45,
		},
	},
}

var securityAudit = &Template{
	Name:        "security-audit",
	Description: "Security audit: reconnaissance, vulnerability assessment, remediation, and verification",
	Goal:        "Conduct a thorough security audit of the application, identify vulnerabilities, implement fixes, and verify remediation",
	Tasks: []TemplateTask{
		{
			Title:            "Reconnaissance and attack surface mapping",
			Description:      "Enumerate all entry points: API endpoints, authentication flows, file uploads, third-party integrations, and exposed infrastructure. Document the threat model.",
			Priority:         1,
			Role:             pm.RoleSecurity,
			EstimatedMinutes: 60,
		},
		{
			Title:            "Vulnerability assessment",
			Description:      "Test for OWASP Top 10 issues (injection, broken auth, IDOR, XSS, CSRF, misconfiguration, etc.), insecure dependencies, and secrets in version control. Record all findings with CVSS scores.",
			Priority:         2,
			Role:             pm.RoleSecurity,
			DependsOn:        []int{1},
			EstimatedMinutes: 120,
		},
		{
			Title:            "Implement security fixes",
			Description:      "Remediate all critical and high findings first: sanitise inputs, fix auth flaws, patch vulnerable dependencies, add rate limiting and security headers.",
			Priority:         3,
			Role:             pm.RoleSecurity,
			DependsOn:        []int{2},
			EstimatedMinutes: 120,
		},
		{
			Title:            "Verify remediation and write security report",
			Description:      "Re-test each finding to confirm it is resolved. Write a security report covering methodology, findings, remediations, and remaining accepted risks.",
			Priority:         4,
			Role:             pm.RoleSecurity,
			DependsOn:        []int{3},
			EstimatedMinutes: 60,
		},
	},
}
