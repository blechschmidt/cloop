package arch_test

// Every entry point a run's credentials reach is classified (Task 20499).
//
// The hub mints a run credentials of its own — a knowledge session, a model
// relay session, git proxy, Kubernetes monitor and egress sessions — and an
// executor pool's controller and runners theirs, a CI job its relay session.
// Each is good at one entry point, which authenticates it and reads the
// run's project (or the pool's, or the CI rule's) off it, never off the
// request (docs/security/model.md, "What a run's credentials reach"). Every
// entry point is one of three things:
//
//   - own-project: it serves the credential's own project, and nothing in the
//     request can name another;
//   - readers-gated-read: it may read another project, and only while that
//     project's readers list (pkg/projectreaders) names the credential's —
//     asked at every request — and it never writes one;
//   - refused: no run credential opens it.
//
// The gate keeps that true of entry points nobody has written yet:
//
//   - every route the dashboard serves without its own authentication
//     (authz.PermPublic), as the hub's route table reports them at run time,
//     is classified here — the dashboard's other routes refuse every run
//     credential in authMiddleware, which the gate checks too;
//   - every handler of such a route is named by its classification, and an
//     own-project or readers-gated handler authenticates the credential with
//     the function named, takes no project, index or path from the request
//     through any of the dashboard's resolvers, and — for a read — asks the
//     readers list through the gate named;
//   - every layer of the dashboard's handler chain, every request
//     servedBeforeAuth lets past authentication, and every listener pkg/ui
//     serves on is classified;
//   - the git proxy asks the readers list before serving a foreign read, and
//     the hub hands it the list to ask;
//   - every credential shape the hub mints (pkg/redact's cloop-* detectors)
//     is classified, and the run-scoped ones are the ones the dashboard
//     refuses (pkg/ui/run_credentials.go).
//
// A new entry point fails here until somebody decides which of the three it
// is, and writes why.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/ui"
)

type runClass string

const (
	ownProject       runClass = "own-project"
	readersGatedRead runClass = "readers-gated-read"
	refusedClass     runClass = "refused"
)

// runRoute classifies one public route's path, every method of it.
type runRoute struct {
	class runClass
	// handlers serve the path.
	handlers []string
	// scope is whose the credential is, for an own-project or readers-gated
	// route: project, rule (a CI rule's project) or pool.
	scope string
	// authenticates is the function each handler calls to authenticate the
	// credential, for an own-project or readers-gated route.
	authenticates string
	// gate is the method a readers-gated handler resolves what it reads
	// through, which must ask runMayRead.
	gate string
	// why says, for a refused route, why no run credential opens it.
	why string
}

// Reasons shared by many refused routes.
const (
	behindAuth = "behind authMiddleware, which refuses every run credential (refuseRunCredential) before the " +
		"hub's own credentials are looked at"
	staticBytes = "static bytes compiled into the binary, the same for every caller and holding no project's data; " +
		"a run credential gains nothing there"
)

// publicRoutes classifies every path the dashboard serves under
// authz.PermPublic.
var publicRoutes = map[string]runRoute{
	// The run-scoped knowledge search (Task 20472): the knowledge session
	// names its project; another one is read only through call.target, which
	// asks runMayRead.
	"/api/run/knowledge/search": {class: readersGatedRead, scope: "project",
		handlers: []string{"handleRunKnowledgeSearch"}, authenticates: "openRunKnowledgeCall", gate: "target"},
	"/api/run/knowledge/get": {class: readersGatedRead, scope: "project",
		handlers: []string{"handleRunKnowledgeGet"}, authenticates: "openRunKnowledgeCall", gate: "target"},
	// The projects a run was given to read (Task 20501): the session records
	// what it was given at its dispatch, and each is answered for — or its
	// snapshot built — only through readOnlyTarget, which asks runMayRead.
	"/api/run/knowledge/readonly": {class: readersGatedRead, scope: "project",
		handlers: []string{"handleRunReadOnly"}, authenticates: "openRunKnowledgeCall", gate: "readOnlyTarget"},
	"/api/run/knowledge/readonly/snapshot": {class: readersGatedRead, scope: "project",
		handlers: []string{"handleRunReadOnlySnapshot"}, authenticates: "openRunKnowledgeCall", gate: "readOnlyTarget"},
	// A seeded run's tasks' input files (Task 20511): the session records the
	// directory its run was dispatched to, and only that directory's tasks'
	// input files are listed or served — never another project's, whatever
	// a readers list says.
	"/api/run/knowledge/inputs": {class: ownProject, scope: "project",
		handlers: []string{"handleRunInputs"}, authenticates: "openRunKnowledgeCall"},
	"/api/run/knowledge/inputs/file": {class: ownProject, scope: "project",
		handlers: []string{"handleRunInputFile"}, authenticates: "openRunKnowledgeCall"},
	// The files a seeded run's tasks attach (Task 20513): kept in the store of
	// the directory the session records, attached only to that directory's
	// tasks — a write, so the run's own whatever a readers list says.
	"/api/run/knowledge/results": {class: ownProject, scope: "project",
		handlers: []string{"handleRunResult"}, authenticates: "openRunKnowledgeCall"},
	// Citations are taken from the session — a write — so they are the
	// run's own whatever a list says.
	"/api/run/knowledge/citations": {class: ownProject, scope: "project",
		handlers: []string{"handleRunKnowledgeCitations"}, authenticates: "openRunKnowledgeCall"},
	// The model relay (Task 20435): the session stands on the run's lease,
	// which names the project; the request is the Anthropic API's.
	"/_anthropic/": {class: ownProject, scope: "project", handlers: []string{"handleModelRelay"},
		authenticates: "activeModelRelay"},
	// The CI relay (Task 20278): the session's project is its rule's,
	// recorded when it was minted.
	"/api/ci/anthropic/": {class: ownProject, scope: "rule", handlers: []string{"handleCIRelay"},
		authenticates: "ciSvc"},
	// An executor pool's controller (Task 20482): the credential names its
	// pool; a runner of another pool is unknown to it.
	"/api/pool-controller/feed": {class: ownProject, scope: "pool", handlers: []string{"handlePoolControllerFeed"},
		authenticates: "authenticatePoolController"},
	"/api/pool-controller/runners": {class: ownProject, scope: "pool",
		handlers: []string{"handlePoolControllerRunners"}, authenticates: "authenticatePoolController"},
	"/api/pool-controller/runners/retire": {class: ownProject, scope: "pool",
		handlers: []string{"handlePoolControllerRetire"}, authenticates: "authenticatePoolController"},
	"/api/pool-controller/status": {class: ownProject, scope: "pool",
		handlers: []string{"handlePoolControllerStatus"}, authenticates: "authenticatePoolController"},

	"/api/ci/token": {class: refusedClass, handlers: []string{"handleCIExchange"},
		why: "exchanges a forge-signed OIDC assertion for a CI session; a run credential is no assertion"},
	"/api/csp-report": {class: refusedClass, handlers: []string{"handleCSPReport"},
		why: "takes no credential and reads nothing: it counts a browser's report"},
	"/api/device/code": {class: refusedClass, handlers: []string{"handleDeviceCode"},
		why: "a terminal asking for a sign-in code; it takes no credential"},
	"/api/device/token": {class: refusedClass, handlers: []string{"handleDeviceToken"},
		why: "a terminal polling for its own code; it takes no credential"},
	"/api/device/lookup":  {class: refusedClass, handlers: []string{"handleDeviceLookup"}, why: behindAuth},
	"/api/device/approve": {class: refusedClass, handlers: []string{"handleDeviceApprove"}, why: behindAuth},
	"/api/device/deny":    {class: refusedClass, handlers: []string{"handleDeviceDeny"}, why: behindAuth},
	"/device":             {class: refusedClass, handlers: []string{"handleDevicePage"}, why: behindAuth},

	"/":                     {class: refusedClass, handlers: []string{"handleDashboard"}, why: behindAuth},
	"/assets/":              {class: refusedClass, handlers: []string{"handleAsset"}, why: staticBytes},
	"/glasses":              {class: refusedClass, handlers: []string{"handleGlassesPage"}, why: staticBytes},
	"/favicon.ico":          {class: refusedClass, handlers: []string{"handleIcon"}, why: staticBytes},
	"/apple-touch-icon.png": {class: refusedClass, handlers: []string{"handleIcon"}, why: staticBytes},
	"/icon-192.png":         {class: refusedClass, handlers: []string{"handleIcon"}, why: staticBytes},
	"/icon-512.png":         {class: refusedClass, handlers: []string{"handleIcon"}, why: staticBytes},
	"/icon.svg":             {class: refusedClass, handlers: []string{"handleIcon"}, why: staticBytes},
	"/manifest.webmanifest": {class: refusedClass, handlers: []string{"handleIcon"}, why: staticBytes},
	"/charts/cloop-executor-controller.tgz": {class: refusedClass, handlers: []string{"handleExecutorControllerChart"},
		why: staticBytes},
	"/auth/sign-in.js": {class: refusedClass, handlers: []string{"ServeScript"}, why: behindAuth},
	"/auth/login":      {class: refusedClass, handlers: []string{"handleOIDCLogin"}, why: behindAuth},
	"/auth/callback":   {class: refusedClass, handlers: []string{"handleOIDCCallback"}, why: behindAuth},
	"/auth/logout":     {class: refusedClass, handlers: []string{"handleOIDCLogout"}, why: behindAuth},
	"/auth/renew":      {class: refusedClass, handlers: []string{"handleOIDCRenew"}, why: behindAuth},

	"/api/session/logout-all": {class: refusedClass, handlers: []string{"handleLogoutAll"}, why: behindAuth},
	"/api/me":                 {class: refusedClass, handlers: []string{"handleMe"}, why: behindAuth},
	"/api/client-error":       {class: refusedClass, handlers: []string{"handleClientError"}, why: behindAuth},
	"/api/telemetry":          {class: refusedClass, handlers: []string{"handleTelemetryIngest"}, why: behindAuth},
	"/api/telemetry/config":   {class: refusedClass, handlers: []string{"handleTelemetryClientConfig"}, why: behindAuth},
	"/api/version":            {class: refusedClass, handlers: []string{"handleVersion"}, why: behindAuth},
	"/api/approvals":          {class: refusedClass, handlers: []string{"handleApprovals"}, why: behindAuth},
	"/api/approvals/count":    {class: refusedClass, handlers: []string{"handleApprovalsCount"}, why: behindAuth},
	"/api/quota/me":           {class: refusedClass, handlers: []string{"handleQuotaMe"}, why: behindAuth},
	"/api/glasses/link":       {class: refusedClass, handlers: []string{"handleGlassesLinkGet", "handleGlassesLinkCreate", "handleGlassesLinkRevoke"}, why: behindAuth},
	"/api/glasses/telemetry":  {class: refusedClass, handlers: []string{"handleGlassesTelemetryIngest"}, why: behindAuth},
	"/api/glasses/telemetry/config": {class: refusedClass, handlers: []string{"handleGlassesTelemetryClientConfig"},
		why: behindAuth},
}

// scimRoute classifies the SCIM service, every path under /scim/v2.
var scimRoute = runRoute{class: refusedClass, why: "the SCIM service takes the cloop_scim_ credential and nothing " +
	"else (scimEnter), and a run is never given one",
	handlers: []string{"handleSCIMServiceProviderConfig", "handleSCIMResourceTypes", "handleSCIMResourceType",
		"handleSCIMSchemas", "handleSCIMSchema", "handleSCIMUsersList", "handleSCIMUserCreate", "handleSCIMUserGet",
		"handleSCIMUserReplace", "handleSCIMUserPatch", "handleSCIMUserDelete", "handleSCIMGroupsList",
		"handleSCIMGroupCreate", "handleSCIMGroupGet", "handleSCIMGroupReplace", "handleSCIMGroupPatch",
		"handleSCIMGroupDelete", "handleSCIMFallback"}}

// projectResolvers are the dashboard's ways of reading a project, a project
// index or a path out of a request: an own-project or readers-gated handler
// calls none of them, so the project it serves can only be the one its
// credential names.
var projectResolvers = []string{
	"resolveWorkDir", "resolveWorkDirFrom", "projectAtIdx", "projectEntryFromPath", "projectEntryAt",
	"projectIndexFromRequest", "requestProject", "PathValue", "FormValue", "projectFromQuery",
}

// handlerLayers classifies every layer of the dashboard's handler chain
// (Server.buildHandler).
var handlerLayers = map[string]string{
	"uiRequestIDMiddleware":   "passes every request on: a request id",
	"panicRecoveryMiddleware": "passes every request on: a 500 for a panic",
	"probeBypass":             "refused: /healthz and /readyz take no credential and say nothing of any project",
	"servedByMiddleware":      "passes every request on: names the member that served it",
	"peerMiddleware":          "passes every request on: verifies a request another member forwarded, keeping its credential",
	"gzipAPIMiddleware":       "passes every request on: compression",
	"uiRateLimitMiddleware":   "passes every request on: the per-address limit",
	"securityHeaders":         "passes every request on: response headers",
	"hostGuard":               "passes every request on: refuses a foreign Host on an open hub",
	"forgeryGuard":            "passes every request on: refuses a page on another origin",
	"executorConnectBypass": "own-project: /api/executors/connect takes an agent's or a pool runner's credential, " +
		"and its frames address the executor's own handles, whose projects the hub chose when it dispatched them",
	"forwarderConnectBypass": "refused: /api/devices/forwarders/connect takes a device forwarder's credential, " +
		"which no run holds",
	"clusterInternalBypass": "refused: the cluster's internal API takes a member's signature, which no run holds",
	"authMiddleware":        "refuses every run credential (refuseRunCredential), then authenticates the hub's own",
	"authzMiddleware":       "passes on what authMiddleware admitted, with its permissions",
}

// beforeAuth classifies every predicate servedBeforeAuth lets past the
// dashboard's authentication: the public routes above that answer for
// themselves.
var beforeAuth = map[string]string{
	"isPublicShell":            "/glasses",
	"isPublicIcon":             "the icons",
	"isPublicAsset":            "/assets/",
	"isCSPReport":              "/api/csp-report",
	"isCIFederationEndpoint":   "/api/ci/token and /api/ci/anthropic/",
	"isDeviceGrantEndpoint":    "/api/device/code and /api/device/token",
	"isSCIMEndpoint":           "/scim/v2",
	"isModelRelayEndpoint":     "/_anthropic/",
	"isKnowledgeRunEndpoint":   "/api/run/knowledge/",
	"isPoolControllerEndpoint": "/api/pool-controller/",
	"isPublicChart":            "/charts/cloop-executor-controller.tgz",
}

// listeners classifies every function in pkg/ui that serves HTTP on a
// listener of its own.
var listeners = map[string]string{
	"Run": "the dashboard: its routes are classified above",
	"startGitProxy": "own-project and readers-gated-read: a git proxy session is minted for one run's project and " +
		"scoped to its grants' repositories; a foreign read (gitproxy.Session.ReadsProject) fetches another " +
		"project's repository only while its readers list names the run's, asked at every request, and never pushes",
	"startKubeGuard": "own-project: a monitor session is minted from one run's kubeconfig grant, and its policy is " +
		"that grant's namespaces and verbs",
	"startEgressProxy": "own-project: an egress session is redeemed for one run's project, from a grant aimed at " +
		"that project",
}

// credentialShapes classifies every credential shape the hub mints, by its
// pkg/redact detector: the run-scoped ones by the kind
// pkg/ui/run_credentials.go refuses them as at the dashboard's routes.
var credentialShapes = map[string]string{
	"cloop-knowledge-session":  "run:knowledge_session",
	"cloop-relay-token":        "run:model_relay_session",
	"cloop-ci-token":           "run:ci_relay_session",
	"cloop-git-proxy-session":  "run:git_proxy_session",
	"cloop-kube-guard-session": "run:kube_guard_session",
	"cloop-egress-session":     "run:egress_session",
	"cloop-pool-credential":    "run:pool_controller",
	"cloop-runner-token":       "run:runner_token",
	"cloop-runner-credential":  "run:runner_credential",
	"cloop-api-token":          "dashboard: a person's or a service account's API token",
	"cloop-glasses-link":       "dashboard: a display-glasses link, an API token",
	"cloop-scim-credential":    "scim: an identity provider's, refused by everything but /scim/v2",
	"cloop-enrollment-token":   "device: an edge device's single-use enrollment, at /api/executors/connect",
	"cloop-enrollment-bundle":  "device: the bundle carrying an enrollment token",
	"cloop-agent-credential":   "device: an enrolled agent's, at /api/executors/connect",
}

func TestEveryRouteARunCredentialReachesIsClassified(t *testing.T) {
	root := repoRoot(t)
	paths := map[string]bool{}
	for _, r := range ui.APIRoutes() {
		if r.Public {
			paths[r.Path] = true
		}
	}
	if len(paths) < 40 {
		t.Fatalf("the route table reports %d public paths: the scan has gone blind", len(paths))
	}
	classOf := func(path string) (runRoute, bool) {
		if strings.HasPrefix(path, "/scim/v2/") {
			return scimRoute, true
		}
		r, ok := publicRoutes[path]
		return r, ok
	}
	var sorted []string
	for p := range paths {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)
	for _, p := range sorted {
		if _, ok := classOf(p); !ok {
			t.Errorf("%s is served before the dashboard's authentication (authz.PermPublic), and nobody has said "+
				"what a run's credential reaches there: classify it in publicRoutes as own-project, "+
				"readers-gated-read or refused, and why", p)
		}
	}
	for p := range publicRoutes {
		if !paths[p] {
			t.Errorf("publicRoutes classifies %s, which the hub no longer serves publicly: remove it", p)
		}
	}

	// Every handler of a public route literal is named by a classification,
	// and every named handler is one.
	used, err := publicHandlers(filepath.Join(root, "pkg/ui"))
	if err != nil {
		t.Fatal(err)
	}
	named := map[string]bool{}
	for _, r := range append(mapValues(publicRoutes), scimRoute) {
		for _, h := range r.handlers {
			named[h] = true
		}
	}
	for h := range used {
		if !named[h] {
			t.Errorf("%s serves a public route nobody classified: add it to its path's handlers in publicRoutes", h)
		}
	}
	for h := range named {
		if !used[h] {
			t.Errorf("publicRoutes names %s, which serves no public route: remove it", h)
		}
	}

	// What an own-project or readers-gated handler may and must call — and
	// what anything it calls in pkg/ui calls, so a helper that reads a
	// project out of the request is found too.
	graph, err := callGraphIn(filepath.Join(root, "pkg/ui"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range sorted {
		r, ok := classOf(p)
		if !ok {
			continue // reported above
		}
		switch r.class {
		case refusedClass:
			if strings.TrimSpace(r.why) == "" {
				t.Errorf("%s is refused with no reason", p)
			}
			continue
		case ownProject, readersGatedRead:
		default:
			t.Errorf("%s has class %q", p, r.class)
			continue
		}
		if r.scope == "" || r.authenticates == "" {
			t.Errorf("%s: an %s route names whose credential it takes and what authenticates it", p, r.class)
		}
		for _, h := range r.handlers {
			calls, err := methodCallsIn(filepath.Join(root, "pkg/ui"), h)
			if err != nil {
				t.Errorf("%s: handler %s: %v", p, h, err)
				continue
			}
			if !calls[r.authenticates] {
				t.Errorf("%s: %s no longer calls %s: it is classified as authenticating the credential there", p,
					h, r.authenticates)
			}
			reach := graph.reach(h)
			for _, res := range projectResolvers {
				if reach[res] != "" {
					t.Errorf("%s: %s reaches %s (through %s), which reads a project out of the request — an %s "+
						"route serves the project its credential names, and nothing a request says", p, h, res,
						reach[res], r.class)
				}
			}
			if r.class == readersGatedRead {
				if !calls[r.gate] {
					t.Errorf("%s: %s no longer resolves what it reads through %s", p, h, r.gate)
				}
			} else if calls["target"] || calls["runMayRead"] {
				t.Errorf("%s: %s reads another project, but is classified own-project", p, h)
			}
		}
		if r.class == readersGatedRead {
			gate, err := methodCallsIn(filepath.Join(root, "pkg/ui"), r.gate)
			if err != nil {
				t.Errorf("%s: gate %s: %v", p, r.gate, err)
			} else if !gate["runMayRead"] {
				t.Errorf("%s: %s no longer asks runMayRead: a read of another project would not ask its readers list",
					p, r.gate)
			}
		}
	}
}

func TestTheDashboardRefusesRunCredentialsBeforeItsOwn(t *testing.T) {
	root := repoRoot(t)
	fn, fset, err := funcDecl(filepath.Join(root, "pkg/ui"), "authMiddleware")
	if err != nil {
		t.Fatal(err)
	}
	pos := map[string]token.Pos{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			name := calleeName(call)
			if _, seen := pos[name]; !seen && name != "" {
				pos[name] = call.Pos()
			}
		}
		return true
	})
	refuse, ok := pos["refuseRunCredential"]
	if !ok || pos["runCredentialIn"] == 0 {
		t.Fatal("authMiddleware no longer refuses run credentials (runCredentialIn, refuseRunCredential)")
	}
	for _, own := range []string{"oidcGate", "authenticateAPIToken", "checkStaticToken", "staticTokenConfigured"} {
		if p, ok := pos[own]; ok && p < refuse {
			t.Errorf("authMiddleware calls %s (%s) before it refuses run credentials (%s): on a hub without "+
				"sign-in a run would be served as the operator", own, fset.Position(p), fset.Position(refuse))
		}
	}

	// Every credential shape the hub mints is classified, and the run-scoped
	// ones are exactly the kinds the dashboard refuses.
	shapes, err := cloopDetectors(filepath.Join(root, "pkg/redact/patterns.go"))
	if err != nil {
		t.Fatal(err)
	}
	wantKinds := map[string]bool{}
	for _, d := range shapes {
		class, ok := credentialShapes[d]
		if !ok {
			t.Errorf("pkg/redact knows a credential shape %s nobody classified: say in credentialShapes whose it is "+
				"— and, if a run holds it, add its kind to pkg/ui/run_credentials.go", d)
			continue
		}
		if kind, ok := strings.CutPrefix(class, "run:"); ok {
			wantKinds[kind] = true
		}
	}
	for d := range credentialShapes {
		if !slicesContains(shapes, d) {
			t.Errorf("credentialShapes names %s, which pkg/redact no longer detects: remove it", d)
		}
	}
	kinds, err := runCredentialKindNames(filepath.Join(root, "pkg/ui/run_credentials.go"))
	if err != nil {
		t.Fatal(err)
	}
	for k := range wantKinds {
		if !kinds[k] {
			t.Errorf("%s is a run's credential the dashboard does not refuse: add it to runCredentialKinds", k)
		}
	}
	for k := range kinds {
		if !wantKinds[k] {
			t.Errorf("runCredentialKinds has %s, which no detector is classified as: classify its shape", k)
		}
	}
}

func TestEveryOtherEntryPointARunReachesIsClassified(t *testing.T) {
	root := repoRoot(t)
	uiDir := filepath.Join(root, "pkg/ui")

	// The handler chain.
	build, _, err := funcDecl(uiDir, "buildHandler")
	if err != nil {
		t.Fatal(err)
	}
	layers := map[string]bool{}
	ast.Inspect(build.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if name := calleeName(call); name != "" && len(call.Args) == 1 {
				layers[name] = true
			}
		}
		return true
	})
	for name := range layers {
		if _, ok := handlerLayers[name]; !ok {
			t.Errorf("buildHandler wraps the dashboard in %s, which nobody classified: say in handlerLayers what "+
				"a run's credential reaches through it", name)
		}
	}
	for name := range handlerLayers {
		if !layers[name] {
			t.Errorf("handlerLayers names %s, which buildHandler no longer uses: remove it", name)
		}
	}

	// What gets past authentication.
	served, _, err := funcDecl(uiDir, "servedBeforeAuth")
	if err != nil {
		t.Fatal(err)
	}
	preds := map[string]bool{}
	ast.Inspect(served.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			preds[calleeName(call)] = true
		}
		return true
	})
	for name := range preds {
		if _, ok := beforeAuth[name]; !ok {
			t.Errorf("servedBeforeAuth lets %s past authentication, and nobody classified it in beforeAuth", name)
		}
	}
	for name := range beforeAuth {
		if !preds[name] {
			t.Errorf("beforeAuth names %s, which servedBeforeAuth no longer calls: remove it", name)
		}
	}

	// Every listener.
	found, err := servingFunctions(uiDir)
	if err != nil {
		t.Fatal(err)
	}
	for name := range found {
		if _, ok := listeners[name]; !ok {
			t.Errorf("%s serves HTTP on a listener of its own, and nobody classified what a run's credential "+
				"reaches there: add it to listeners", name)
		}
	}
	for name := range listeners {
		if !found[name] {
			t.Errorf("listeners names %s, which no longer serves a listener: remove it", name)
		}
	}

	// The git proxy asks the readers list before it serves a foreign read,
	// and the hub gives it the list to ask.
	serve, err := methodCallsIn(filepath.Join(root, "pkg/gitproxy"), "ServeHTTP")
	if err != nil || !serve["foreignReadRefusal"] {
		t.Errorf("the git proxy's ServeHTTP no longer checks foreign reads (foreignReadRefusal): %v", err)
	}
	refusal, err := methodCallsIn(filepath.Join(root, "pkg/gitproxy"), "foreignReadRefusal")
	if err != nil || !refusal["Readers"] {
		t.Errorf("foreignReadRefusal no longer asks Options.Readers: %v", err)
	}
	start, _, err := funcDecl(uiDir, "startGitProxy")
	if err != nil {
		t.Fatal(err)
	}
	gives := false
	ast.Inspect(start.Body, func(n ast.Node) bool {
		if kv, ok := n.(*ast.KeyValueExpr); ok {
			if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Readers" {
				gives = true
			}
		}
		return true
	})
	if !gives {
		t.Error("startGitProxy no longer hands the git proxy the readers list (gitproxy.Options.Readers): every " +
			"foreign read would be refused, or a proxy built otherwise would not ask")
	}
}

// callGraph is, for each function or method name declared in a package, the
// names its bodies call — every declaration of the name, so a method and a
// function sharing one are both followed.
type callGraph map[string]map[string]bool

// callGraphIn reads dir's non-test files into a callGraph. A call into
// another package (knowledge.New, statedb.Open) is not the package's own and
// is left out, so it cannot be mistaken for a function of the same name here.
func callGraphIn(dir string) (callGraph, error) {
	g := callGraph{}
	err := eachFile(dir, func(file *ast.File, _ *token.FileSet) {
		imported := map[string]bool{}
		for _, imp := range file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			name := filepath.Base(path)
			if imp.Name != nil {
				name = imp.Name.Name
			}
			imported[name] = true
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			calls := g[fn.Name.Name]
			if calls == nil {
				calls = map[string]bool{}
				g[fn.Name.Name] = calls
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if pkg, ok := sel.X.(*ast.Ident); ok && imported[pkg.Name] && pkg.Obj == nil {
						// A package's function, but PathValue and its kind
						// are what a handler reads a project with whichever
						// receiver they are called on.
						if sel.Sel.Name != "PathValue" && sel.Sel.Name != "FormValue" {
							return true
						}
					}
				}
				if name := calleeName(call); name != "" {
					calls[name] = true
				}
				return true
			})
		}
	})
	return g, err
}

// reach returns every name the function named from calls, directly or
// through what it calls in the package, each with the declared function it
// was found in.
func (g callGraph) reach(from string) map[string]string {
	out := map[string]string{}
	seen := map[string]bool{from: true}
	queue := []string{from}
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		for callee := range g[fn] {
			if _, ok := out[callee]; !ok {
				out[callee] = fn
			}
			if _, declared := g[callee]; declared && !seen[callee] {
				seen[callee] = true
				queue = append(queue, callee)
			}
		}
	}
	return out
}

// publicHandlers returns the handler of every route literal in dir declaring
// authz.PermPublic — as `public`, the route table's own name for it, or as
// the constant.
func publicHandlers(dir string) (map[string]bool, error) {
	out := map[string]bool{}
	err := eachFile(dir, func(file *ast.File, _ *token.FileSet) {
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			var perm, handler string
			for _, el := range lit.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch key.Name {
				case "Perm":
					perm = exprName(kv.Value)
				case "Handler":
					switch v := kv.Value.(type) {
					case *ast.SelectorExpr:
						handler = v.Sel.Name
					case *ast.Ident:
						handler = v.Name
					}
				}
			}
			if handler != "" && (perm == "public" || perm == "authz.PermPublic") {
				out[handler] = true
			}
			return true
		})
	})
	return out, err
}

// servingFunctions returns the functions in dir that call Serve or ServeTLS
// on something: each serves HTTP on a listener.
func servingFunctions(dir string) (map[string]bool, error) {
	out := map[string]bool{}
	err := eachFile(dir, func(file *ast.File, _ *token.FileSet) {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					switch calleeName(call) {
					case "Serve", "ServeTLS", "ListenAndServe", "ListenAndServeTLS":
						out[fn.Name.Name] = true
					}
				}
				return true
			})
		}
	})
	return out, err
}

// funcDecl finds the function or method named name among dir's non-test
// files.
func funcDecl(dir, name string) (*ast.FuncDecl, *token.FileSet, error) {
	var found *ast.FuncDecl
	var fset *token.FileSet
	err := eachFile(dir, func(file *ast.File, fs *token.FileSet) {
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name && fn.Body != nil && found == nil {
				found, fset = fn, fs
			}
		}
	})
	if err == nil && found == nil {
		err = os.ErrNotExist
	}
	return found, fset, err
}

// eachFile parses every non-test Go file in dir.
func eachFile(dir string, fn func(*ast.File, *token.FileSet)) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			return err
		}
		fn(file, fset)
	}
	return nil
}

var detectorName = regexp.MustCompile(`name:\s*"(cloop-[a-z0-9-]+)"`)

// cloopDetectors lists pkg/redact's detectors of cloop's own credential
// shapes.
func cloopDetectors(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range detectorName.FindAllStringSubmatch(string(raw), -1) {
		out = append(out, m[1])
	}
	return out, nil
}

// runCredentialKindNames lists the kinds pkg/ui/run_credentials.go refuses.
func runCredentialKindNames(path string) (map[string]bool, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "runCredentialKinds" || len(vs.Values) != 1 {
			return true
		}
		lit, ok := vs.Values[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, el := range lit.Elts {
			kind, ok := el.(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, f := range kind.Elts {
				kv, ok := f.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "name" {
					if bl, ok := kv.Value.(*ast.BasicLit); ok {
						if v, err := strconv.Unquote(bl.Value); err == nil {
							out[v] = true
						}
					}
				}
			}
		}
		return false
	})
	return out, nil
}

func mapValues(m map[string]runRoute) []runRoute {
	out := make([]runRoute, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
