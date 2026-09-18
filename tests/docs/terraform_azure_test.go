package docs_test

// Gates the Azure Entra ID Terraform module against the code it configures.
//
// deploy/terraform/azure-entra-id/ has its own test suite — `terraform test`
// with a mocked provider — and that suite is thorough about everything
// decidable from the module alone: both redirect URIs, the /v2.0 issuer, the
// rendered scopes, the derived app role IDs. What it cannot see is cloop.
//
// Every one of those values is a claim about this codebase. The callback path
// is a route in pkg/ui. The four app roles are pkg/authz's role ladder. The
// YAML keys are fields of config.OIDCConfig. The environment variable is a
// constant in pkg/config. Terraform cannot check any of them, and the failure
// mode when one drifts is the worst kind: `terraform apply` succeeds, the hub
// starts, and sign-in fails — or worse, succeeds at the wrong role.
//
// So the joins live here, in Go, where both sides are visible. A fifth role,
// a moved callback, a renamed config key: each fails this test and names the
// file to change.

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// azureModuleDir is the module's path relative to the repository root.
const azureModuleDir = "deploy/terraform/azure-entra-id"

// azureModuleFile reads one file of the module.
func azureModuleFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(repoRoot(t), azureModuleDir, name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s/%s: %v\n"+
			"The Azure SSO module is part of the documented deployment surface; "+
			"if it moved, update azureModuleDir.", azureModuleDir, name, err)
	}
	return string(b)
}

// hclBlockBody returns the body of the first `<header> {` block, matched by
// brace depth rather than by a closing-brace pattern — the bodies here nest.
func hclBlockBody(t *testing.T, src, header string) string {
	t.Helper()
	start := strings.Index(src, header+" {")
	if start < 0 {
		t.Fatalf("no %q block found; the module's structure changed and this check is no longer reading what it names", header)
	}
	depth, from := 0, start+len(header)+1
	for i := from; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[from+1 : i]
			}
		}
	}
	t.Fatalf("unterminated %q block", header)
	return ""
}

// assignableCloopRoles is pkg/authz's ladder minus "none", read from the
// source rather than listed here.
//
// "none" is excluded on purpose and is not an oversight: in cloop it is the
// absence of a grant, the value default_role takes when nothing matched. There
// is nothing for Entra to assign, and an app role called "none" would be a
// thing a user could be given — which is the opposite of what it means.
func assignableCloopRoles(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, v := range allCloopRoles(t) {
		if v == string(authz.RoleNone) {
			continue
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		t.Fatal("every authz Role is RoleNone — this check is disabled, not passing")
	}
	sort.Strings(out)
	return out
}

// allCloopRoles reads the ladder out of pkg/authz with go/ast, the same way
// the drift gate does, so adding a constant is enough to fail these checks.
func allCloopRoles(t *testing.T) []string {
	t.Helper()
	values := constStrings(t, filepath.Join(repoRoot(t), "pkg/authz/authz.go"), "Role", "Role")
	if len(values) == 0 {
		t.Fatal("found no authz Role constants — this check is disabled, not passing")
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// TestAzureModuleDeclaresEveryAssignableRole is the join that matters most.
//
// Entra puts an app role's `value` into the `roles` claim verbatim, and
// cloop's role_mappings bind on it. A cloop role with no app role is a role
// nobody in the directory can be granted; an app role the rendered config does
// not bind is a role Entra hands out and cloop ignores. Both fail silently —
// the user signs in and lands on default_role — so neither may pass here.
func TestAzureModuleDeclaresEveryAssignableRole(t *testing.T) {
	roles := assignableCloopRoles(t)
	main := azureModuleFile(t, "main.tf")
	outputs := azureModuleFile(t, "outputs.tf")

	declared := map[string]bool{}
	body := hclBlockBody(t, main, "app_roles =")
	for _, m := range regexp.MustCompile(`(?m)^\s{4}(\w+) = \{`).FindAllStringSubmatch(body, -1) {
		declared[m[1]] = true
	}
	if len(declared) == 0 {
		t.Fatal("parsed no app roles out of the module's app_roles local — this check is disabled, not passing")
	}

	for _, role := range roles {
		if !declared[role] {
			t.Errorf("cloop role %q has no Entra app role.\n"+
				"  add it to the app_roles local in %s/main.tf, so a directory\n"+
				"  principal can actually be granted it", role, azureModuleDir)
		}
		delete(declared, role)
	}
	for extra := range declared {
		t.Errorf("the module declares an app role %q that is not a cloop role.\n"+
			"  Entra will happily assign it and cloop will ignore the claim;\n"+
			"  remove it from %s/main.tf or add it to pkg/authz", extra, azureModuleDir)
	}

	// The other half: the rendered config must bind each of them. It is
	// generated by iterating the same local, which is what keeps the two in
	// step — so assert that, rather than the strings it currently produces.
	if !strings.Contains(outputs, "for role, _ in local.app_roles") {
		t.Errorf("%s/outputs.tf no longer renders role_mappings by iterating local.app_roles.\n"+
			"  Whatever replaced it can drift from the declared app roles, and the symptom "+
			"is a user who signs in successfully at default_role.", azureModuleDir)
	}
}

// TestAzureModuleValidationMatchesTheRoleLadder covers the input side.
//
// Two variables enumerate roles by hand for their validation messages. A
// stale list there refuses a legitimate value at plan time — or, worse,
// accepts one cloop does not know and writes it into a role mapping that never
// matches anything.
func TestAzureModuleValidationMatchesTheRoleLadder(t *testing.T) {
	vars := azureModuleFile(t, "variables.tf")

	// The two lists differ, and the difference is the point. Entra can only
	// assign a role, so role_assignments excludes "none"; a cloop role mapping
	// can *name* it, because binding a scope to "none" is how a broader grant
	// is revoked for one project.
	assertHCLRoleList(t, vars, "role_assignments keys",
		`contains([%s], role)`, assignableCloopRoles(t))

	assertHCLRoleList(t, vars, "cloop_default_role validation",
		`contains([%s], var.cloop_default_role)`, allCloopRoles(t))

	assertHCLRoleList(t, vars, "extra role-mapping validation",
		`contains([%s], m.role)`, allCloopRoles(t))
}

// assertHCLRoleList finds a `contains([...], <subject>)` condition in the
// module and compares the roles it lists against want as a set.
//
// A set comparison rather than a string match: the literal's order is a style
// choice (the module writes them in ladder order, which reads better than
// alphabetical), and a test that fails on reordering teaches people to edit
// the test.
func assertHCLRoleList(t *testing.T, src, what, shape string, want []string) {
	t.Helper()

	subject := strings.TrimPrefix(shape, `contains([%s], `)
	pattern := `contains\(\[([^\]]*)\], ` + regexp.QuoteMeta(subject)
	m := regexp.MustCompile(pattern).FindStringSubmatch(src)
	if m == nil {
		t.Errorf("no %s found in %s/variables.tf (looked for %s).\n"+
			"  Without it the variable accepts any string, and an unknown role "+
			"becomes a mapping that never matches.", what, azureModuleDir, shape)
		return
	}

	var got []string
	for _, q := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(m[1], -1) {
		got = append(got, q[1])
	}
	sort.Strings(got)

	wantSorted := append([]string{}, want...)
	sort.Strings(wantSorted)

	if !reflect.DeepEqual(got, wantSorted) {
		t.Errorf("the %s in %s/variables.tf lists %v, but cloop's roles are %v.\n"+
			"  Update the validation list in the module.",
			what, azureModuleDir, got, wantSorted)
	}
}

// TestAzureModuleCallbackPathIsARealRoute binds the redirect URI to the route
// table.
//
// A redirect URI Entra does not recognise fails loudly at sign-in
// (AADSTS50011). A redirect URI that is registered but that the hub does not
// serve fails as a 404 *after* a successful authentication, which reads as
// "cloop is broken" rather than "the URI is stale" — and nothing else in the
// tree would notice if pkg/ui moved the route.
func TestAzureModuleCallbackPathIsARealRoute(t *testing.T) {
	main := azureModuleFile(t, "main.tf")

	m := regexp.MustCompile(`callback_path\s*=\s*"([^"]+)"`).FindStringSubmatch(main)
	if m == nil {
		t.Fatal("no callback_path local in the module — this check is disabled, not passing")
	}
	path := m[1]

	for _, r := range ui.APIRoutes() {
		if r.Path == path && r.Method == "GET" {
			if !r.Public {
				t.Errorf("%s requires a permission, but it is the route an unauthenticated "+
					"browser is redirected to by the identity provider", path)
			}
			return
		}
	}
	t.Errorf("the module registers %q as a redirect URI, but the hub serves no GET %s.\n"+
		"  Sign-in would complete at Entra and 404 at cloop.\n"+
		"  Fix the callback_path local in %s/main.tf to match pkg/ui's route table.",
		path, path, azureModuleDir)
}

// TestAzureModuleRendersRealConfigKeys checks the generated YAML against the
// struct that parses it.
//
// cloop's YAML decoding ignores unknown keys, so a renamed field turns a
// rendered setting into a no-op rather than an error: `default_role` silently
// reverting to the zero value is a hub that denies everyone, and a silently
// dropped `issuer` is a hub that refuses to start with a message about a
// setting the operator can see in their config file.
func TestAzureModuleRendersRealConfigKeys(t *testing.T) {
	outputs := azureModuleFile(t, "outputs.tf")

	known := yamlKeys(reflect.TypeOf(config.OIDCConfig{}))
	if len(known) == 0 {
		t.Fatal("reflected no yaml tags off config.OIDCConfig — this check is disabled, not passing")
	}

	// The keys the module writes under `oidc:`. Listed rather than parsed out
	// of the heredoc: the point is to assert this exact set is real, and a
	// parser lenient enough to find them in generated strings would also be
	// lenient enough to find nothing and pass.
	rendered := []string{"enabled", "issuer", "client_id", "redirect_url", "scopes", "default_role", "role_mappings", "admin_emails", "require_idp"}

	for _, key := range rendered {
		if !known[key] {
			t.Errorf("the module renders `%s:` but config.OIDCConfig has no such yaml key.\n"+
				"  cloop would ignore it silently. Known keys: %s",
				key, strings.Join(sortedKeys(known), ", "))
		}
		if !strings.Contains(outputs, key) {
			t.Errorf("%s/outputs.tf no longer renders `%s:` — this check names a key the module does not write, so it is asserting nothing",
				azureModuleDir, key)
		}
	}

	// The role-mapping fields are a second struct with its own tags.
	mappingKeys := yamlKeys(reflect.TypeOf(config.RoleMapping{}))
	for _, key := range []string{"claim", "value", "role", "project", "executor"} {
		if !mappingKeys[key] {
			t.Errorf("the module renders role mappings with a `%s` key, which config.RoleMapping does not have", key)
		}
	}
}

// TestAzureModuleNamesTheRealSecretEnvVar keeps the one instruction an
// operator follows by hand pointing at the variable cloop reads.
func TestAzureModuleNamesTheRealSecretEnvVar(t *testing.T) {
	outputs := azureModuleFile(t, "outputs.tf")
	if !strings.Contains(outputs, config.EnvOIDCClientSecret) {
		t.Errorf("the rendered config does not mention %s, which is how cloop actually "+
			"receives the client secret (config.EnvOIDCClientSecret).\n"+
			"  An operator following %s/outputs.tf would export the wrong variable and "+
			"the hub would refuse to start.", config.EnvOIDCClientSecret, azureModuleDir)
	}

	// And it must not put the credential in the file it tells people to commit.
	if regexp.MustCompile(`(?m)^\s*"?\s*client_secret:`).MatchString(outputs) {
		t.Error("the rendered cloop config contains a client_secret field; the secret belongs in " +
			config.EnvOIDCClientSecret + " so the config file stays committable")
	}
}

// TestAzureModuleGrantsEveryScopeItRequests is the module's own internal join,
// checked here because Terraform cannot see across the two files either.
//
// The registration asks Microsoft Graph for a set of delegated permissions;
// the rendered config tells cloop to request a set of scopes. A scope in the
// second but not the first is one Entra will refuse at the authorization
// endpoint — and the one most likely to go missing is offline_access, whose
// absence does not break sign-in at all. It silently ends IdP-side revocation:
// no refresh token, so a session survives a disabled account until one of the
// two timeouts fires.
func TestAzureModuleGrantsEveryScopeItRequests(t *testing.T) {
	main := azureModuleFile(t, "main.tf")
	outputs := azureModuleFile(t, "outputs.tf")

	m := regexp.MustCompile(`scopes: \[([^\]]+)\]`).FindStringSubmatch(outputs)
	if m == nil {
		t.Fatal("the rendered config has no scopes list — this check is disabled, not passing")
	}
	var requested []string
	for _, s := range strings.Split(m[1], ",") {
		if s = strings.TrimSpace(s); s != "" {
			requested = append(requested, s)
		}
	}
	if len(requested) == 0 {
		t.Fatal("parsed an empty scopes list")
	}

	granted := map[string]bool{}
	gm := regexp.MustCompile(`for_each = toset\(\[([^\]]+)\]\)`).FindStringSubmatch(main)
	if gm == nil {
		t.Fatal("the module no longer resolves Graph scopes through a toset() list — this check is disabled, not passing")
	}
	for _, s := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(gm[1], -1) {
		granted[s[1]] = true
	}

	for _, scope := range requested {
		if !granted[scope] {
			t.Errorf("the rendered config asks cloop to request the %q scope, but the "+
				"application registration does not request that delegated Microsoft Graph "+
				"permission.\n  Entra will refuse it at the authorization endpoint.\n"+
				"  Add it to required_resource_access in %s/main.tf.", scope, azureModuleDir)
		}
	}

	// offline_access specifically, because its absence is silent.
	if !granted["offline_access"] {
		t.Errorf("the registration does not request offline_access.\n" +
			"  Without a refresh token cloop can never re-ask the identity provider " +
			"whether a user is still valid: ui.oidc.refresh_interval_minutes and " +
			"max_claim_age_minutes both stop working and nothing reports it.")
	}
}

// yamlKeys returns the yaml tag names declared on a struct, tag options
// (",omitempty") stripped.
func yamlKeys(rt reflect.Type) map[string]bool {
	out := map[string]bool{}
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		if name, _, _ := strings.Cut(tag, ","); name != "" {
			out[name] = true
		}
	}
	return out
}
