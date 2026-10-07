package cmd

// What `cloop ui` says at startup about role-based access control (Task 20395).
//
// The line used to read "RBAC: 0 role mapping(s), default role "none"" on a hub
// whose RBAC was off — an empty default_role rendered as the deny-by-default it
// would mean if a policy existed — so the one hub that most needed a warning got
// a line that read like the safe configuration. Whether RBAC is in force is now
// authz.Enforced's answer, the same one the request gate acts on, and the off
// state is a warning on stderr that survives a redirected stdout.

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
)

// reportRBAC prints the RBAC line of the startup banner to stdout and, when
// single sign-on runs without a role policy, the warning to stderr. It returns
// the refusal ui.oidc.require_rbac makes of that state, which the caller
// returns before the hub serves anything.
//
// resolver is the one `cloop ui` has just built from oc, runtime layer
// included. A block with single sign-on off says nothing: there are no claims
// to authorize, and the exposure rules decide who can reach such a hub.
func reportRBAC(stdout, stderr io.Writer, oc config.OIDCConfig, resolver *authz.Resolver) error {
	if !oc.Enabled {
		return nil
	}
	runtime := describeRuntimeBindings(resolver.RuntimeBindings())
	if authz.Enforced(oc.Enabled, resolver) {
		fmt.Fprintf(stdout, "RBAC: %d role mapping(s), default role %q%s\n",
			len(oc.RoleMappings), resolver.DefaultRole(), runtime)
		return nil
	}
	fmt.Fprintf(stdout, "RBAC: off — no role mappings and no default role, so every signed-in identity has full access%s\n",
		runtime)
	if err := oc.RequireRBACRefusal(); err != nil {
		return err
	}
	warnRBACOff(stderr, oc)
	return nil
}

// warnRBACOff writes the RBAC-off warning: the sentence every reporter leads
// with, what it means, and how to leave it. Shared by `cloop ui` and `cloop
// config set ui.oidc.*`, which can produce the state.
func warnRBACOff(w io.Writer, oc config.OIDCConfig) {
	warn := color.New(color.FgYellow)
	dim := color.New(color.Faint)
	warn.Fprintf(w, "warning: %s.\n", config.RBACOff(oc.Issuer))
	dim.Fprintln(w, indentWrapped(config.RBACOffConsequence+".", "  ", 78))
	dim.Fprintln(w, indentWrapped(config.RBACOffRemedy+".", "  ", 78))
}

// indentWrapped wraps text at width columns, each line prefixed with indent.
func indentWrapped(text, indent string, width int) string {
	var lines []string
	line := indent
	for _, word := range strings.Fields(text) {
		if len(line) > len(indent) && len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = indent
		}
		if len(line) > len(indent) {
			line += " "
		}
		line += word
	}
	if len(line) > len(indent) {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
