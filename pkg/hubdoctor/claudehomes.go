package hubdoctor

// offboard.claude_homes: is the Claude Code home of an identity the control
// plane denies still on this host? (Task 20422)
//
// A per-user Claude home holds that person's OAuth refresh token in plaintext.
// An offboarding removes the copies on every member it reaches and names the
// rest: a member that did not answer, a stopped member's tree. Every running
// member removes such homes from its own tree as it starts and hourly after,
// so a copy found here is one no running member reads — a stopped member's,
// or one a sweep failed to remove — and it stays until that member starts
// again or somebody removes it. This check finds them on the trees of this
// host: the doctor's own, and the ones its hub members recorded.

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/offboard"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func checkClaudeLeftovers(dir string, opts Options, add addFn) {
	path := state.DBPath(dir)
	if _, err := os.Stat(path); err != nil {
		return
	}
	const title = "Claude Code homes of denied identities"
	db, err := statedb.Open(path)
	if err != nil {
		add(Finding{Check: "offboard.claude_homes", Title: title, Severity: SeverityWarn,
			Message:     "the control plane could not be read, so leftover Claude homes were not looked for: " + err.Error(),
			Remediation: "Run `cloop db verify` and fix what it reports"})
		return
	}
	defer db.Close()
	denied, _, err := offboard.DeniedIdentities(db)
	if err != nil {
		add(Finding{Check: "offboard.claude_homes", Title: title, Severity: SeverityWarn,
			Message:     "which identities the control plane denies could not be read: " + err.Error(),
			Remediation: "Run `cloop db verify` and fix what it reports"})
		return
	}
	own := opts.ClaudeHomesRoot
	if own == "" {
		own, _ = claudecodeauth.HomeRootPath()
	}
	trees, treeErr := offboard.ClaudeTreesOnThisHost(db, own)

	keys := offboard.OwnerKeysOf(denied)
	var left, unreadable []string
	var dirs []string
	for _, t := range trees {
		if _, err := os.Lstat(t.Root); err != nil {
			if !os.IsNotExist(err) {
				unreadable = append(unreadable, t.Root+": "+err.Error())
			}
			continue
		}
		homes, _, err := offboard.LocalClaude{Root: t.Root}.Inspect(keys)
		if err != nil {
			unreadable = append(unreadable, t.Root+": "+err.Error())
			continue
		}
		whose := "this shell's tree"
		if t.Member != "" {
			whose = "member " + t.Member + "'s tree"
		}
		for _, h := range homes {
			if !h.Exists {
				continue
			}
			login := ""
			if h.Credential {
				login = ", holding a login"
			}
			left = append(left, fmt.Sprintf("%s (%s, %s%s)", h.Dir, h.OwnerKey, whose, login))
			dirs = append(dirs, h.Dir)
		}
	}
	if treeErr != nil {
		unreadable = append(unreadable, treeErr.Error())
	}

	switch {
	case len(left) > 0:
		add(Finding{
			Check: "offboard.claude_homes", Title: title, Severity: SeverityFail,
			Message: fmt.Sprintf("%d Claude Code home(s) of identities the control plane denies are still on this "+
				"host, each holding the person's refresh token in plaintext: %s", len(left), strings.Join(left, "; ")),
			Remediation: "Every running hub member removes these from its own tree as it starts and hourly after; a " +
				"tree no running member reads — a stopped member's — keeps them until that member starts again. Start " +
				"it, or remove them by hand: rm -rf " + strings.Join(dirs, " "),
			Details: map[string]any{"homes": dirs},
		})
	case len(unreadable) > 0:
		add(Finding{
			Check: "offboard.claude_homes", Title: title, Severity: SeverityWarn,
			Message: "not every Claude home tree on this host could be read, so a leftover home there is not " +
				"ruled out: " + strings.Join(unreadable, "; "),
			Remediation: "Run the doctor as the user the hub runs as",
		})
	case len(denied) == 0:
		add(Finding{
			Check: "offboard.claude_homes", Title: title, Severity: SeverityPass,
			Message: "the control plane denies no identity whose Claude home a hub member would remove",
		})
	default:
		add(Finding{
			Check: "offboard.claude_homes", Title: title, Severity: SeverityPass,
			Message: fmt.Sprintf("no Claude home of the %d identit(ies) the control plane denies is left on this "+
				"host's %d tree(s)", len(denied), len(trees)),
		})
	}
}
