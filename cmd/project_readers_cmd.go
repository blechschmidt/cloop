package cmd

// `cloop project readers` (Task 20498): which other projects may read a
// project, from a terminal.
//
//	cloop project readers ls  <project>            who may read it, and what it may read
//	cloop project readers add <project> <reader>   let <reader> read <project>
//	cloop project readers rm  <project> <reader>   stop <reader> reading <project>
//
// Unlike `cloop project members`, which writes the hub's database directly,
// this is a client of the hub: the dashboard's own routes, made with this
// terminal's session (`cloop login`), an API token, or nothing at all for a
// hub on this machine without sign-in. So the hub decides, as it does for the
// dashboard: anyone who can see a project may list its readers, only its
// administrators may change them, and a project is named only to someone who
// can see it.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/hubclient"
)

var (
	preadersHub   string
	preadersToken string
	preadersJSON  bool
)

// readerEntryIDPattern is the shape of an entry id the hub issues.
var readerEntryIDPattern = regexp.MustCompile(`^prd_[0-9a-f]{24}$`)

var projectReadersCmd = &cobra.Command{
	Use:   "readers",
	Short: "List, add and remove the other projects that may read a project",
	Long: `A project's readers list names the other projects whose runs may read it. It is
deny-by-default: no project reads another unless the other's list names it, and
nothing else makes it so. A project is never on its own list, and a feature is
never on a list: name its project.

Anyone who can see a project may list its readers, and the projects it may
read. Only its administrators change the list: its owner, a member at admin, a
hub administrator, and on a hub without sign-in whoever holds its static admin
token. On a hub with single sign-on a change also needs a recent sign-in (run
` + "`cloop login`" + ` again when asked). You can only add a project you can see.

<project> and <reader> are a project's name, its index or its path, as
` + "`cloop remote projects`" + ` lists them. ` + "`rm`" + ` also takes the path or the entry id
(prd_…) of a reader you cannot see, from ` + "`ls`" + `.

The command talks to the hub: --hub, CLOOP_HUB_URL, the hub ` + "`cloop login`" + `
signed this terminal in to, or else the hub on this machine.`,
	Example: `  cloop project readers ls shop
  cloop project readers add shop billing
  cloop project readers rm shop billing
  cloop project readers rm shop prd_3f9c2a7d10b4e865a1b2c3d4`,
}

var projectReadersListCmd = &cobra.Command{
	Use:     "ls <project>",
	Aliases: []string{"list"},
	Short:   "List the projects that may read a project, and the projects it may read",
	Args:    cobra.ExactArgs(1),
	RunE:    runProjectReadersList,
}

var projectReadersAddCmd = &cobra.Command{
	Use:   "add <project> <reader>",
	Short: "Let the runs of <reader> read <project>",
	Args:  cobra.ExactArgs(2),
	RunE:  runProjectReadersAdd,
}

var projectReadersRemoveCmd = &cobra.Command{
	Use:     "rm <project> <reader>",
	Aliases: []string{"remove"},
	Short:   "Stop the runs of <reader> reading <project>",
	Args:    cobra.ExactArgs(2),
	RunE:    runProjectReadersRemove,
}

// readersAnswer is GET /api/projects/{idx}/readers.
type readersAnswer struct {
	Project        string         `json:"project"`
	Path           string         `json:"path"`
	Readers        []readerEntry  `json:"readers"`
	HiddenReaders  int            `json:"hidden_readers"`
	Hidden         []hiddenReader `json:"hidden,omitempty"`
	Readable       []readerEntry  `json:"readable"`
	HiddenReadable int            `json:"hidden_readable"`
	CanManage      bool           `json:"can_manage"`
	Feature        bool           `json:"feature,omitempty"`
	Note           string         `json:"note,omitempty"`
}

type readerEntry struct {
	ID      string    `json:"id"`
	Project string    `json:"project"`
	Path    string    `json:"path"`
	Idx     int       `json:"idx"`
	AddedBy string    `json:"added_by,omitempty"`
	AddedAt time.Time `json:"added_at"`
}

type hiddenReader struct {
	ID      string    `json:"id"`
	AddedBy string    `json:"added_by,omitempty"`
	AddedAt time.Time `json:"added_at"`
}

// readersURL is the readers route of the project at idx.
func readersURL(idx int) string { return fmt.Sprintf("/api/projects/%d/readers", idx) }

// readersClient is the hub this command acts on, and the project it names.
func readersClient(ctx context.Context, ref string) (*hubclient.Client, hubclient.Project, error) {
	c, err := localOrLoginHubClient(preadersHub, preadersToken)
	if err != nil {
		return nil, hubclient.Project{}, err
	}
	p, err := c.ResolveProject(ctx, ref)
	if err != nil {
		return c, hubclient.Project{}, moveErr(c, err)
	}
	return c, p, nil
}

func runProjectReadersList(cmd *cobra.Command, args []string) error {
	ctx := remoteContext(cmd)
	c, p, err := readersClient(ctx, args[0])
	if err != nil {
		return err
	}
	var ans readersAnswer
	if err := c.Do(ctx, http.MethodGet, readersURL(p.Idx), nil, nil, &ans); err != nil {
		return moveErr(c, err)
	}
	out := cmd.OutOrStdout()
	if preadersJSON {
		return writeJSON(out, ans)
	}
	writeReadersList(out, ans)
	return nil
}

// writeReadersList prints a project's list for a terminal.
func writeReadersList(out io.Writer, ans readersAnswer) {
	if ans.Feature {
		fmt.Fprintln(out, ans.Note)
		return
	}
	switch {
	case len(ans.Readers) == 0 && ans.HiddenReaders == 0:
		fmt.Fprintf(out, "No other project may read %s.\n", ans.Project)
	default:
		fmt.Fprintf(out, "Projects that may read %s (%s):\n", ans.Project, ans.Path)
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		for _, r := range ans.Readers {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", r.Project, r.Path, addedLine(r.AddedBy, r.AddedAt), r.ID)
		}
		_ = w.Flush()
		if ans.HiddenReaders > 0 {
			fmt.Fprintf(out, "  and %d more you cannot see\n", ans.HiddenReaders)
			for _, h := range ans.Hidden {
				fmt.Fprintf(out, "    %s  %s\n", h.ID, addedLine(h.AddedBy, h.AddedAt))
			}
		}
	}
	switch {
	case len(ans.Readable) == 0 && ans.HiddenReadable == 0:
		fmt.Fprintf(out, "%s reads no other project.\n", ans.Project)
	default:
		fmt.Fprintf(out, "%s may read:\n", ans.Project)
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		for _, r := range ans.Readable {
			fmt.Fprintf(w, "  %s\t%s\n", r.Project, r.Path)
		}
		_ = w.Flush()
		if ans.HiddenReadable > 0 {
			fmt.Fprintf(out, "  and %d more you cannot see\n", ans.HiddenReadable)
		}
	}
	if !ans.CanManage {
		fmt.Fprintf(out, "Only the administrators of %s change who may read it.\n", ans.Project)
	}
}

// addedLine says who added an entry, and when.
func addedLine(by string, at time.Time) string {
	when := "at an unknown time"
	if !at.IsZero() {
		when = "on " + at.Local().Format("2006-01-02 15:04")
	}
	if by == "" {
		return "added " + when
	}
	return "added by " + by + " " + when
}

func runProjectReadersAdd(cmd *cobra.Command, args []string) error {
	ctx := remoteContext(cmd)
	c, p, err := readersClient(ctx, args[0])
	if err != nil {
		return err
	}
	reader, err := c.ResolveProject(ctx, args[1])
	if err != nil {
		return moveErr(c, err)
	}
	var ans struct {
		Added  bool        `json:"added"`
		Reader readerEntry `json:"reader"`
	}
	if err := c.Do(ctx, http.MethodPut, readersURL(p.Idx), nil, map[string]any{"reader": reader.Path}, &ans); err != nil {
		return moveErr(c, err)
	}
	out := cmd.OutOrStdout()
	if preadersJSON {
		return writeJSON(out, ans)
	}
	if ans.Added {
		fmt.Fprintf(out, "%s may now read %s.\n", reader.Name, p.Name)
	} else {
		fmt.Fprintf(out, "%s could already read %s; nothing changed.\n", reader.Name, p.Name)
	}
	return nil
}

func runProjectReadersRemove(cmd *cobra.Command, args []string) error {
	ctx := remoteContext(cmd)
	c, p, err := readersClient(ctx, args[0])
	if err != nil {
		return err
	}
	q, name, err := readerToRemove(ctx, c, args[1])
	if err != nil {
		return err
	}
	var ans struct {
		OK     bool   `json:"ok"`
		ID     string `json:"id"`
		Reader string `json:"reader,omitempty"`
	}
	if err := c.Do(ctx, http.MethodDelete, readersURL(p.Idx), q, nil, &ans); err != nil {
		return moveErr(c, err)
	}
	out := cmd.OutOrStdout()
	if preadersJSON {
		return writeJSON(out, ans)
	}
	fmt.Fprintf(out, "%s may no longer read %s.\n", name, p.Name)
	return nil
}

// readerToRemove names the entry rm takes off: a project this terminal can see,
// or else — for one it cannot — the entry's id, or the path given literally.
func readerToRemove(ctx context.Context, c *hubclient.Client, ref string) (url.Values, string, error) {
	ref = strings.TrimSpace(ref)
	if readerEntryIDPattern.MatchString(ref) {
		return url.Values{"id": {ref}}, "the project in entry " + ref, nil
	}
	reader, err := c.ResolveProject(ctx, ref)
	if err == nil {
		return url.Values{"reader": {reader.Path}}, reader.Name, nil
	}
	if filepath.IsAbs(ref) {
		return url.Values{"reader": {filepath.Clean(ref)}}, filepath.Clean(ref), nil
	}
	var ae *hubclient.APIError
	if errors.As(err, &ae) {
		return nil, "", moveErr(c, err)
	}
	return nil, "", fmt.Errorf("%w — to remove a project you cannot see, give its path or the entry id `cloop project readers ls` shows", err)
}

func init() {
	for _, c := range []*cobra.Command{projectReadersListCmd, projectReadersAddCmd, projectReadersRemoveCmd} {
		c.Flags().StringVar(&preadersHub, "hub", "", "the hub's URL (default: CLOOP_HUB_URL, the hub you signed in to, or this machine's)")
		c.Flags().StringVar(&preadersToken, "token", "", "an API token for --hub, instead of your session")
		c.Flags().BoolVar(&preadersJSON, "json", false, "print the hub's answer as JSON")
	}
	projectReadersCmd.AddCommand(projectReadersListCmd, projectReadersAddCmd, projectReadersRemoveCmd)
	projectCmd.AddCommand(projectReadersCmd)
}
