package cmd

// `cloop remote approvals` (Task 20427): the approvals inbox from a terminal —
// the grant requests an approver may decide and the API tokens an
// administrator may approve, soonest deadline first — and the decisions, made
// with the terminal's own `cloop login` session through the routes the
// dashboard's dialogs use. The hub decides what is listed and what may be
// done: an approver never sees their own request, and approving one aimed at
// every project takes an administrator.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/hubclient"
)

var (
	approvalsNote string
	approvalsTTL  time.Duration
)

var remoteApprovalsCmd = &cobra.Command{
	Use:   "approvals",
	Short: "Decide the grant requests and API tokens waiting on you",
	Long: `What waits on you on the hub: access requests you may decide — filed by somebody
else, for a credential you may grant — and API tokens a role policy suspends until an
administrator approves them. ` + "`list`" + ` shows them, soonest deadline first; ` + "`approve`" + `
and ` + "`deny`" + ` decide one. A request nobody decides lapses, and its requester has to
ask again.`,
}

var remoteApprovalsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List what is waiting on you",
	Args:  cobra.NoArgs,
	RunE:  runRemoteApprovalsList,
}

var remoteApprovalsApproveCmd = &cobra.Command{
	Use:   "approve <id>",
	Short: "Approve a grant request (minting the grant it asks for) or an API token",
	Long: `Approve the item <id> from ` + "`cloop remote approvals list`" + `, given whole: a prefix that named
one item when you listed could name another once that one is decided.

A grant request is approved as asked: the grant it mints carries the request's own
subject and allowlist. --ttl can only shorten its lifetime. An API token is approved
holding the roles it was minted with, which you must hold yourself.`,
	Args: cobra.ExactArgs(1),
	RunE: runRemoteApprovalsApprove,
}

var remoteApprovalsDenyCmd = &cobra.Command{
	Use:   "deny <id>",
	Short: "Refuse a grant request, with the reason the requester sees",
	Args:  cobra.ExactArgs(1),
	RunE:  runRemoteApprovalsDeny,
}

// approvalDeadline renders an item's deadline relative to now.
func approvalDeadline(it hubclient.ApprovalItem, now time.Time) string {
	if it.Deadline == "" {
		return "none"
	}
	t, err := time.Parse(time.RFC3339, it.Deadline)
	if err != nil {
		return it.Deadline
	}
	verb := "lapses"
	if it.Kind == "api_token" {
		verb = "expires"
	}
	d := t.Sub(now)
	if d <= 0 {
		return verb + " now"
	}
	return verb + " in " + roundDuration(d)
}

// roundDuration renders d coarsely for a table.
func roundDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd%dh", int(d/(24*time.Hour)), int(d%(24*time.Hour)/time.Hour))
	case d >= time.Hour:
		return fmt.Sprintf("%dh%dm", int(d/time.Hour), int(d%time.Hour/time.Minute))
	}
	return fmt.Sprintf("%dm", int(d/time.Minute)+1)
}

func runRemoteApprovalsList(cmd *cobra.Command, _ []string) error {
	c, err := remoteClient()
	if err != nil {
		return err
	}
	inbox, err := c.Approvals(remoteContext(cmd))
	if err != nil {
		return remoteErr(c, err)
	}
	out := cmd.OutOrStdout()
	if remoteJSON {
		return json.NewEncoder(out).Encode(inbox)
	}
	printApprovals(out, inbox, time.Now())
	return nil
}

func printApprovals(out io.Writer, inbox *hubclient.Approvals, now time.Time) {
	if len(inbox.Items) == 0 {
		fmt.Fprintln(out, "Nothing is waiting on you.")
	} else {
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "KIND\tID\tWHO\tWHAT\tFOR\tDEADLINE")
		for _, it := range inbox.Items {
			switch {
			case it.Request != nil:
				r := it.Request
				what := orDash(termText(r.SecretName))
				if r.Kind != "" {
					what += " (" + termText(r.Kind) + ")"
				}
				fmt.Fprintf(w, "request\t%s\t%s\t%s\t%s\t%s\n", termText(it.ID), orDash(termText(r.RequestedBy)), what,
					termText(r.Subject), approvalDeadline(it, now))
			case it.Token != nil:
				t := it.Token
				fmt.Fprintf(w, "token\t%s\t%s\t%s\t%s\t%s\n", termText(it.ID), orDash(termText(t.CreatedBy)),
					orDash(termText(t.Name)), "roles "+termText(strings.Join(t.Roles, ",")), approvalDeadline(it, now))
			}
		}
		_ = w.Flush()
		for _, it := range inbox.Items {
			if it.Request != nil && strings.TrimSpace(it.Request.Justification) != "" {
				fmt.Fprintf(out, "%s: %s\n", termText(it.ID),
					truncateField(strings.Join(strings.Fields(termText(it.Request.Justification)), " "), 160))
			}
		}
	}
	pending := 0
	for _, m := range inbox.Mine {
		if m.State == "pending" {
			pending++
		}
	}
	if pending > 0 {
		fmt.Fprintf(out, "%d request(s) of your own are waiting on somebody else: cloop remote grants list\n", pending)
	}
}

// termText makes text somebody else typed safe to print to a terminal. A
// control character — an escape sequence's ESC, a carriage return, a C1
// control — or a bidirectional override could repaint or reorder what the
// approver reads, so each becomes a space. --json needs none of this: the
// encoder escapes them.
func termText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, s)
}

// resolveApproval finds the item an argument names, by its whole id. ok is
// false when nothing waiting on the caller has it. A prefix is not enough: the
// one that named a single item when the approver listed could name another
// once that item is decided, and approving mints a grant.
func resolveApproval(inbox *hubclient.Approvals, ref string) (hubclient.ApprovalItem, bool) {
	ref = strings.TrimSpace(ref)
	for _, it := range inbox.Items {
		if it.ID == ref {
			return it, true
		}
	}
	return hubclient.ApprovalItem{}, false
}

// approvalTarget resolves ref against the caller's inbox. A request id that
// is not in it is still sent — the hub then says why it may not be decided
// (somebody else decided it first, it is the caller's own, it lapsed) — while
// anything else is refused here.
func approvalTarget(cmd *cobra.Command, c *hubclient.Client, ref string) (hubclient.ApprovalItem, error) {
	inbox, err := c.Approvals(remoteContext(cmd))
	if err != nil {
		return hubclient.ApprovalItem{}, remoteErr(c, err)
	}
	it, ok := resolveApproval(inbox, ref)
	if ok {
		return it, nil
	}
	if ref = strings.TrimSpace(ref); ref != "" {
		for _, other := range inbox.Items {
			if strings.HasPrefix(other.ID, ref) {
				return it, fmt.Errorf("%q is only the start of an id — give the id whole (%s); a prefix that "+
					"names one item now can name another once that one is decided", ref, other.ID)
			}
		}
	}
	if strings.HasPrefix(strings.TrimSpace(ref), "req_") {
		return hubclient.ApprovalItem{Kind: "grant_request", ID: strings.TrimSpace(ref)}, nil
	}
	return it, fmt.Errorf("nothing waiting on you has the id %q — see cloop remote approvals list, and give the "+
		"id whole", ref)
}

func runRemoteApprovalsApprove(cmd *cobra.Command, args []string) error {
	c, err := remoteClient()
	if err != nil {
		return err
	}
	it, err := approvalTarget(cmd, c, args[0])
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	ctx := remoteContext(cmd)
	if it.Kind == "api_token" {
		if approvalsTTL != 0 || approvalsNote != "" {
			return errors.New("an API token is approved as it was minted: --ttl and --note apply to grant requests")
		}
		if err := c.ApproveToken(ctx, it.ID); err != nil {
			return remoteErr(c, err)
		}
		if remoteJSON {
			return json.NewEncoder(out).Encode(map[string]any{"ok": true, "id": it.ID, "kind": it.Kind})
		}
		fmt.Fprintf(out, "Approved API token %s.\n", it.ID)
		return nil
	}
	if approvalsTTL < 0 || (approvalsTTL > 0 && approvalsTTL < time.Minute) {
		// Under a minute would round to no --ttl at all, which issues the
		// grant for as long as the request asked.
		return errors.New("--ttl must be a minute or more: it shortens the grant the request asked for")
	}
	res, err := c.ApproveGrantRequest(ctx, it.ID, approvalsNote, int(approvalsTTL/time.Minute))
	if err != nil {
		return remoteErr(c, err)
	}
	if remoteJSON {
		return json.NewEncoder(out).Encode(res)
	}
	until := ""
	if !res.Request.GrantExpiresAt.IsZero() {
		until = ", until " + res.Request.GrantExpiresAt.Local().Format("2006-01-02 15:04 MST")
	}
	fmt.Fprintf(out, "Approved request %s: grant %s for %s on %s%s.\n", res.Request.ID, orDash(res.GrantID),
		termText(res.Request.Subject), orDash(termText(res.Request.SecretName)), until)
	if res.Note != "" {
		fmt.Fprintln(out, res.Note)
	}
	return nil
}

func runRemoteApprovalsDeny(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(approvalsNote) == "" {
		return errors.New("a denial needs a reason the requester can act on: pass --note \"…\"")
	}
	c, err := remoteClient()
	if err != nil {
		return err
	}
	it, err := approvalTarget(cmd, c, args[0])
	if err != nil {
		return err
	}
	if it.Kind == "api_token" {
		return errors.New("an API token is not denied: revoke it (Secrets → API tokens in the dashboard, " +
			"or cloop hub token revoke on the hub)")
	}
	res, err := c.DenyGrantRequest(remoteContext(cmd), it.ID, approvalsNote)
	if err != nil {
		return remoteErr(c, err)
	}
	out := cmd.OutOrStdout()
	if remoteJSON {
		return json.NewEncoder(out).Encode(res)
	}
	fmt.Fprintf(out, "Denied request %s from %s.\n", res.Request.ID, orDash(termText(res.Request.RequestedBy)))
	return nil
}

func init() {
	remoteApprovalsListCmd.Flags().BoolVar(&remoteJSON, "json", false, "Print JSON")
	ap := remoteApprovalsApproveCmd.Flags()
	ap.StringVar(&approvalsNote, "note", "", "A note recorded with the approval")
	ap.DurationVar(&approvalsTTL, "ttl", 0, "Issue a shorter grant than the request asked for (it can only narrow)")
	ap.BoolVar(&remoteJSON, "json", false, "Print the decision as JSON")
	dn := remoteApprovalsDenyCmd.Flags()
	dn.StringVar(&approvalsNote, "note", "", "Why — the requester sees it (required)")
	dn.BoolVar(&remoteJSON, "json", false, "Print the decision as JSON")
	remoteApprovalsCmd.AddCommand(remoteApprovalsListCmd, remoteApprovalsApproveCmd, remoteApprovalsDenyCmd)
	remoteCmd.AddCommand(remoteApprovalsCmd)
}
