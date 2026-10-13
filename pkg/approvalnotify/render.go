package approvalnotify

// Rendering a notice for a webhook type.
//
// Each type gets its own body, and each body treats every string it did not
// write itself — an identity, a secret's name, a subject, a token's name — as
// hostile text. Two things can go wrong with such a string, and each has its
// own guard:
//
//   - It can carry a credential. A token named after a PAT, a subject pasted
//     with a key in it: whatever the string is, it goes through
//     redact.Scrub, the registry every credential scanner in cloop shares,
//     before any renderer sees it.
//   - It can carry markup the channel acts on: a Slack <!channel>, a Discord
//     @everyone or masked link, a Teams markdown link. Slack's three special
//     characters are escaped, Discord's markdown is backslash-escaped and its
//     mentions are switched off in the payload, and the Teams card puts every
//     such string in a TextRun, which Adaptive Cards never read as markdown.
//
// Strings are also clipped: a channel that truncates on its own would cut in
// the middle of an escape, and a body over the channel's limit is refused
// outright, which here would mean an approver is never told.

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/redact"
)

// MaxBodyBytes bounds a rendered message. Every channel's own limit is well
// under it; it exists so that no input can make the hub POST megabytes.
const MaxBodyBytes = 32 << 10

// maxValueRunes clips one rendered value.
const maxValueRunes = 200

// fact is one labelled line of a message.
type fact struct {
	label, value string
}

// message is a notice in words, before a webhook type shapes it.
type message struct {
	title string
	facts []fact
	link  string
	at    time.Time
	// color is the accent Discord and Teams draw the message in.
	color int
}

// clean prepares a string the hub did not write: control characters and the
// Unicode line and paragraph separators become spaces, credential shapes become
// the scrubber's marker, and the result is clipped.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, s)
	s = redact.Scrub(strings.TrimSpace(s))
	if utf8.RuneCountInString(s) > maxValueRunes {
		r := []rune(s)
		s = string(r[:maxValueRunes-1]) + "…"
	}
	return s
}

// orDash renders an empty value.
func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// when renders a deadline for a reader in any time zone: UTC, and how far off
// it is.
func when(t, now time.Time) string {
	if t.IsZero() {
		return ""
	}
	stamp := t.UTC().Format("2006-01-02 15:04 UTC")
	d := t.Sub(now)
	switch {
	case d > 0:
		return stamp + " (in " + humanDuration(d) + ")"
	case d < 0:
		return stamp + " (" + humanDuration(-d) + " ago)"
	}
	return stamp
}

// humanDuration renders d coarsely: "2 d 4 h", "11 h", "35 min".
func humanDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		days := int(d / (24 * time.Hour))
		hours := int((d % (24 * time.Hour)) / time.Hour)
		if hours == 0 {
			return fmt.Sprintf("%d d", days)
		}
		return fmt.Sprintf("%d d %d h", days, hours)
	case d >= time.Hour:
		return fmt.Sprintf("%d h", int((d+30*time.Minute)/time.Hour))
	case d >= time.Minute:
		return fmt.Sprintf("%d min", int(d/time.Minute))
	}
	return "under a minute"
}

// compose puts a notice into words.
func compose(n Notice, link string, now time.Time) message {
	m := message{link: link, at: n.At, color: 0x3b82f6}
	who := orDash(clean(n.RequestedBy))
	secret := clean(n.SecretName)
	if kind := clean(n.SecretKind); kind != "" && secret != "" {
		secret += " (" + kind + ")"
	}
	secret = orDash(secret)
	subject := orDash(clean(n.Subject))
	requestFacts := func(withDeadline bool) []fact {
		f := []fact{{"Requested by", who}, {"Credential", secret}, {"For", subject}}
		if withDeadline && !n.Deadline.IsZero() {
			f = append(f, fact{"Decide by", when(n.Deadline, now)})
		}
		return append(f, fact{"Request", orDash(clean(n.RequestID))})
	}
	decider := orDash(clean(n.DecidedBy))

	switch n.Event {
	case config.NotifyEventRequestFiled:
		m.title = "Access request waiting for a decision: " + who + " asks for " + secret
		m.facts = requestFacts(true)
	case config.NotifyEventRequestReminder:
		m.title = "Reminder: an access request lapses undecided " + strings.TrimPrefix(lapseIn(n.Deadline, now), " ") +
			" — " + who + " asks for " + secret
		m.facts = requestFacts(true)
		m.color = 0xf59e0b
	case config.NotifyEventRequestApproved:
		m.title = "Access request approved by " + decider
		m.facts = append(requestFacts(false), fact{"Approved by", decider})
		m.color = 0x22c55e
	case config.NotifyEventRequestDenied:
		m.title = "Access request denied by " + decider
		m.facts = append(requestFacts(false), fact{"Denied by", decider})
		m.color = 0xef4444
	case config.NotifyEventRequestWithdrawn:
		m.title = "Access request withdrawn by " + decider
		m.facts = append(requestFacts(false), fact{"Withdrawn by", decider})
		m.color = 0x6b7280
	case config.NotifyEventRequestLapsed:
		m.title = "Access request lapsed undecided: " + who + " asked for " + secret
		m.facts = requestFacts(false)
		m.color = 0x6b7280
	case config.NotifyEventTokenWaiting:
		name := orDash(clean(n.TokenName))
		m.title = "API token waiting for an administrator's approval: " + name
		roles := make([]string, 0, len(n.Roles))
		for _, r := range n.Roles {
			if c := clean(r); c != "" {
				roles = append(roles, c)
			}
		}
		expires := "never"
		if !n.Deadline.IsZero() {
			expires = when(n.Deadline, now)
		}
		m.facts = []fact{
			{"Token", name}, {"Roles", orDash(clean(strings.Join(roles, ", ")))},
			{"Minted by", orDash(clean(n.CreatedBy))}, {"Expires", expires},
			{"Token id", orDash(clean(n.TokenID))},
		}
		m.color = 0xf59e0b
	case EventTest:
		m.title = "Test notification from cloop: this webhook will be told when an access request or an API token waits on an approver"
	default:
		m.title = "cloop: " + orDash(clean(n.Event))
	}
	return m
}

// lapseIn says how long until a deadline, for a title.
func lapseIn(deadline, now time.Time) string {
	if deadline.IsZero() {
		return ""
	}
	if d := deadline.Sub(now); d > 0 {
		return "in " + humanDuration(d)
	}
	return "now"
}

// Render builds the body a webhook of type kind is sent for n. link is the
// dashboard address a message points at, or empty for none.
func Render(kind string, n Notice, link string, now time.Time) ([]byte, error) {
	m := compose(n, link, now)
	var (
		body []byte
		err  error
	)
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case config.NotifySlack:
		body, err = renderSlack(m)
	case config.NotifyTeams:
		body, err = renderTeams(m)
	case config.NotifyDiscord:
		body, err = renderDiscord(m)
	case config.NotifyJSON:
		body, err = renderJSON(n, m)
	default:
		return nil, fmt.Errorf("approvalnotify: unknown webhook type %q", kind)
	}
	if err != nil {
		return nil, err
	}
	if len(body) > MaxBodyBytes {
		return nil, fmt.Errorf("approvalnotify: the %s message is %d bytes, over %d", kind, len(body), MaxBodyBytes)
	}
	return body, nil
}

// marshal encodes without HTML escaping: the bodies are read by chat services,
// not embedded in a page, and < in a Slack message is text, not a tag.
func marshal(v any) ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(b.String(), "\n")), nil
}

// ── Slack ───────────────────────────────────────────────────────────────────

// slackEscape escapes the three characters Slack's mrkdwn gives meaning to.
// With them escaped nothing in the text can open a <!channel>, a user mention
// or a link.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func renderSlack(m message) ([]byte, error) {
	fields := make([]map[string]any, 0, len(m.facts))
	for i, f := range m.facts {
		if i == 10 { // Slack's limit per section
			break
		}
		fields = append(fields, map[string]any{
			"type": "mrkdwn",
			"text": "*" + slackEscape(f.label) + "*\n" + slackEscape(f.value),
		})
	}
	blocks := []map[string]any{
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": "*" + slackEscape(m.title) + "*"}},
	}
	if len(fields) > 0 {
		blocks = append(blocks, map[string]any{"type": "section", "fields": fields})
	}
	if m.link != "" {
		blocks = append(blocks, map[string]any{
			"type": "actions",
			"elements": []map[string]any{{
				"type": "button",
				"text": map[string]any{"type": "plain_text", "text": "Open approvals"},
				"url":  m.link,
			}},
		})
	}
	return marshal(map[string]any{
		"text":         slackEscape(m.title),
		"blocks":       blocks,
		"unfurl_links": false,
		"unfurl_media": false,
	})
}

// ── Microsoft Teams (Workflows, Adaptive Card) ──────────────────────────────

// teamsRun is a run of text an Adaptive Card shows as it is: a TextRun is
// never parsed as markdown, which is why every string the hub did not write is
// one.
func teamsRun(text string, bold bool) map[string]any {
	r := map[string]any{"type": "TextRun", "text": text}
	if bold {
		r["weight"] = "Bolder"
	}
	return r
}

func renderTeams(m message) ([]byte, error) {
	title := teamsRun(m.title, true)
	title["size"] = "Medium"
	body := []map[string]any{{"type": "RichTextBlock", "inlines": []map[string]any{title}}}
	for _, f := range m.facts {
		body = append(body, map[string]any{
			"type":    "RichTextBlock",
			"spacing": "Small",
			"inlines": []map[string]any{teamsRun(f.label+": ", true), teamsRun(f.value, false)},
		})
	}
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.4",
		"body":    body,
		"msteams": map[string]any{"width": "Full"},
	}
	if m.link != "" {
		card["actions"] = []map[string]any{{"type": "Action.OpenUrl", "title": "Open approvals", "url": m.link}}
	}
	return marshal(map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"contentUrl":  nil,
			"content":     card,
		}},
	})
}

// ── Discord ─────────────────────────────────────────────────────────────────

// discordEscape backslash-escapes the characters Discord's markdown acts on,
// so a name cannot become a masked link, a spoiler, a code span or a mention
// pill, and a value cannot open with a heading, a quote or a list. Mentions
// are also switched off in the payload (allowed_mentions), so an @everyone
// that got past this would still ping nobody.
func discordEscape(s string) string {
	var b strings.Builder
	for i, r := range s {
		if strings.ContainsRune("\\*_~`|[]<@", r) || (i == 0 && strings.ContainsRune("#>-", r)) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// clipRunes cuts s to at most n runes.
func clipRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func renderDiscord(m message) ([]byte, error) {
	fields := make([]map[string]any, 0, len(m.facts))
	for _, f := range m.facts {
		fields = append(fields, map[string]any{
			"name":   clipRunes(f.label, 256),
			"value":  clipRunes(orDash(discordEscape(f.value)), 1024),
			"inline": true,
		})
	}
	embed := map[string]any{
		"title":  clipRunes(m.title, 256),
		"color":  m.color,
		"fields": fields,
	}
	if !m.at.IsZero() {
		embed["timestamp"] = m.at.UTC().Format(time.RFC3339)
	}
	if m.link != "" {
		embed["url"] = m.link
	}
	return marshal(map[string]any{
		"username":         "cloop",
		"content":          clipRunes(discordEscape(m.title), 2000),
		"embeds":           []map[string]any{embed},
		"allowed_mentions": map[string]any{"parse": []string{}},
	})
}

// ── Generic JSON ────────────────────────────────────────────────────────────

func renderJSON(n Notice, m message) ([]byte, error) {
	out := map[string]any{
		"source": "cloop",
		"kind":   "approval",
		"event":  n.Event,
		"title":  m.title,
	}
	if !n.At.IsZero() {
		out["at"] = n.At.UTC().Format(time.RFC3339)
	}
	if m.link != "" {
		out["link"] = m.link
	}
	stamp := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	}
	switch {
	case n.RequestID != "":
		req := map[string]any{
			"id":           clean(n.RequestID),
			"requested_by": clean(n.RequestedBy),
			"secret_name":  clean(n.SecretName),
			"secret_kind":  clean(n.SecretKind),
			"subject":      clean(n.Subject),
		}
		if d := stamp(n.Deadline); d != "" {
			req["deadline"] = d
		}
		if n.DecidedBy != "" {
			req["decided_by"] = clean(n.DecidedBy)
		}
		out["request"] = req
	case n.TokenID != "":
		roles := make([]string, 0, len(n.Roles))
		for _, r := range n.Roles {
			roles = append(roles, clean(r))
		}
		tok := map[string]any{
			"id":         clean(n.TokenID),
			"name":       clean(n.TokenName),
			"roles":      roles,
			"created_by": clean(n.CreatedBy),
		}
		if d := stamp(n.Deadline); d != "" {
			tok["expires_at"] = d
		}
		out["token"] = tok
	}
	return marshal(out)
}
