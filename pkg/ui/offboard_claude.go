package ui

// offboard_claude.go: ending a departed identity's Claude Code logins on every
// hub member (Task 20400).
//
// A per-user Claude home lives under the config directory of the process that
// created it — claudecodeauth.HomeRootPath, from that process's own HOME or
// XDG_CONFIG_HOME — not on the control plane's database. Members on one
// machine under one user share one tree; members under different users, or in
// containers with their own filesystems, keep one tree each. In-flight logins
// live in a member's memory. So an offboarding that removed the copy beside
// itself would report success while another member still held a plaintext
// refresh token, and this file is how it reaches the others:
//
//   - from the dashboard, the member serving the request asks every live peer
//     over the signed peer channel (clusterAPIOffboardClaude) and folds the
//     answers in;
//   - from `cloop hub user offboard`, which is no member and cannot sign a peer
//     call, the request goes on the bus every member reads, and each member's
//     answer comes back on it, addressed to the CLI (ClaudeHomesOnMembers).
//
// Either way, a member that does not answer is named in the report, and so is
// a stopped member that kept a tree on a host that is still up, because a copy
// nobody reached may still hold a live refresh token.
//
// A member acts on another process's word only for an identity the control
// plane denies. The offboarding writes those deny bindings in its credential
// transaction, before it asks anyone; a request for anybody else is refused.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/jsonbody"
	"github.com/blechschmidt/cloop/pkg/offboard"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	// busTopicOffboard carries requests about a departed identity's Claude
	// logins from a process that is no member — the CLI — and the members'
	// answers back to it.
	busTopicOffboard = "offboard"
	// busKeyClaudeRequest and busKeyClaudeReply are its two messages.
	busKeyClaudeRequest = "claude"
	busKeyClaudeReply   = "claude_reply"

	// claudeOpInspect and claudeOpSever are what a request asks for.
	claudeOpInspect = "inspect"
	claudeOpSever   = "sever"

	// memberEndpointClaudeHomes is the member-row endpoint naming where a
	// member keeps its Claude homes, so a stopped member's tree can be told
	// apart from the trees the run reached. A path, not a URL: it is read by
	// processes on the same machine.
	memberEndpointClaudeHomes = "claude_homes"
)

// claudeOffboardRequest is what one process asks another about Claude logins.
//
// No actor and no reason: the member asked records nothing — the offboarding
// process writes the one audit row for every copy — and the reason, often an
// HR matter, has no business on the bus, where it would sit in hub_events for
// every process with the database open to read.
type claudeOffboardRequest struct {
	// ID correlates a bus request with its answers. Unused on the peer
	// channel, where the answer is the response.
	ID   string   `json:"id,omitempty"`
	Op   string   `json:"op"`
	Keys []string `json:"keys"`
	Keep bool     `json:"keep,omitempty"`
}

// claudeOffboardAnswer is one member's answer.
type claudeOffboardAnswer struct {
	RequestID string                      `json:"request_id,omitempty"`
	Member    string                      `json:"member"`
	Hostname  string                      `json:"hostname,omitempty"`
	Root      string                      `json:"root,omitempty"`
	Homes     []offboard.ClaudeHomeRef    `json:"homes,omitempty"`
	Results   []offboard.ClaudeHomeResult `json:"results,omitempty"`
	// Error is a refusal or a failure that kept the member from acting at
	// all. Per-copy failures are on Results.
	Error string `json:"error,omitempty"`
}

// ClaudeHomesRoot is where this process keeps per-user Claude homes, for the
// member row (cmd/ui_cluster.go). Empty when the process has no config
// directory to resolve one from.
func ClaudeHomesRoot() string {
	root, err := claudecodeauth.HomeRootPath()
	if err != nil {
		return ""
	}
	return root
}

// claudeRoot is where this member keeps per-user Claude homes.
func (s *Server) claudeRoot() string {
	if s.claudeHomesRoot != "" {
		return s.claudeHomesRoot
	}
	return ClaudeHomesRoot()
}

// offboardLocalClaude is this process's own Claude login surface.
func (s *Server) offboardLocalClaude() offboard.LocalClaude {
	member := ""
	if n := s.clusterNode(); n != nil {
		member = n.ID()
	}
	return offboard.LocalClaude{
		Manager: s.claudeAuthManager(),
		Member:  member,
		Root:    s.claudeHomesRoot,
		// Strict no-host-execution is enforced inside the step: under it the
		// home is removed, the logout skipped, and the report says which.
		// A login claimed by this member is given up with the login, so a
		// later request for the same identity is not routed to a member that
		// holds nothing.
		OnLoginCancelled: func(key string) { s.releaseClusterClaim(ownerCCAuth, key) },
		Logout:           testClaudeLogout,
	}
}

// testClaudeLogout, when set, stands in for `claude auth logout`, so a test can
// watch the hub log a copy out without the real CLI talking to Anthropic. Nil
// in production, which runs the real one.
var testClaudeLogout func(ctx context.Context, configDir string) error

// offboardClaude is the Claude surface of an offboarding served here: this
// member's copies, and every other live member's.
func (s *Server) offboardClaude() offboard.ClaudeHomes {
	return clusterClaude{s: s}
}

// clusterClaude implements offboard.ClaudeHomes across hub members.
type clusterClaude struct{ s *Server }

func (c clusterClaude) Inspect(keys []string) ([]offboard.ClaudeHomeRef, []offboard.ClaudeUnreached, error) {
	homes, _, err := c.s.offboardLocalClaude().Inspect(keys)
	answers, unreached := c.s.askPeersAboutClaude(claudeOffboardRequest{Op: claudeOpInspect, Keys: keys})
	for _, a := range answers {
		homes = append(homes, a.Homes...)
	}
	unreached = append(unreached, c.s.strandedClaudeTrees(keys, answers)...)
	return homes, unreached, err
}

func (c clusterClaude) Sever(keys []string, keep bool, actor, reason string) ([]offboard.ClaudeHomeResult, []offboard.ClaudeUnreached, error) {
	// This member's copies first, then the others': members that share a
	// tree then find it already gone rather than racing each other to log
	// the same directory out.
	results, _, err := c.s.offboardLocalClaude().Sever(keys, keep, actor, reason)
	answers, unreached := c.s.askPeersAboutClaude(claudeOffboardRequest{
		Op: claudeOpSever, Keys: keys, Keep: keep,
	})
	for _, a := range answers {
		results = append(results, a.Results...)
	}
	unreached = append(unreached, c.s.strandedClaudeTrees(keys, answers)...)
	return results, unreached, err
}

// askPeersAboutClaude puts one request to every other live member and splits
// the outcome into answers and members that could not be asked.
func (s *Server) askPeersAboutClaude(req claudeOffboardRequest) ([]claudeOffboardAnswer, []offboard.ClaudeUnreached) {
	if !s.clusterPeersAlive() {
		return nil, nil
	}
	results, errs := s.fanOut(context.Background(), http.MethodPost, clusterAPIOffboardClaude, req,
		func() any { return &claudeOffboardAnswer{} })
	var answers []claudeOffboardAnswer
	var unreached []offboard.ClaudeUnreached
	for member, v := range results {
		a, ok := v.(*claudeOffboardAnswer)
		if !ok || a == nil {
			continue
		}
		if a.Member == "" {
			a.Member = member
		}
		if a.Error != "" {
			unreached = append(unreached, offboard.ClaudeUnreached{Member: a.Member, Detail: a.Error})
		}
		answers = append(answers, *a)
	}
	for member, err := range errs {
		unreached = append(unreached, offboard.ClaudeUnreached{Member: member, Detail: peerFailure(err)})
	}
	sort.Slice(answers, func(i, j int) bool { return answers[i].Member < answers[j].Member })
	sortUnreached(unreached)
	return answers, unreached
}

// peerFailure explains a member that could not be asked, naming the one cause
// an operator can act on: a build too old to know the request.
func peerFailure(err error) string {
	var ce *hubcluster.CallError
	if errors.As(err, &ce) && ce.Status == http.StatusNotFound {
		return "it does not know this request — it runs a build older than this one; " +
			"upgrade it, or remove its copies by hand"
	}
	return err.Error()
}

// strandedClaudeTrees names stopped members that kept Claude homes in a tree
// nobody reached, on a host this run did reach — so their files are still
// there. A stopped member on a host the run cannot see is left out: its
// container, and everything it wrote, is most likely gone with it.
func (s *Server) strandedClaudeTrees(keys []string, answers []claudeOffboardAnswer) []offboard.ClaudeUnreached {
	n := s.clusterNode()
	if n == nil {
		return nil
	}
	self := n.Self()
	reached := []claudeTree{{host: self.Hostname, root: s.claudeRoot()}}
	for _, a := range answers {
		reached = append(reached, claudeTree{host: a.Hostname, root: a.Root})
	}
	var stopped []claudeTree
	for _, m := range n.Members() {
		if m.Alive || m.Self {
			continue
		}
		stopped = append(stopped, claudeTree{member: m.ID, host: m.Hostname,
			root: m.Endpoint(memberEndpointClaudeHomes), at: m.HeartbeatAt})
	}
	return strandedTrees(keys, reached, stopped)
}

// claudeTree is one process's Claude home root on one host.
type claudeTree struct {
	member string
	host   string
	root   string
	at     time.Time
}

// strandedTrees is the decision strandedClaudeTrees and the CLI share.
func strandedTrees(keys []string, reached, stopped []claudeTree) []offboard.ClaudeUnreached {
	hosts := map[string]bool{}
	seen := map[string]bool{}
	for _, t := range reached {
		hosts[t.host] = true
		seen[t.host+"\x00"+t.root] = true
	}
	var out []offboard.ClaudeUnreached
	for _, t := range stopped {
		if t.root == "" || !hosts[t.host] || seen[t.host+"\x00"+t.root] {
			continue
		}
		seen[t.host+"\x00"+t.root] = true
		var dirs []string
		for _, k := range keys {
			if strings.TrimSpace(k) != "" {
				dirs = append(dirs, t.root+string(os.PathSeparator)+claudecodeauth.IdentitySlug(k))
			}
		}
		out = append(out, offboard.ClaudeUnreached{Member: t.member, Detail: fmt.Sprintf(
			"stopped (last seen %s) and kept Claude logins under %s on %s, which no running process reads; "+
				"remove %s there by hand", t.at.UTC().Format(time.RFC3339), t.root, t.host,
			strings.Join(uniqueStrings(dirs), " and "))})
	}
	sortUnreached(out)
	return out
}

func sortUnreached(u []offboard.ClaudeUnreached) {
	sort.Slice(u, func(i, j int) bool { return u[i].Member < u[j].Member })
}

// claudeOffboardRemote answers another process's request: a peer's, over the
// peer channel, or the CLI's, over the bus.
func (s *Server) claudeOffboardRemote(req claudeOffboardRequest) claudeOffboardAnswer {
	ans := claudeOffboardAnswer{RequestID: req.ID, Root: s.claudeRoot()}
	if n := s.clusterNode(); n != nil {
		ans.Member, ans.Hostname = n.ID(), n.Self().Hostname
	}
	local := s.offboardLocalClaude()
	switch req.Op {
	case claudeOpInspect:
		homes, _, err := local.Inspect(req.Keys)
		ans.Homes = homes
		if err != nil {
			ans.Error = err.Error()
		}
	case claudeOpSever:
		keys, refused, err := s.deniedKeys(req.Keys)
		if err != nil {
			ans.Error = "could not confirm the identity is offboarded, so nothing was ended: " + err.Error()
			return ans
		}
		if len(refused) > 0 {
			ans.Error = fmt.Sprintf("refused to end the Claude logins of %s: the control plane does not deny "+
				"that identity, and a member ends logins on another process's word only for one it does",
				strings.Join(refused, ", "))
		}
		if len(keys) == 0 {
			return ans
		}
		results, _, err := local.Sever(keys, req.Keep, "", "")
		ans.Results = results
		if err != nil && ans.Error == "" {
			ans.Error = err.Error()
		}
	default:
		ans.Error = fmt.Sprintf("unknown request %q", req.Op)
	}
	return ans
}

// deniedKeys splits owner keys into those the control plane denies outright —
// a global deny binding on the email or the subject — and the rest.
func (s *Server) deniedKeys(keys []string) (denied, refused []string, err error) {
	db, err := s.controlPlaneDB()
	if err != nil {
		return nil, nil, err
	}
	defer db.Close()
	rows, err := db.ListRoleBindings()
	if err != nil {
		return nil, nil, fmt.Errorf("read role bindings: %w", err)
	}
	deny := map[string]bool{}
	for _, b := range rows {
		if b.Effect != statedb.RoleEffectDeny || b.Project != "" || b.Executor != "" {
			continue
		}
		switch b.Claim {
		case "email":
			deny[strings.ToLower(strings.TrimSpace(b.Value))] = true
		case "sub":
			deny["sub:"+strings.TrimSpace(b.Value)] = true
		}
	}
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		key := k
		if !strings.HasPrefix(k, "sub:") {
			key = strings.ToLower(k)
		}
		if deny[key] {
			denied = append(denied, k)
		} else {
			refused = append(refused, k)
		}
	}
	return denied, refused, nil
}

// handleClusterOffboardClaude is the peer side of askPeersAboutClaude.
func (s *Server) handleClusterOffboardClaude(w http.ResponseWriter, r *http.Request) {
	var req claudeOffboardRequest
	if !jsonbody.Decode(w, r, &req, jsonbody.Options{Limit: 64 << 10}) {
		return
	}
	if len(req.Keys) == 0 || len(req.Keys) > maxOffboardKeys {
		jsonErr(w, fmt.Sprintf("between 1 and %d owner keys are required", maxOffboardKeys), http.StatusBadRequest)
		return
	}
	jsonOK(w, s.claudeOffboardRemote(req))
}

// maxOffboardKeys bounds one request's owner keys. One person resolves to a
// handful of spellings; a request naming hundreds is not an offboarding.
const maxOffboardKeys = 64

// onBusOffboard answers a request the CLI put on the bus. It runs on the bus
// goroutine, which must not block, and logging a home out is a round trip to
// Anthropic, so the work and the reply happen on a goroutine of their own.
func (s *Server) onBusOffboard(ev hubcluster.Event) {
	if ev.Key != busKeyClaudeRequest {
		return
	}
	var req claudeOffboardRequest
	if err := ev.Decode(&req); err != nil || req.ID == "" || len(req.Keys) == 0 || len(req.Keys) > maxOffboardKeys {
		return
	}
	go func() {
		defer recoverGoroutine("offboard: answer a Claude login request")
		ans := s.claudeOffboardRemote(req)
		if n := s.clusterNode(); n != nil {
			n.PublishTo(ev.Origin, busTopicOffboard, busKeyClaudeReply, ans)
		}
	}()
}

// ── the CLI's side ──────────────────────────────────────────────────────────

// ClaudeHomesOnMembers is the Claude login surface of `cloop hub user
// offboard`: its own tree, through local, and every running member's, asked on
// the bus (Task 20400). A member that does not answer within the wait is
// reported unreached; so is a hub holding the control plane exclusively, which
// reads no bus, and a stopped member whose tree on a host that is still up
// nobody reached.
func ClaudeHomesOnMembers(db *statedb.DB, origin string, local offboard.ClaudeHomes) offboard.ClaudeHomes {
	return busClaude{db: db, origin: origin, local: local,
		inspectWait: 10 * time.Second, severWait: 60 * time.Second}
}

type busClaude struct {
	db     *statedb.DB
	origin string
	local  offboard.ClaudeHomes
	// How long to wait for every member's answer. A sever logs each copy
	// out, a network round trip per copy, so it waits longer.
	inspectWait, severWait time.Duration
}

func (b busClaude) Inspect(keys []string) ([]offboard.ClaudeHomeRef, []offboard.ClaudeUnreached, error) {
	homes, unreached, err := b.local.Inspect(keys)
	answers, missed := b.ask(claudeOffboardRequest{Op: claudeOpInspect, Keys: keys}, b.inspectWait)
	for _, a := range answers {
		homes = append(homes, a.Homes...)
	}
	unreached = append(unreached, missed...)
	return homes, unreached, err
}

func (b busClaude) Sever(keys []string, keep bool, actor, reason string) ([]offboard.ClaudeHomeResult, []offboard.ClaudeUnreached, error) {
	results, unreached, err := b.local.Sever(keys, keep, actor, reason)
	answers, missed := b.ask(claudeOffboardRequest{
		Op: claudeOpSever, Keys: keys, Keep: keep,
	}, b.severWait)
	for _, a := range answers {
		results = append(results, a.Results...)
	}
	unreached = append(unreached, missed...)
	return results, unreached, err
}

// ask writes the request on the bus and collects the answers addressed back to
// this process, until every member alive when it asked has answered or wait
// runs out. It also names the copies nothing will answer for.
func (b busClaude) ask(req claudeOffboardRequest, wait time.Duration) ([]claudeOffboardAnswer, []offboard.ClaudeUnreached) {
	if b.db == nil {
		return nil, nil
	}
	rows, err := b.db.ListHubMembers()
	if err != nil {
		return nil, []offboard.ClaudeUnreached{{Member: "(cluster)",
			Detail: "the member list could not be read, so no hub member was asked: " + err.Error()}}
	}
	now := time.Now()
	expect := map[string]statedb.HubMemberRow{}
	var stoppedRows []statedb.HubMemberRow
	for _, r := range rows {
		if hubcluster.RowAlive(r, now) {
			expect[r.InstanceID] = r
		} else {
			stoppedRows = append(stoppedRows, r)
		}
	}

	var answers []claudeOffboardAnswer
	var unreached []offboard.ClaudeUnreached
	if len(expect) > 0 {
		answers, unreached = b.collect(req, expect, wait)
	}

	// A hub holding the control plane alone is no member and reads no bus.
	if st, err := hublease.Inspect(hublease.Options{Store: b.db}); err == nil && st.Live {
		if _, member := expect[st.Row.InstanceID]; !member {
			unreached = append(unreached, offboard.ClaudeUnreached{Member: st.Row.InstanceID, Detail: fmt.Sprintf(
				"holds this control plane exclusively (ui.cluster.exclusive, pid %d on %s) and reads no bus, so it "+
					"was not asked; offboard from its dashboard, which ends its logins too, or remove its copies of %s by hand",
				st.Row.PID, st.Row.Hostname, strings.Join(slugsOf(req.Keys), ", "))})
		}
	}

	host, _ := os.Hostname()
	reached := []claudeTree{{host: host, root: ClaudeHomesRoot()}}
	for _, a := range answers {
		reached = append(reached, claudeTree{host: a.Hostname, root: a.Root})
	}
	var stopped []claudeTree
	for _, r := range stoppedRows {
		stopped = append(stopped, claudeTree{member: r.InstanceID, host: r.Hostname,
			root: memberRowEndpoint(r, memberEndpointClaudeHomes), at: r.HeartbeatAt})
	}
	unreached = append(unreached, strandedTrees(req.Keys, reached, stopped)...)
	sortUnreached(unreached)
	return answers, unreached
}

// collect writes the request and reads the answers.
func (b busClaude) collect(req claudeOffboardRequest, expect map[string]statedb.HubMemberRow, wait time.Duration) ([]claudeOffboardAnswer, []offboard.ClaudeUnreached) {
	fail := func(detail string) []offboard.ClaudeUnreached {
		var out []offboard.ClaudeUnreached
		for id := range expect {
			out = append(out, offboard.ClaudeUnreached{Member: id, Detail: detail})
		}
		return out
	}
	_, _, cursor, err := b.db.HubEventBounds()
	if err != nil {
		return nil, fail("the bus could not be read, so this member was not asked: " + err.Error())
	}
	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fail("could not mint a request id: " + err.Error())
	}
	req.ID = hex.EncodeToString(idBytes)
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fail(err.Error())
	}
	if _, err := b.db.AppendHubEvents([]statedb.HubEventRow{{
		Origin: b.origin, Topic: busTopicOffboard, Key: busKeyClaudeRequest,
		Payload: string(payload), CreatedAt: time.Now(),
	}}); err != nil {
		return nil, fail("the request could not be written to the bus: " + err.Error())
	}

	got := map[string]claudeOffboardAnswer{}
	deadline := time.Now().Add(wait)
	for len(got) < len(expect) && time.Now().Before(deadline) {
		events, err := b.db.HubEventsAfter(cursor, 512)
		if err == nil {
			for _, ev := range events {
				cursor = ev.Seq
				if ev.Topic != busTopicOffboard || ev.Key != busKeyClaudeReply || ev.Target != b.origin {
					continue
				}
				var a claudeOffboardAnswer
				if json.Unmarshal([]byte(ev.Payload), &a) != nil || a.RequestID != req.ID {
					continue
				}
				if a.Member == "" {
					a.Member = ev.Origin
				}
				got[ev.Origin] = a
			}
		}
		if len(got) < len(expect) {
			time.Sleep(150 * time.Millisecond)
		}
	}

	var answers []claudeOffboardAnswer
	var unreached []offboard.ClaudeUnreached
	for id, a := range got {
		if a.Error != "" {
			unreached = append(unreached, offboard.ClaudeUnreached{Member: id, Detail: a.Error})
		}
		answers = append(answers, a)
	}
	for id, r := range expect {
		if _, ok := got[id]; ok {
			continue
		}
		unreached = append(unreached, offboard.ClaudeUnreached{Member: id, Detail: fmt.Sprintf(
			"did not answer within %s (pid %d on %s, build %s) — a build older than this one does not know "+
				"the request; upgrade it, or remove its copies of %s by hand",
			wait, r.PID, r.Hostname, r.Version, strings.Join(slugsOf(req.Keys), ", "))})
	}
	sort.Slice(answers, func(i, j int) bool { return answers[i].Member < answers[j].Member })
	return answers, unreached
}

// memberRowEndpoint reads one named endpoint from a member row's meta.
func memberRowEndpoint(r statedb.HubMemberRow, name string) string {
	var eps map[string]string
	if json.Unmarshal([]byte(strings.TrimSpace(r.Meta)), &eps) != nil {
		return ""
	}
	return eps[name]
}

// slugsOf names the directories an identity's homes are kept under, for a
// remedy an operator follows by hand on a host the run could not reach.
func slugsOf(keys []string) []string {
	var out []string
	for _, k := range keys {
		if strings.TrimSpace(k) != "" {
			out = append(out, "claude-identities/"+claudecodeauth.IdentitySlug(k))
		}
	}
	return uniqueStrings(out)
}
