package offboard

// sweep.go: which identities' Claude Code homes no hub member should keep
// (Task 20422).
//
// An offboarding ends a departed identity's Claude logins on every member it
// can reach, and names — without reaching — a member that did not answer and
// a stopped member's tree on a host that is still up. Each of those copies
// holds the person's OAuth refresh token in plaintext. So every member also
// sweeps its own tree, at startup and on a timer: it removes the home of every
// identity the control plane denies hub-wide, logging it out first where it
// may, and `cloop hub doctor` reports the homes still on its host.
//
// "Denies" is what a member already acts on another process's word for — a
// hub-wide deny binding — with two exceptions that keep the sweep from
// destroying what was deliberately kept:
//
//   - a deny written by a SCIM suspension that is still in force: a
//     suspension keeps stored credentials so that reactivating restores the
//     person, and only the deny rows it wrote itself carry its reason;
//   - an identity under a legal hold, looked up across every spelling the
//     hub can resolve for it, as an offboarding looks it up.
//
// A deny on preferred_username or oid — what a SCIM directory matching on
// those writes when no session carries an email — is resolved to the email
// and subject spellings sessions, token owners and the SCIM directory record
// for it, since a home is keyed by the owner key the person signed in under.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ClaudeHomesEndpoint is the member-row endpoint naming where a hub member
// keeps its Claude homes, so a tree a member left behind can be found on its
// host. A path, read by processes on the same machine.
const ClaudeHomesEndpoint = "claude_homes"

// DeniedIdentity is one person the control plane denies hub-wide, with every
// owner-key spelling their Claude home may be kept under.
type DeniedIdentity struct {
	// Keys are the owner keys: lowercased emails and "sub:<subject>".
	Keys []string
	// Denies names the bindings that deny them, as claim=value.
	Denies []string
}

// DeniedIdentities lists the identities whose Claude homes no member should
// keep: denied hub-wide by a binding other than an in-force SCIM suspension's,
// and under no legal hold. Held reports, by owner key, the denied identities a
// hold keeps.
func DeniedIdentities(db *statedb.DB) (denied []DeniedIdentity, held []string, err error) {
	if db == nil {
		return nil, nil, fmt.Errorf("offboard: nil database")
	}
	bindings, err := db.ListRoleBindings()
	if err != nil {
		return nil, nil, fmt.Errorf("read role bindings: %w", err)
	}
	directory, err := db.ListSCIMUsers()
	if err != nil {
		return nil, nil, fmt.Errorf("read the SCIM directory: %w", err)
	}
	suspended := suspensionDenies(directory, bindings)

	sessions, err := db.ListSessions()
	if err != nil {
		return nil, nil, fmt.Errorf("list sessions: %w", err)
	}
	store, err := apitoken.NewSQLStore(db)
	if err != nil {
		return nil, nil, err
	}
	tokens, err := store.List()
	if err != nil {
		return nil, nil, fmt.Errorf("list api tokens: %w", err)
	}

	// Seeds, as owner keys, per group of deny bindings written together: an
	// offboarding writes one per spelling of the person in one transaction,
	// with one reason, author and time — the one durable record that those
	// spellings are one person once the sessions linking them are gone, and
	// so the one a legal hold on any of them is found through.
	type seeded struct {
		denies []string
		seeds  []string
	}
	groups := map[string]*seeded{}
	var all []*seeded
	for _, b := range bindings {
		if b.Effect != statedb.RoleEffectDeny || b.Project != "" || b.Executor != "" || suspended[b.ID] {
			continue
		}
		value := strings.TrimSpace(b.Value)
		if value == "" {
			continue
		}
		var seeds []string
		switch b.Claim {
		case "email":
			seeds = []string{strings.ToLower(value)}
		case "sub":
			seeds = []string{"sub:" + value}
		case "username", "oid":
			seeds = accountSeeds(b.Claim, value, sessions, tokens, directory)
		}
		if len(seeds) == 0 {
			continue
		}
		key := b.Reason + "\x00" + b.CreatedBy + "\x00" + b.CreatedAt.UTC().Format(time.RFC3339Nano)
		g := groups[key]
		if g == nil {
			g = &seeded{}
			groups[key] = g
			all = append(all, g)
		}
		g.denies = append(g.denies, b.Claim+"="+value)
		g.seeds = append(g.seeds, seeds...)
	}

	// One identity per resolved person, however many bindings deny them.
	byKey := map[string]*DeniedIdentity{}
	var order []*DeniedIdentity
	for _, s := range all {
		keys := map[string]bool{}
		for _, seed := range s.seeds {
			t, _ := resolve(seed, sessions, tokens)
			for _, k := range t.OwnerKeys() {
				keys[k] = true
			}
		}
		var id *DeniedIdentity
		for k := range keys {
			if byKey[k] != nil {
				id = byKey[k]
				break
			}
		}
		if id == nil {
			id = &DeniedIdentity{}
			order = append(order, id)
		}
		for k := range keys {
			if byKey[k] == nil {
				byKey[k] = id
				id.Keys = append(id.Keys, k)
			}
		}
		id.Denies = append(id.Denies, s.denies...)
	}

	for _, id := range order {
		sort.Strings(id.Keys)
		sort.Strings(id.Denies)
		if _, ok, err := db.LegalHoldFor(id.Keys); err != nil {
			return nil, nil, fmt.Errorf("read legal holds: %w", err)
		} else if ok {
			held = append(held, id.Keys[0])
			continue
		}
		denied = append(denied, *id)
	}
	sort.Slice(denied, func(i, j int) bool { return denied[i].Keys[0] < denied[j].Keys[0] })
	sort.Strings(held)
	return denied, held, nil
}

// OwnerKeysOf returns every key of every identity, sorted.
func OwnerKeysOf(ids []DeniedIdentity) []string {
	var out []string
	for _, id := range ids {
		out = append(out, id.Keys...)
	}
	sort.Strings(out)
	return out
}

// suspensionDenies is the set of binding ids an in-force SCIM suspension
// wrote and that still carry its reason — the rows its reactivation lifts.
func suspensionDenies(directory []statedb.SCIMUserRow, bindings []statedb.RoleBindingRow) map[string]bool {
	byID := map[string]statedb.RoleBindingRow{}
	for _, b := range bindings {
		byID[b.ID] = b
	}
	out := map[string]bool{}
	for _, u := range directory {
		rec, ok := u.SuspensionRecord()
		if !ok {
			continue
		}
		for _, id := range rec.Denies {
			if b, ok := byID[id]; ok && b.Reason == rec.Reason {
				out[id] = true
			}
		}
	}
	return out
}

// accountSeeds resolves a preferred_username or oid deny to the owner keys
// sessions, token owners and the SCIM directory record for it.
func accountSeeds(claim, value string, sessions []statedb.SessionRow, tokens []apitoken.Token, directory []statedb.SCIMUserRow) []string {
	var out []string
	add := func(sub, email string) {
		if email = strings.ToLower(strings.TrimSpace(email)); email != "" {
			out = append(out, email)
		}
		if sub = strings.TrimSpace(sub); sub != "" {
			out = append(out, "sub:"+sub)
		}
	}
	match := func(username, oid string) bool {
		if claim == "username" {
			return username != "" && strings.EqualFold(strings.TrimSpace(username), value)
		}
		return oid != "" && strings.EqualFold(strings.TrimSpace(oid), value)
	}
	for _, s := range sessions {
		if match(s.Username, s.OID) {
			add(s.Subject, s.Email)
		}
	}
	for _, t := range tokens {
		if t.Owner != nil && match(t.Owner.Username, t.Owner.OID) {
			add(t.Owner.Sub, t.Owner.Email)
		}
	}
	if claim == "username" {
		for _, u := range directory {
			if strings.EqualFold(strings.TrimSpace(u.UserName), value) {
				add("", u.Email)
			}
		}
	}
	return out
}

// ClaudeTree is one hub process's Claude home root on this host.
type ClaudeTree struct {
	// Member names the hub member that keeps it, "" for this process's own.
	Member string
	Root   string
}

// ClaudeTreesOnThisHost lists the Claude home roots hub members on this host
// recorded in their member rows, besides own — the tree of the process asking
// — without duplicates. A member on another host keeps a tree this one cannot
// see.
func ClaudeTreesOnThisHost(db *statedb.DB, own string) ([]ClaudeTree, error) {
	out := []ClaudeTree{}
	seen := map[string]bool{}
	if own != "" {
		out = append(out, ClaudeTree{Root: own})
		seen[own] = true
	}
	if db == nil {
		return out, nil
	}
	rows, err := db.ListHubMembers()
	if err != nil {
		return out, fmt.Errorf("read the hub members: %w", err)
	}
	host, _ := os.Hostname()
	for _, r := range rows {
		if r.Hostname != host {
			continue
		}
		var eps map[string]string
		if json.Unmarshal([]byte(strings.TrimSpace(r.Meta)), &eps) != nil {
			continue
		}
		if root := strings.TrimSpace(eps[ClaudeHomesEndpoint]); root != "" && !seen[root] {
			seen[root] = true
			out = append(out, ClaudeTree{Member: r.InstanceID, Root: root})
		}
	}
	return out, nil
}
