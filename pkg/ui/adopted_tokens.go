package ui

// adopted_tokens.go: what a hub process adopting a run knows of the tokens
// its dispatcher minted for it (Task 20454).
//
// The process that dispatched a run handed it tokens it minted itself: the
// bearer tokens of the run's git proxy, Kubernetes monitor, egress and model
// relay sessions, and the GitHub App installation tokens behind its GitHub
// grants. A process that adopts the run never had their plaintext, because
// nothing stores it. So the values it scrubs the run's output with and scans
// its pushes for, which Broker.RedactionCredentials re-derives from the run's
// grants, cannot include them.
//
// What is stored of each token is a SHA-256: proxy_sessions.token_sha256 for
// every session, and app_token_slots.token_hashes for every App token. The
// adopting process reads those before it takes anything else of the run over
// (a takeover can retire a slot's record) and hands them to two places:
//
//   - the driver, which scrubs from the stream each token it confirms
//     (executor.HandleTokenRedactor);
//   - the push scan, which refuses a push that carries one, naming the
//     token's grant and secret (gitproxy.ScanToken).
//
// Each is found by the prefix it was minted with and confirmed by its hash.
// A token of the same shape that is not one of the run's own is left alone.
//
// Only an adopted run has any, and only when its dispatcher minted something.
// A run this process dispatched, and one whose grants are all re-derivable,
// streams and pushes at the exact-value cost it always had.

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/claudeproxy"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/kubeguard"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// adoptedToken is one token an adopted run holds that this process knows only
// by its recorded hash, and where the token came from.
type adoptedToken struct {
	hash   redact.TokenHash
	grant  string
	secret string
	field  string
}

// recordedTokenShape is the prefix and length a session of kind was minted
// with since Task 20454: how a candidate is cut before it is hashed.
func recordedTokenShape(kind string) (prefix string, n int, ok bool) {
	switch kind {
	case statedb.ProxySessionGit:
		return redact.GitProxyTokenPrefix, gitproxy.TokenLen, true
	case statedb.ProxySessionKube:
		return redact.KubeGuardTokenPrefix, kubeguard.TokenLen, true
	case statedb.ProxySessionEgress:
		return redact.EgressTokenPrefix, egressbroker.TokenLen, true
	case statedb.ProxySessionModel:
		return modelRelayTokenPrefix, claudeproxy.TokenLen(modelRelayTokenPrefix), true
	}
	return "", 0, false
}

// recordedTokenField says which token of the run a session's is, for a push
// refusal: the words CredentialValues uses for the same token on the run
// that dispatched it.
func recordedTokenField(kind string) (field, secret string) {
	switch kind {
	case statedb.ProxySessionGit:
		return "the git proxy session token", ""
	case statedb.ProxySessionKube:
		return "the Kubernetes monitor session token", ""
	case statedb.ProxySessionEgress:
		return "the egress proxy session's password", "the run's egress proxy session"
	default:
		return "the model relay session token", "the run's model relay session"
	}
}

// adoptedRunTokens reads what confirms each token the run's dispatcher minted
// for it: the tokens of the sessions its leases fed and of its workspace and
// egress sessions, closed ones included (a closed session's token no longer
// opens anything, but a workload can still print it), and every App token its
// leases' slots held. Rows whose hash cannot be read are skipped. So are
// sessions minted before their kind had a prefix: nothing can find such a
// token.
//
// It also returns the run id those records name, for an owner row that does
// not.
func adoptedRunTokens(db *statedb.DB, meta runOwnerMeta) ([]adoptedToken, string) {
	if db == nil {
		return nil, ""
	}
	leases := append([]string(nil), meta.Leases...)
	var sessions []string
	if meta.Workspace != nil {
		if meta.Workspace.Lease != "" {
			leases = append(leases, meta.Workspace.Lease)
		}
		if meta.Workspace.Session != "" {
			sessions = append(sessions, meta.Workspace.Session)
		}
	}
	sessions = append(sessions, meta.Egress...)

	var rows []statedb.ProxySessionRow
	if len(leases) > 0 {
		r, err := db.ListProxySessions(statedb.ProxySessionFilter{LeaseIDs: leases})
		if err != nil {
			fmt.Fprintf(os.Stderr, "ui: read the sessions an adopted run's leases fed: %v\n", err)
		}
		rows = append(rows, r...)
	}
	if len(sessions) > 0 {
		r, err := db.ListProxySessions(statedb.ProxySessionFilter{SessionIDs: sessions})
		if err != nil {
			fmt.Fprintf(os.Stderr, "ui: read an adopted run's workspace and egress sessions: %v\n", err)
		}
		rows = append(rows, r...)
	}

	names := grantSecretNames(db)
	seen := map[[32]byte]bool{}
	var out []adoptedToken
	add := func(tok adoptedToken) {
		if seen[tok.hash.Sum] {
			return
		}
		seen[tok.hash.Sum] = true
		out = append(out, tok)
	}
	runID := ""
	for _, row := range rows {
		if runID == "" && row.Kind != statedb.ProxySessionEgress {
			runID = row.RunID
		}
		prefix, n, ok := recordedTokenShape(row.Kind)
		if !ok {
			continue
		}
		h, ok := redact.TokenHashOf(prefix, n, row.TokenSHA256)
		if !ok {
			continue
		}
		field, secret := recordedTokenField(row.Kind)
		if secret == "" {
			secret = names(row.GrantID)
		}
		add(adoptedToken{hash: h, grant: row.GrantID, secret: secret, field: field})
	}
	for _, lease := range leases {
		slots, err := db.ListAppTokenSlots(lease)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ui: read the App token slots of lease %s: %v\n", lease, err)
			continue
		}
		for _, slot := range slots {
			hs, err := redact.ParseTokenHashes(slot.TokenHashes)
			if err != nil {
				// The rest still confirm their tokens.
				fmt.Fprintf(os.Stderr, "ui: App token slot %s/%s: %v\n", slot.LeaseID, slot.GrantID, err)
			}
			for _, h := range hs {
				add(adoptedToken{hash: h, grant: slot.GrantID, secret: slot.SecretName,
					field: "the GitHub App installation token"})
			}
		}
	}
	return out, runID
}

// grantSecretNames returns a lookup from a secret grant to its secret's name,
// "" for a grant it cannot resolve: an egress grant, or one since deleted.
func grantSecretNames(db *statedb.DB) func(string) string {
	store, err := secretstore.New(db)
	if err != nil {
		return func(string) string { return "" }
	}
	cache := map[string]string{}
	return func(grantID string) string {
		grantID = strings.TrimSpace(grantID)
		if grantID == "" {
			return ""
		}
		if name, ok := cache[grantID]; ok {
			return name
		}
		name := ""
		if g, err := store.GetGrant(grantID); err == nil {
			if s, err := store.GetSecret(g.SecretID); err == nil {
				name = s.Name
			}
		}
		cache[grantID] = name
		return name
	}
}

// adoptRunTokens reads what confirms the tokens an adopted run's dispatcher
// minted and hands it to the run's driver and push scan. It runs before
// anything of the run is streamed or taken over.
func (s *Server) adoptRunTokens(workDir string, ex executor.Executor, meta runOwnerMeta) {
	db, closeDB := egressRecordDB()
	if db == nil {
		return
	}
	defer closeDB()
	toks, recordedRun := adoptedRunTokens(db, meta)
	if len(toks) == 0 {
		return
	}
	hashes := make([]redact.TokenHash, 0, len(toks))
	scan := make([]gitproxy.ScanToken, 0, len(toks))
	for _, tok := range toks {
		hashes = append(hashes, tok.hash)
		scan = append(scan, gitproxy.ScanToken{Hash: tok.hash, Grant: tok.grant, Secret: tok.secret, Field: tok.field})
	}
	installed := false
	if r, ok := ex.(executor.HandleTokenRedactor); ok {
		installed = r.AddHandleTokens(meta.Handle, hashes...)
	}
	leases := append([]string(nil), meta.Leases...)
	if meta.Workspace != nil && meta.Workspace.Lease != "" {
		leases = append(leases, meta.Workspace.Lease)
	}
	runID := s.adoptedRunID(ex, meta)
	if runID == "" {
		runID = recordedRun
	}
	adoptRunPushScanTokens(runID, workDir, ex, meta.Handle, leases, scan)
	kinds := map[string]int{}
	for _, tok := range toks {
		kinds[tok.field]++
	}
	var parts []string
	for k, n := range kinds {
		parts = append(parts, fmt.Sprintf("%d × %s", n, k))
	}
	sort.Strings(parts)
	s.log().Info("cluster", 0, "an adopted run's output and pushes are searched for the tokens its dispatcher minted",
		map[string]interface{}{"project": workDir, "executor": ex.ID(), "handle": meta.Handle,
			"tokens": strings.Join(parts, ", "), "driver_scrubs": installed})
}

// adoptedRunID is the id of the run an owner row names: its provenance's, or
// else the one the handle's record carries.
func (s *Server) adoptedRunID(ex executor.Executor, meta runOwnerMeta) string {
	if meta.Provenance != nil && meta.Provenance.RunID != "" {
		return meta.Provenance.RunID
	}
	if store := s.clusterHandleStoreFor(); store != nil && ex != nil {
		if recs, err := store.ListHandles(ex.ID()); err == nil {
			for _, rec := range recs {
				if rec.HandleID == meta.Handle {
					return rec.Meta[executor.MetaRunID]
				}
			}
		}
	}
	return ""
}
