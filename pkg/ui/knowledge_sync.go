package ui

// Knowledge sync on the hub (Task 20470): the leader's schedule, the manual
// sync route, and the index-size gauges.
//
// The schedule is a leader duty (runLeaderDuty), so a cluster of members syncs
// each source once per interval, not once per member. A manual sync — POST
// /api/knowledge/sources/{id}/sync, `cloop knowledge sync` — runs on whichever
// member the request reached. Both go through one knowledge.Runner per
// member, and every sync takes its source's lease in the control plane first,
// so a manual sync and the leader's scheduled one never overlap, nor two
// manual ones on different members: the second is answered 409, naming the
// member that holds the source.
//
// Each sync opens the control plane and the secret broker for its own length
// (openBrokers); the source's credential is opened inside the sync and wiped
// at its end, and never leaves this process. Shutdown interrupts this
// member's syncs and waits for them to record that and release their leases.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/state"
)

// knowledgeSyncState is a member's knowledge sync runner, made on first use.
type knowledgeSyncState struct {
	mu     sync.Mutex
	runner *knowledge.Runner
	// tune, set by a test before first use, adjusts the runner's options:
	// its tick, its lease, the connectors it reads with.
	tune func(*knowledge.RunnerOptions)
	// serviceOptions, set by a test, are added to every sync's Service.
	serviceOptions []knowledge.Option
}

// knowledgeRunner returns this member's knowledge sync runner.
func (s *Server) knowledgeRunner() *knowledge.Runner {
	st := &s.knowledgeSync
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.runner != nil {
		return st.runner
	}
	member := s.hubInstanceID()
	if member == "" {
		// A hub with neither a cluster nor an instance lease — one a tool
		// built in-process — still names its process to the leases it takes.
		host, _ := os.Hostname()
		member = fmt.Sprintf("%s/%d", host, os.Getpid())
	}
	opts := knowledge.RunnerOptions{
		Member: member,
		Open:   s.openKnowledgeSync,
		Logf: func(format string, args ...any) {
			s.log().Warn(logger.EventKnowledge, 0, fmt.Sprintf(format, args...), nil)
		},
	}
	if st.tune != nil {
		st.tune(&opts)
	}
	st.runner = knowledge.NewRunner(opts)
	return st.runner
}

// openKnowledgeSync opens what one sync, or one pass of the schedule, runs
// with: the control plane, released when it ends, and the secret broker for
// the one call that opens the source's credential (syncCredentials). A hub
// with no control-plane database yet has nothing to sync, and none is made.
func (s *Server) openKnowledgeSync() (*knowledge.Service, func(), error) {
	path := state.DBPath(s.WorkDir)
	if _, err := os.Stat(path); err != nil {
		return nil, nil, fmt.Errorf("%w: the control plane has no state database at %s yet", knowledge.ErrUnavailable, path)
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		return nil, nil, err
	}
	opts := []knowledge.Option{knowledge.WithCredentials(syncCredentials{s: s}),
		knowledge.WithEmbeddings(s.knowledgeEmbeddings())}
	s.knowledgeSync.mu.Lock()
	opts = append(opts, s.knowledgeSync.serviceOptions...)
	s.knowledgeSync.mu.Unlock()
	return knowledge.New(db, opts...), func() { _ = db.Close() }, nil
}

// syncCredentials is the secret broker as a sync reaches it: opened for each
// call and closed as soon as it has answered, so a sync holds its source's
// credential — and the broker its unwrapped keys — for that call alone. The
// sync wipes the credential when it ends.
type syncCredentials struct{ s *Server }

func (c syncCredentials) broker() (*brokerSet, error) {
	bs, err := c.s.openBrokers()
	if err != nil {
		return nil, err
	}
	if bs.secret == nil {
		bs.close()
		return nil, fmt.Errorf("%w: this hub has no secret store: %s %s", knowledge.ErrUnavailable,
			bs.status.Reason, bs.status.Remediation)
	}
	return bs, nil
}

func (c syncCredentials) CheckSourceCredential(ref, owner string) error {
	bs, err := c.broker()
	if err != nil {
		return err
	}
	defer bs.close()
	return bs.secret.CheckSourceCredential(ref, owner)
}

func (c syncCredentials) SourceCredential(ref, owner string) ([]byte, error) {
	bs, err := c.broker()
	if err != nil {
		return nil, err
	}
	defer bs.close()
	return bs.secret.SourceCredential(ref, owner)
}

// watchKnowledgeSync runs the sync schedule for as long as this member leads.
func (s *Server) watchKnowledgeSync(ctx context.Context) {
	defer recoverGoroutine("watchKnowledgeSync")
	s.knowledgeRunner().Schedule(ctx)
}

// stopKnowledgeSyncs interrupts this member's syncs and waits up to wait for
// them to record that and release their leases. The runner is stopped even if
// it never ran a sync, so a request still reaching the listener while the hub
// stops is refused rather than starting a sync nothing would interrupt.
func (s *Server) stopKnowledgeSyncs(wait time.Duration) {
	s.knowledgeRunner().Stop(wait)
}

// handleKnowledgeSourceSync serves POST /api/knowledge/sources/{id}/sync:
// sync the source now, on this member. An administrator may sync any source,
// a person their own personal one. The sync runs in the background; the
// answer is 202 once it holds the source's lease, 409 when another sync does
// — on this member or another — naming where it runs. The request is audited
// as knowledge.source.sync when the sync starts.
func (s *Server) handleKnowledgeSourceSync(w http.ResponseWriter, r *http.Request) {
	id, ok := knowledgeID(w, r, "id")
	if !ok {
		return
	}
	acc, done, ok := s.knowledgeAccess(w, r, nil)
	if !ok {
		return
	}
	defer done()
	// Whether the caller can see the source at all is asked first, so that
	// another person's source is not found rather than forbidden.
	src, _, err := acc.Source(r.Context(), id)
	if err != nil {
		s.writeKnowledgeError(w, err, "sync the knowledge source")
		return
	}
	g, ok := s.knowledgeAdminGrant(w, r, src)
	if !ok {
		return
	}
	if _, err := s.knowledgeWith(acc, r, g).MaySync(r.Context(), id); err != nil {
		s.writeKnowledgeError(w, err, "sync the knowledge source")
		return
	}
	running, err := s.knowledgeRunner().Start(id, knowledge.OriginManual, s.auditActor(r))
	var busy *knowledge.BusyError
	switch {
	case errors.As(err, &busy):
		apierror.WriteError(w, apierror.New(apierror.CodeConflict,
			"a sync of this source is already running; wait for it to end, or follow it with cloop knowledge sources").
			WithDetails(map[string]any{"running": knowledgeRunningViewOf(&busy.Running, true)}))
		return
	case errors.Is(err, knowledge.ErrRunnerStopped):
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "this hub is stopping; ask another member, or try again"))
		return
	case err != nil:
		s.writeKnowledgeError(w, err, "start the sync")
		return
	}
	s.broadcastAuditAppend(string(auditaction.ActionKnowledgeSourceSync))
	view := knowledgeSourceViewOf(acc, src)
	view.Sync.Running = knowledgeRunningViewOf(&running, true)
	writeJSONStatus(w, http.StatusAccepted, map[string]any{"source": view, "sync": view.Sync.Running})
}

// collectKnowledgeIndex publishes how large the knowledge index is, per
// connector kind: its documents, chunks and the bytes of text they were made
// from. Leader only, as every gauge of the shared database is. Every kind this
// build reads with is exported, zero included, so a kind with no sources reads
// 0 rather than absent.
func collectKnowledgeIndex(sc *metricsScrape) {
	if !sc.leader {
		return
	}
	db := sc.controlDB()
	if db == nil {
		return
	}
	sources, err := db.ListKnowledgeSources()
	if err != nil {
		return
	}
	counts, err := db.CountKnowledge()
	if err != nil {
		return
	}
	vectors := map[int64]int{}
	if model := sc.srv.knowledgeEmbeddings().Model(); model != "" {
		if vectors, err = db.CountKnowledgeVectors(model); err != nil {
			return
		}
	}
	type size struct{ docs, chunks, bytes, vectors float64 }
	byKind := map[string]*size{}
	for _, kind := range knowledge.DefaultRegistry().Kinds() {
		byKind[kind] = &size{}
	}
	for _, src := range sources {
		kind := src.Kind
		if _, ok := knowledge.DefaultRegistry().Lookup(kind); !ok {
			kind = hubmetrics.KnowledgeKindUnknown
		}
		sz := byKind[kind]
		if sz == nil {
			sz = &size{}
			byKind[kind] = sz
		}
		c := counts[src.ID]
		sz.docs += float64(c.Documents)
		sz.chunks += float64(c.Chunks)
		sz.bytes += float64(c.BodyBytes)
		sz.vectors += float64(vectors[src.ID])
	}
	for kind, sz := range byKind {
		hubmetrics.KnowledgeIndexDocuments.Set(sz.docs, kind)
		hubmetrics.KnowledgeIndexChunks.Set(sz.chunks, kind)
		hubmetrics.KnowledgeIndexBytes.Set(sz.bytes, kind)
		hubmetrics.KnowledgeIndexVectors.Set(sz.vectors, kind)
	}
}
