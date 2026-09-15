// Package auditmerge reads the audit trail as one thing (Task 20292).
//
// `audit_events` is not one table. It exists in the hub's control-plane
// state.db and in every project's .cloop/state.db, each with its own
// independent hash chain. Every reader before this one opened exactly one of
// them: `cloop audit-log list`, `verify` and `export` all run against whichever
// database the working directory resolved to, and the Audit panel reads
// whichever project the request was scoped to.
//
// That makes the ordinary compliance question unanswerable without knowing the
// storage layout. "What happened to project X" spans both chains — the plan's
// own life is in the project's, while the executor that ran it, the image
// policy that admitted it, the workspace fetched for it and the credentials it
// held are in the hub's — and an operator who reads one gets a confident,
// incomplete answer with nothing to suggest anything is missing.
//
// So this package reads both, labels every row with where it came from, and
// verifies both chains rather than whichever one was opened. It adds no
// storage and changes no row: it is a read-side join over two append-only logs
// that were always meant to be read together.
//
// # Ordering
//
// The two chains have independent id sequences, so ids collide and mean
// nothing across a merge. Rows are ordered by timestamp instead, which is the
// only field comparable between them. Ties — common, because a dispatch and
// its lease are written within the same millisecond — are broken by source and
// then by id, so a merged read is stable rather than merely sorted.
//
// This is why merged rows keep their id but are never keyed on it. A caller
// that needs to point at one row wants (source, id), and Row.Ref renders it.
package auditmerge

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Source names which chain a row came from.
type Source string

const (
	// SourceControlPlane is the hub's own state.db.
	SourceControlPlane Source = "control-plane"
	// SourceProject is a project's .cloop/state.db.
	SourceProject Source = "project"
)

// String renders the source for a table cell or a --source filter.
func (s Source) String() string { return string(s) }

// home maps a source to the auditaction home whose events belong in it.
func (s Source) home() auditaction.HomeDB {
	if s == SourceControlPlane {
		return auditaction.HomeControlPlane
	}
	return auditaction.HomeProject
}

// Chain is one database to read.
type Chain struct {
	// Source says which side of the split this is.
	Source Source
	// Dir is the directory holding .cloop/state.db. Used to open it and to
	// label rows, because on a multi-project hub "project" alone does not say
	// which project.
	Dir string
}

// Row is one audit event with its provenance attached.
//
// The embedded event is unmodified — a merged read must not rewrite what it
// reports — and everything this package adds is alongside it.
type Row struct {
	statedb.AuditEvent

	// Source is the chain this row was read from.
	Source Source
	// Dir is the directory whose database it came from.
	Dir string
	// Shared is true when that database serves as both chains at once — the
	// hub's own project. Both homes are correct in it, so Misrouted must not
	// judge its rows.
	Shared bool
}

// Ref identifies a row across the merge: ids are per-chain, so "id 41" is
// ambiguous and "control-plane#41" is not.
func (r Row) Ref() string { return string(r.Source) + "#" + fmt.Sprint(r.ID) }

// Verdict is one chain's verification result.
type Verdict struct {
	Source Source
	Dir    string
	Path   string
	Report statedb.AuditVerifyReport
	// Err is set when the chain could not be checked at all — a missing or
	// unreadable database. Distinct from a failed check: "could not verify"
	// and "verified and found broken" call for different responses, and
	// collapsing them is how an unreadable trail gets reported as an intact
	// one.
	Err error
}

// OK reports whether this chain verified. An unreadable chain is not OK: a
// verifier that returns success for a database it could not open is worse than
// no verifier.
func (v Verdict) OK() bool { return v.Err == nil && v.Report.OK }

// Reader reads a set of chains as one trail.
type Reader struct {
	chains []openChain
}

type openChain struct {
	Chain
	path string
	db   *statedb.DB
	// shared marks a database that was named as both chains — the hub's own
	// project, where the control plane and a project are one file. Rows from
	// it carry both homes legitimately.
	shared bool
}

// Open opens every chain that exists, skipping the ones that do not.
//
// A project that has never been run has no state.db, and a hub reading a
// fleet of them must not fail because one is absent — so a missing database is
// skipped rather than refused. An existing database that will not open is an
// error, because that is a real fault and silently omitting its rows would make
// the merged view quietly partial, which is the exact defect this package
// exists to fix.
//
// Chains whose databases resolve to the same file are collapsed to one. This is
// not a hypothetical: the hub runs from a directory that is itself a project,
// so on the hub's own project the "control plane" and "project" chains are the
// same file, and reading it twice would duplicate every row in the merged view
// — which reads exactly like the double-counting bug somebody would then go
// hunting for in the merge. The surviving copy keeps the control-plane source,
// because that is the role the file's fleet-wide rows were written under.
func Open(chains []Chain) (*Reader, error) {
	r := &Reader{}
	at := map[string]int{} // resolved path -> index in r.chains
	for _, c := range chains {
		if strings.TrimSpace(c.Dir) == "" {
			continue
		}
		path := state.DBPath(c.Dir)
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		if i, dup := at[path]; dup {
			// Two roles, one file. Record that so Misrouted does not report
			// this chain's project-homed rows as strays: on a shared database
			// they are exactly where they belong.
			r.chains[i].shared = true
			continue
		}
		// Existence is checked here rather than inferred from the open error.
		// The driver reports a missing database as "unable to open database
		// file (14)" — indistinguishable by string from a permissions fault or
		// a corrupt header — so matching on the message would either skip
		// chains that are really broken or fail on ones that are merely
		// absent. Statting first makes "not there" a fact instead of a guess,
		// and leaves Open's error path meaning "present, but would not open".
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			r.Close()
			return nil, fmt.Errorf("auditmerge: stat %s chain at %s: %w", c.Source, path, err)
		}
		db, err := statedb.Open(path)
		if err != nil {
			r.Close()
			return nil, fmt.Errorf("auditmerge: open %s chain at %s: %w", c.Source, path, err)
		}
		at[path] = len(r.chains)
		r.chains = append(r.chains, openChain{Chain: c, path: path, db: db})
	}
	return r, nil
}

// Chains reports what was actually opened, so a caller can tell the reader
// which sources are represented — and therefore whether an empty result means
// "nothing happened" or "that chain was not there".
func (r *Reader) Chains() []Chain {
	out := make([]Chain, 0, len(r.chains))
	for _, c := range r.chains {
		out = append(out, c.Chain)
	}
	return out
}

// Close releases every handle. Safe to call on a partially-opened Reader.
func (r *Reader) Close() error {
	var firstErr error
	for _, c := range r.chains {
		if err := c.db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	r.chains = nil
	return firstErr
}

// List returns the merged, timestamp-ordered rows matching f, plus the total
// number of rows across every chain.
//
// Paging is applied after the merge, not before: each chain is asked for
// Offset+Limit rows and the window is taken from the merged sequence. Slicing
// per chain first would return the first N of each and call it the first N
// overall, which is wrong whenever the chains are not interleaved evenly — and
// they never are, because one records a plan's steps and the other a fleet's
// administration.
//
// The per-chain fetch is ordered by id while the merge orders by timestamp,
// which is sound because the two agree by construction: audit_events is
// append-only, and a row's id and timestamp are both assigned at append. The
// exception is a caller that sets AuditEvent.Timestamp explicitly to a value
// out of line with append order — hand-built fixtures do this, production
// emitters do not — and for those the window can miss a row that a
// timestamp-ordered fetch would have included. Fixing it properly needs
// ORDER BY timestamp in statedb.ListAuditEvents; until something real needs
// back-dated rows, over-fetching every chain in full would cost far more than
// the case is worth.
func (r *Reader) List(f statedb.AuditFilter) ([]Row, int, error) {
	// The per-chain query must not pre-trim the window; the merge decides it.
	sub := f
	sub.Offset = 0
	if f.Limit > 0 {
		sub.Limit = f.Limit + f.Offset
	}

	var (
		rows  []Row
		total int
	)
	for _, c := range r.chains {
		got, chainTotal, err := c.db.ListAuditEvents(sub)
		if err != nil {
			return nil, 0, fmt.Errorf("auditmerge: read %s chain at %s: %w", c.Source, c.path, err)
		}
		total += chainTotal
		for _, ev := range got {
			rows = append(rows, Row{AuditEvent: ev, Source: c.Source, Dir: c.Dir, Shared: c.shared})
		}
	}

	sortRows(rows, strings.EqualFold(strings.TrimSpace(f.Order), "desc"))

	if f.Offset > 0 {
		if f.Offset >= len(rows) {
			return nil, total, nil
		}
		rows = rows[f.Offset:]
	}
	if f.Limit > 0 && len(rows) > f.Limit {
		rows = rows[:f.Limit]
	}
	return rows, total, nil
}

// sortRows orders by timestamp, then source, then id.
//
// The tie-breaks are not cosmetic. Rows written in the same millisecond are
// routine — a dispatch and the lease it was granted are two writes in one
// operation — and without a total order the merged view would shuffle between
// identical reads, which for a compliance artefact is indistinguishable from
// the trail changing.
func sortRows(rows []Row, desc bool) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if !a.Timestamp.Equal(b.Timestamp) {
			if desc {
				return a.Timestamp.After(b.Timestamp)
			}
			return a.Timestamp.Before(b.Timestamp)
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if desc {
			return a.ID > b.ID
		}
		return a.ID < b.ID
	})
}

// Verify checks every chain and returns one verdict per chain.
//
// Each chain is verified independently, because they are independent: one hash
// chain says nothing about the other, and a single combined boolean would let
// an intact hub chain vouch for a broken project one. Callers report every
// verdict, which is the whole point — a `verify` that prints "OK" without
// saying what it checked is what this replaces.
func (r *Reader) Verify() []Verdict {
	out := make([]Verdict, 0, len(r.chains))
	for _, c := range r.chains {
		v := Verdict{Source: c.Source, Dir: c.Dir, Path: c.path}
		rep, err := c.db.VerifyAuditChain()
		if err != nil {
			v.Err = err
		} else {
			v.Report = rep
		}
		out = append(out, v)
	}
	return out
}

// Misrouted returns the rows whose declared home disagrees with the chain they
// were found in.
//
// This is the read-side counterpart to the emit-path assertion, and it exists
// because that assertion only guards handles this binary classified and only
// from the moment it shipped. Rows written by an older build, or through an
// unclassified handle, are already on disk — and the only way to find them is
// to read both chains and compare each row against the registry, which is
// precisely what a merged reader is in a position to do.
//
// Only one direction is reported, and the asymmetry is the whole design.
//
// A control-plane-homed row sitting in a project's chain is unambiguously
// wrong: a project database has no business holding a fleet fact, and nothing
// legitimate puts one there.
//
// The reverse is not a finding. The hub runs from a directory that is itself a
// cloop project — always, not occasionally — so the control-plane database is
// also some project's database and its own `state.save`, `config.set` and
// `task.*` rows are exactly where they belong. Reporting those would fire on
// every real hub, and an advisory that always fires is one nobody reads, which
// would bury the single stray row this exists to surface.
//
// Actions homed HomeEither are scoped to whatever they decided about and are
// never misrouted; unregistered ones have no declared home to disagree with.
// Rows from a database named as both chains are skipped for the same reason the
// reverse direction is: both homes are correct in it.
func Misrouted(rows []Row) []Row {
	var out []Row
	for _, r := range rows {
		if r.Shared || r.Source != SourceProject {
			continue
		}
		home, known := auditaction.HomeOf(auditaction.Action(r.EventType))
		if !known || home == auditaction.HomeEither {
			continue
		}
		if home != auditaction.HomeProject {
			out = append(out, r)
		}
	}
	return out
}
