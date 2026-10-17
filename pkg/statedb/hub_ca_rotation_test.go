package statedb

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// caRow is a CA row with recognisable sealed bytes, so a scan of the file can
// tell whether they survived.
func caRow(id, serial string) HubTLSRow {
	return HubTLSRow{
		ID: id, Kind: "ca", Serial: serial, CertPEM: "-----BEGIN CERTIFICATE-----\n" + serial + "\n-----END CERTIFICATE-----\n",
		KeyID: "kek_test", WrappedDEK: []byte("wrapped-dek-of-" + serial), KeySealed: []byte("sealed-key-of-" + serial + "-0123456789"),
		NotBefore: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2036, 10, 1, 0, 0, 0, 0, time.UTC),
		IssuedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), IssuedBy: "test",
	}
}

func stagedRotation(id, from, to string) HubCARotationRow {
	return HubCARotationRow{ID: id, State: HubCARotationStaged, FromSerial: from, ToSerial: to,
		Names: []string{"hub.internal"}, StagedAt: time.Now().UTC(), StagedBy: "test"}
}

// TestHubCARotationStepsMoveTheRows walks a rotation through its three steps
// and checks the rows and the journal after each, and that a step asked to
// move from a state the rotation is not in refuses rather than guessing.
func TestHubCARotationStepsMoveTheRows(t *testing.T) {
	db, err := Open(freshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if ok, err := db.InsertHubTLS(caRow(HubCAActive, "aaaa")); err != nil || !ok {
		t.Fatalf("insert the first CA: %v %v", ok, err)
	}

	ok, err := db.StageHubCA(caRow(HubCANext, "bbbb"), stagedRotation("rot_1", "aaaa", "bbbb"))
	if err != nil || !ok {
		t.Fatalf("stage: %v %v", ok, err)
	}
	// A second stage loses, and writes nothing — not even its journal row.
	if ok, err := db.StageHubCA(caRow(HubCANext, "cccc"), stagedRotation("rot_2", "aaaa", "cccc")); err != nil || ok {
		t.Fatalf("a second stage: ok=%v err=%v; want a refusal", ok, err)
	}
	if _, err := db.GetHubCARotation("rot_2"); !errors.Is(err, ErrHubTLSNotFound) {
		t.Fatalf("the refused stage left a journal row: %v", err)
	}
	cur, ok, err := db.CurrentHubCARotation()
	if err != nil || !ok || cur.ID != "rot_1" || cur.State != HubCARotationStaged || cur.Names[0] != "hub.internal" {
		t.Fatalf("current rotation after stage: %+v %v %v", cur, ok, err)
	}

	// Activating from the wrong serial refuses.
	if err := db.ActivateHubCA("ffff", "bbbb", "rot_1", time.Now(), "test", nil); !errors.Is(err, ErrHubCARotationConflict) {
		t.Fatalf("activation from the wrong CA: %v", err)
	}
	if err := db.ActivateHubCA("aaaa", "bbbb", "rot_1", time.Now(), "test", []string{"run_x"}); err != nil {
		t.Fatalf("activate: %v", err)
	}
	active, err := db.GetHubTLS(HubCAActive)
	if err != nil || active.Serial != "bbbb" || string(active.KeySealed) != string(caRow("", "bbbb").KeySealed) {
		t.Fatalf("active after activation: %+v %v", active, err)
	}
	prev, err := db.GetHubTLS(HubCAPrevious)
	if err != nil || prev.Serial != "aaaa" || string(prev.KeySealed) != string(caRow("", "aaaa").KeySealed) {
		t.Fatalf("previous after activation: %+v %v", prev, err)
	}
	if _, err := db.GetHubTLS(HubCANext); !errors.Is(err, ErrHubTLSNotFound) {
		t.Fatalf("the staged row outlived the activation: %v", err)
	}
	cur, _, _ = db.CurrentHubCARotation()
	if cur.State != HubCARotationActive || len(cur.Forced) != 1 || cur.ActivatedAt.IsZero() {
		t.Fatalf("journal after activation: %+v", cur)
	}
	// A stage while the previous CA is still trusted would make three: the
	// activation of it must refuse.
	if ok, err := db.StageHubCA(caRow(HubCANext, "dddd"), stagedRotation("rot_3", "bbbb", "dddd")); err != nil || !ok {
		t.Fatalf("stage during an active rotation (the store allows it; pkg/hubca refuses): %v %v", ok, err)
	}
	if err := db.ActivateHubCA("bbbb", "dddd", "rot_3", time.Now(), "test", nil); !errors.Is(err, ErrHubCARotationConflict) {
		t.Fatalf("activating a third CA while the previous is still trusted: %v", err)
	}
	if err := db.AbandonHubCANext("dddd", "rot_3", time.Now(), "test", "test"); err != nil {
		t.Fatalf("abandon: %v", err)
	}
	if r, err := db.GetHubCARotation("rot_3"); err != nil || r.State != HubCARotationAbandoned || r.Detail != "test" {
		t.Fatalf("abandoned journal: %+v %v", r, err)
	}

	if err := db.RetireHubCAPrevious("bbbb", "rot_1", time.Now(), "test", nil); !errors.Is(err, ErrHubCARotationConflict) {
		t.Fatalf("retiring the active CA as the previous one: %v", err)
	}
	if err := db.RetireHubCAPrevious("aaaa", "rot_1", time.Now(), "test", []string{"run_y"}); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if _, err := db.GetHubTLS(HubCAPrevious); !errors.Is(err, ErrHubTLSNotFound) {
		t.Fatalf("the previous CA survived its retirement: %v", err)
	}
	if _, ok, _ := db.CurrentHubCARotation(); ok {
		t.Fatal("a retired rotation is still current")
	}
	r, _ := db.GetHubCARotation("rot_1")
	if r.State != HubCARotationRetired || len(r.CutRuns) != 1 || r.EndedAt.IsZero() {
		t.Fatalf("journal after retirement: %+v", r)
	}
	if hist, err := db.ListHubCARotations(10); err != nil || len(hist) != 2 {
		t.Fatalf("history: %d rows, %v", len(hist), err)
	}
}

// TestARetiredCAsKeyIsGoneFromTheFile: deleting a row leaves its record in the
// page's free space unless secure_delete zeroes it, and every earlier write —
// the activation that moved it, a rewrap under a new KEK — freed an image of
// it too. After a rotation retires a CA whose key was rewrapped first, and the
// last handle closes (which checkpoints and removes the log), neither of its
// envelopes is anywhere in the file; the new CA's, which is still live, is.
func TestARetiredCAsKeyIsGoneFromTheFile(t *testing.T) {
	path := freshPath(t)
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	old := caRow(HubCAActive, "0ld0ld")
	if ok, err := db.InsertHubTLS(old); err != nil || !ok {
		t.Fatalf("insert: %v %v", ok, err)
	}
	// A key rotation rewraps the old CA's key: the image it frees holds the
	// first envelope.
	rewrapped := SealedRow{KeyID: "kek_two", WrappedDEK: []byte("rewrapped-dek-of-0ld0ld"), Ciphertext: []byte("rewrapped-key-of-0ld0ld-9876543210")}
	if ok, err := db.ReplaceHubTLSSealed(HubCAActive,
		SealedRow{KeyID: old.KeyID, WrappedDEK: old.WrappedDEK, Ciphertext: old.KeySealed}, rewrapped); err != nil || !ok {
		t.Fatalf("rewrap: %v %v", ok, err)
	}
	if ok, err := db.StageHubCA(caRow(HubCANext, "n3wn3w"), stagedRotation("rot_f", "0ld0ld", "n3wn3w")); err != nil || !ok {
		t.Fatalf("stage: %v %v", ok, err)
	}
	if err := db.ActivateHubCA("0ld0ld", "n3wn3w", "rot_f", time.Now(), "test", nil); err != nil {
		t.Fatalf("activate: %v", err)
	}
	if err := db.RetireHubCAPrevious("0ld0ld", "rot_f", time.Now(), "test", nil); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for what, b := range map[string][]byte{
		"the retired CA's first sealed key": old.KeySealed, "the retired CA's first wrapped DEK": old.WrappedDEK,
		"the retired CA's rewrapped key": rewrapped.Ciphertext, "the retired CA's rewrapped DEK": rewrapped.WrappedDEK,
	} {
		if bytes.Contains(data, b) {
			t.Errorf("%s is still in the file after retirement", what)
		}
	}
	if !bytes.Contains(data, caRow("", "n3wn3w").KeySealed) {
		t.Error("the live CA's sealed key is not in the file: the scan is not reading what it should")
	}
}

// TestHubCAMemberRows: a member's report is updated in place, read back whole,
// and pruned once the member stops reporting.
func TestHubCAMemberRows(t *testing.T) {
	db, err := Open(freshPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	for _, r := range []HubCAMemberRow{
		{InstanceID: "hub_a", Active: "aaaa", Trusts: []string{"aaaa"}, SeenAt: now.Add(-time.Hour)},
		{InstanceID: "hub_a", Active: "aaaa", Trusts: []string{"aaaa", "bbbb"}, AdoptedAt: now, SeenAt: now,
			Leaves: map[string]HubCALeafAck{"git_proxy": {Serial: "1111", Issuer: "aaaa"}}},
		{InstanceID: "hub_gone", Active: "aaaa", Trusts: []string{"aaaa"}, SeenAt: now.Add(-48 * time.Hour)},
	} {
		if err := db.PutHubCAMember(r); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.ListHubCAMembers()
	if err != nil || len(rows) != 2 {
		t.Fatalf("members: %+v %v", rows, err)
	}
	a := rows[0]
	if a.InstanceID != "hub_a" || strings.Join(a.Trusts, ",") != "aaaa,bbbb" || a.Leaves["git_proxy"].Issuer != "aaaa" ||
		!a.AdoptedAt.Equal(now.Truncate(0)) {
		t.Fatalf("member row = %+v", a)
	}
	if n, err := db.PruneHubCAMembers(now.Add(-24 * time.Hour)); err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if rows, _ := db.ListHubCAMembers(); len(rows) != 1 || rows[0].InstanceID != "hub_a" {
		t.Fatalf("after prune: %+v", rows)
	}
}

// Every write to hub_tls runs on a secure-delete connection — a statement
// given to secureExec, or one on the transaction shreddingTx began — for the
// reason TestEveryKeyRegistryWriteIsSecureDelete gives for the KEK registry: a
// writer on the pool frees an image of a row with a sealed key in it unzeroed,
// and the file keeps it past the CA's retirement (Task 20438).
func TestEveryHubTLSWriteIsSecureDelete(t *testing.T) {
	fset := token.NewFileSet()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	write := regexp.MustCompile(`(?is)\b(update|insert\s+(or\s+\w+\s+)?into|delete\s+from|replace\s+into)\s+hub_tls\b`)
	callsShredding := func(fn *ast.FuncDecl) bool {
		found := false
		ast.Inspect(fn, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "shreddingTx" {
					found = true
				}
			}
			return !found
		})
		return found
	}
	writes := 0
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok || len(c.Args) == 0 {
					return true
				}
				// The statement may be built from a literal and a constant
				// (`INSERT INTO hub_tls(`+hubTLSColumns+`)`): read the leftmost
				// literal of a concatenation.
				arg := c.Args[0]
				for {
					be, ok := arg.(*ast.BinaryExpr)
					if !ok {
						break
					}
					arg = be.X
				}
				lit, ok := arg.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING || !write.MatchString(lit.Value) {
					return true
				}
				writes++
				sel, _ := c.Fun.(*ast.SelectorExpr)
				switch {
				case sel != nil && sel.Sel.Name == "secureExec":
				case sel != nil && isIdent(sel.X, "tx") && callsShredding(fn):
				default:
					t.Errorf("%s: %s writes hub_tls off a secure-delete connection", fset.Position(lit.Pos()), fn.Name.Name)
				}
				return true
			})
		}
	}
	if writes < 10 {
		t.Fatalf("found %d writes to hub_tls; the scan is not reading what it should", writes)
	}
}
