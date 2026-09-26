package gitproxy

import (
	"errors"
	"strings"
	"testing"
)

// Tests for RestrictRefs (Task 20340): the second allowlist a grant uses to
// narrow the hub's, so that "this project may push to feature/* only" is a
// property of the session rather than a request the sandbox is trusted with.

// restricted is the hub's default ceiling narrowed by a grant.
func restricted(ceiling, grant []string) Policy {
	p := Policy{
		AllowedRefs:  append([]string(nil), ceiling...),
		RestrictRefs: append([]string(nil), grant...),
		AllowCreate:  true,
		AllowUpdate:  true,
		AllowFetch:   true,
	}
	p.Normalize()
	return p
}

// TestRestrictRefsIntersectsWithTheCeiling is the rule: a ref has to clear both
// lists. Either one alone admitting it is not enough, in either direction.
func TestRestrictRefsIntersectsWithTheCeiling(t *testing.T) {
	p := restricted([]string{"refs/**"}, []string{"cloop/*", "release/**"})

	for _, ref := range []string{
		"refs/heads/cloop/task-1",
		"refs/heads/release/2026/09",
	} {
		if !p.AllowsRef(ref) {
			t.Errorf("AllowsRef(%q) = false; it is inside both lists", ref)
		}
	}
	for _, ref := range []string{
		// Inside the ceiling, outside the grant: the case the field exists for.
		"refs/heads/main",
		"refs/heads/cloop/task-1/fixup", // "*" does not cross a "/"
		"refs/tags/v1.0.0",              // a branch list says nothing about tags
		"refs/heads/release",            // "/**" is strictly below the prefix
	} {
		if p.AllowsRef(ref) {
			t.Errorf("AllowsRef(%q) = true; the grant's list does not admit it", ref)
		}
	}

	// And the other way round: a grant cannot widen the ceiling by naming a
	// branch the hub never allowed.
	narrowHub := restricted([]string{"refs/heads/cloop/**"}, []string{"main", "cloop/*"})
	if narrowHub.AllowsRef("refs/heads/main") {
		t.Error("a grant naming main widened a ceiling of refs/heads/cloop/**")
	}
	if !narrowHub.AllowsRef("refs/heads/cloop/task-9") {
		t.Error("refs/heads/cloop/task-9 is inside both lists and was refused")
	}
}

// TestRestrictRefsEmptyAddsNothing pins the other half of the contract: no
// restriction is exactly the ceiling, not "nothing" and not the default.
func TestRestrictRefsEmptyAddsNothing(t *testing.T) {
	with := restricted([]string{"refs/heads/cloop/**"}, nil)
	without := WriteBackPolicy()
	without.Normalize()
	for _, ref := range []string{"refs/heads/cloop/a", "refs/heads/cloop/a/b", "refs/heads/main"} {
		if with.AllowsRef(ref) != without.AllowsRef(ref) {
			t.Errorf("AllowsRef(%q) differs between an empty RestrictRefs (%v) and none (%v)",
				ref, with.AllowsRef(ref), without.AllowsRef(ref))
		}
	}
	if with.Restricted() {
		t.Error("Restricted() = true for a policy with no second list")
	}
}

// TestRestrictRefsNormalizes checks the second list gets the first list's
// normalisation, and none of its defaulting.
func TestRestrictRefsNormalizes(t *testing.T) {
	p := Policy{
		RestrictRefs: []string{" cloop/* ", "refs/heads/cloop/*", "", "feature/**"},
		AllowCreate:  true,
	}
	p.Normalize()
	want := []string{"refs/heads/cloop/*", "refs/heads/feature/**"}
	if !equalStrings(p.RestrictRefs, want) {
		t.Fatalf("RestrictRefs = %q, want %q", p.RestrictRefs, want)
	}

	// Idempotent, like the ceiling.
	again := p
	again.RestrictRefs = append([]string(nil), p.RestrictRefs...)
	again.Normalize()
	if !equalStrings(again.RestrictRefs, want) {
		t.Fatalf("second Normalize changed RestrictRefs to %q", again.RestrictRefs)
	}

	// No default: AllowedRefs gets the write-back namespace when empty, and an
	// empty RestrictRefs must stay empty rather than inherit it.
	q := Policy{AllowCreate: true}
	q.Normalize()
	if len(q.RestrictRefs) != 0 {
		t.Fatalf("an empty RestrictRefs was filled with %q", q.RestrictRefs)
	}
}

// TestRestrictRefsNeverWidensByNormalisingAway is the fail-closed case. A list
// that named something but held only blanks must not normalise into "no
// restriction", which is the widest reading of a field that exists to narrow.
func TestRestrictRefsNeverWidensByNormalisingAway(t *testing.T) {
	p := Policy{RestrictRefs: []string{"", "   "}, AllowCreate: true}
	p.Normalize()
	if !p.Restricted() {
		t.Fatal("a blank-only RestrictRefs normalised to no restriction at all")
	}
	if p.AllowsRef("refs/heads/cloop/task-1") || p.AllowsRef("refs/heads/main") {
		t.Error("a blank-only RestrictRefs admitted a ref")
	}
	if err := p.Validate(); err == nil {
		t.Error("Validate accepted a restriction that names no ref")
	}
}

// TestRestrictRefsDoesNotAliasTheCallersSlice mirrors the AllowedRefs test:
// Policy is copied by value, the slice is not.
func TestRestrictRefsDoesNotAliasTheCallersSlice(t *testing.T) {
	in := []string{"cloop/*", "cloop/*", "feature/*"}
	before := append([]string(nil), in...)
	p := Policy{AllowedRefs: []string{"refs/**"}, RestrictRefs: in, AllowCreate: true}
	p.Normalize()
	for i := range in {
		if in[i] != before[i] {
			t.Fatalf("Normalize wrote through into the caller's slice: %q, want %q", in, before)
		}
	}
}

func TestRestrictRefsValidate(t *testing.T) {
	for _, bad := range []string{
		"refs/heads/../main",
		"refs/heads//x",
		"refs/heads/x/",
		"refs/heads/a b",
		"refs/heads/[",
	} {
		p := Policy{RestrictRefs: []string{bad}, AllowCreate: true}
		p.Normalize()
		err := p.Validate()
		if err == nil {
			t.Errorf("Validate accepted restricting pattern %q", bad)
			continue
		}
		if !strings.Contains(err.Error(), "restricting ref pattern") {
			t.Errorf("Validate(%q) = %q; it should say which list the bad pattern is in", bad, err)
		}
	}

	many := make([]string, MaxRefPatterns+1)
	for i := range many {
		many[i] = "refs/heads/b" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + "/" + strings.Repeat("y", i)
	}
	p := Policy{RestrictRefs: many, AllowCreate: true}
	p.Normalize()
	if err := p.Validate(); err == nil {
		t.Errorf("Validate accepted %d restricting patterns", len(p.RestrictRefs))
	}
}

// TestRestrictRefsMakesAPolicyNonZero keeps Mint from replacing a policy that
// only narrows with WriteBackPolicy, which would drop the narrowing.
func TestRestrictRefsMakesAPolicyNonZero(t *testing.T) {
	if (Policy{RestrictRefs: []string{"cloop/*"}}).IsZero() {
		t.Fatal("a policy carrying RestrictRefs reports IsZero; Mint would discard the restriction")
	}
}

// TestDecideNamesWhichListRefused keeps the two refusals apart in prose, which
// is where the remedy lives: the hub's list is an operator's to widen, the
// grant's is the project's.
func TestDecideNamesWhichListRefused(t *testing.T) {
	p := restricted([]string{"refs/heads/cloop/**", "refs/heads/main"}, []string{"cloop/feature-*"})

	ceiling := p.Decide(RefUpdate{Old: sha, New: otherSHA, Ref: "refs/heads/develop"})
	grant := p.Decide(RefUpdate{Old: sha, New: otherSHA, Ref: "refs/heads/main"})
	ok := p.Decide(RefUpdate{Old: zeroSHA, New: sha, Ref: "refs/heads/cloop/feature-x"})

	if ok != nil {
		t.Fatalf("a ref inside both lists was refused: %v", ok)
	}
	for name, err := range map[string]error{"ceiling": ceiling, "grant": grant} {
		if !errors.Is(err, ErrRefDenied) {
			t.Fatalf("%s refusal %v does not wrap ErrRefDenied", name, err)
		}
		reason, _ := DenyReasonOf(err)
		if reason != DenyRefNotAllowed {
			t.Errorf("%s refusal classified %q, want %q", name, reason, DenyRefNotAllowed)
		}
	}
	if !strings.Contains(ceiling.Error(), "not in this session's branch allowlist") {
		t.Errorf("the ceiling's refusal changed wording: %q", ceiling)
	}
	if !strings.Contains(grant.Error(), "outside the branches this session's grant may push to") ||
		!strings.Contains(grant.Error(), "refs/heads/cloop/feature-*") {
		t.Errorf("the grant's refusal does not name the grant's list: %q", grant)
	}

	// Direction still gates a ref that clears both lists.
	del := p.Decide(RefUpdate{Old: sha, New: zeroSHA, Ref: "refs/heads/cloop/feature-x"})
	if r, _ := DenyReasonOf(del); r != DenyDelete {
		t.Errorf("a delete inside both lists was %v, want a %s refusal", del, DenyDelete)
	}
}

func TestRefSummary(t *testing.T) {
	p := restricted([]string{"refs/heads/cloop/**"}, nil)
	if got := p.RefSummary(); got != "refs/heads/cloop/**" {
		t.Errorf("RefSummary() = %q for an unrestricted policy", got)
	}
	p = restricted([]string{"refs/heads/cloop/**"}, []string{"cloop/x-*"})
	if got := p.RefSummary(); got != "refs/heads/cloop/** narrowed to refs/heads/cloop/x-*" {
		t.Errorf("RefSummary() = %q", got)
	}
}

// TestAReasonKeepsTheAllowlistWhateverTheRefsLength is the defect the live run
// found: git's status line is cut to one short line, and a long branch name
// restated inside the reason pushed the list of acceptable branches past the
// cut. The ref is printed beside the reason anyway, so the reason leaves it out
// — while the error itself still names it, for anything that logs it bare.
func TestAReasonKeepsTheAllowlistWhateverTheRefsLength(t *testing.T) {
	p := restricted([]string{"refs/heads/cloop/**"}, []string{"cloop/live-*"})
	long := "refs/heads/cloop/other-" + strings.Repeat("x", 90)

	for name, ref := range map[string]string{
		"outside the grant":   long,
		"outside the ceiling": "refs/heads/" + strings.Repeat("y", 100),
	} {
		t.Run(name, func(t *testing.T) {
			u := RefUpdate{Old: zeroSHA, New: sha, Ref: ref}
			err := p.Decide(u)
			if err == nil {
				t.Fatalf("%s was admitted", ref)
			}
			reason := Decision{Update: u, Err: err}.Reason()
			if strings.Contains(reason, ref) {
				t.Errorf("the reason repeats the ref git already prints: %q", reason)
			}
			if !strings.Contains(reason, "refs/heads/cloop/") || strings.HasSuffix(reason, "…") {
				t.Errorf("the reason lost the allowlist to the cut: %q", reason)
			}
			if !strings.Contains(err.Error(), ref) {
				t.Errorf("the error no longer names the ref it refused: %q", err)
			}
		})
	}
}
