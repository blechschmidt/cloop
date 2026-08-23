package gitproxy

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// sha is a plausible non-zero object name. Nothing in the policy layer looks at
// the value, only at whether it is the all-zero name, so one constant serves
// every "this side exists" position in a RefUpdate.
const sha = "1234567890abcdef1234567890abcdef12345678"

// otherSHA distinguishes the two ends of an update in a failure message.
const otherSHA = "fedcba0987654321fedcba0987654321fedcba09"

// --- Normalize ---------------------------------------------------------------

func TestPolicyNormalizePrefixesBareBranchNames(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "bare name becomes a branch",
			in:   []string{"cloop/*"},
			want: []string{"refs/heads/cloop/*"},
		},
		{
			name: "a leading slash is not turned into an empty component",
			in:   []string{"/cloop/*"},
			want: []string{"refs/heads/cloop/*"},
		},
		{
			name: "surrounding whitespace is trimmed before the prefix is added",
			in:   []string{"  cloop/task-42  "},
			want: []string{"refs/heads/cloop/task-42"},
		},
		{
			name: "a pattern already under refs/ is left alone",
			in:   []string{"refs/tags/v*"},
			want: []string{"refs/tags/v*"},
		},
		{
			name: "an empty pattern is dropped rather than prefixed",
			in:   []string{"", "   ", "cloop/*"},
			want: []string{"refs/heads/cloop/*"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy{AllowedRefs: append([]string(nil), tc.in...), AllowCreate: true}
			p.Normalize()
			if !equalStrings(p.AllowedRefs, tc.want) {
				t.Fatalf("Normalize(%q) = %q, want %q", tc.in, p.AllowedRefs, tc.want)
			}
		})
	}
}

func TestPolicyNormalizeIsIdempotent(t *testing.T) {
	// "cloop/*" and its written-out form are the same pattern, so a second pass
	// must neither prefix twice nor resurrect the duplicate.
	first := Policy{
		AllowedRefs: []string{"cloop/*", "refs/heads/cloop/*", "refs/tags/v*"},
		AllowCreate: true,
	}
	first.Normalize()

	second := Policy{
		AllowedRefs: append([]string(nil), first.AllowedRefs...),
		AllowCreate: true,
		// Carry the filled-in bounds forward too: a second Normalize must not
		// treat an already-defaulted policy as a fresh one.
		MaxCommands:  first.MaxCommands,
		MaxPackBytes: first.MaxPackBytes,
	}
	second.Normalize()

	if !equalStrings(first.AllowedRefs, second.AllowedRefs) {
		t.Fatalf("Normalize is not idempotent: once %q, twice %q",
			first.AllowedRefs, second.AllowedRefs)
	}
	if first.MaxCommands != second.MaxCommands || first.MaxPackBytes != second.MaxPackBytes {
		t.Fatalf("Normalize is not idempotent on bounds: once (%d,%d), twice (%d,%d)",
			first.MaxCommands, first.MaxPackBytes, second.MaxCommands, second.MaxPackBytes)
	}
	if want := []string{"refs/heads/cloop/*", "refs/tags/v*"}; !equalStrings(first.AllowedRefs, want) {
		t.Fatalf("Normalize = %q, want %q", first.AllowedRefs, want)
	}
}

func TestPolicyNormalizeDedupesAfterPrefixing(t *testing.T) {
	// The duplicate only becomes visible once the bare name has been prefixed,
	// so dedupe has to run on the canonical form, not on what the caller wrote.
	p := Policy{
		AllowedRefs: []string{"cloop/*", "refs/heads/cloop/*", "cloop/*", "refs/tags/v*"},
		AllowCreate: true,
	}
	p.Normalize()

	want := []string{"refs/heads/cloop/*", "refs/tags/v*"}
	if !equalStrings(p.AllowedRefs, want) {
		t.Fatalf("Normalize = %q, want %q", p.AllowedRefs, want)
	}
}

func TestPolicyNormalizeFillsDefaults(t *testing.T) {
	t.Run("empty allowlist becomes the write-back namespace", func(t *testing.T) {
		p := Policy{AllowCreate: true}
		p.Normalize()
		if want := []string{DefaultAllowedRef}; !equalStrings(p.AllowedRefs, want) {
			t.Fatalf("AllowedRefs = %q, want %q", p.AllowedRefs, want)
		}
		if DefaultAllowedRef != "refs/heads/cloop/**" {
			t.Fatalf("DefaultAllowedRef = %q, want refs/heads/cloop/**", DefaultAllowedRef)
		}
	})

	t.Run("unset bounds get the defaults", func(t *testing.T) {
		p := Policy{AllowCreate: true}
		p.Normalize()
		if p.MaxCommands != DefaultMaxCommands {
			t.Fatalf("MaxCommands = %d, want %d", p.MaxCommands, DefaultMaxCommands)
		}
		if p.MaxPackBytes != DefaultMaxPackBytes {
			t.Fatalf("MaxPackBytes = %d, want %d", p.MaxPackBytes, DefaultMaxPackBytes)
		}
	})

	t.Run("negative bounds are replaced, not kept", func(t *testing.T) {
		// A negative cap would compare as "already exceeded" against every
		// push, which reads as a working policy that refuses everything.
		p := Policy{AllowCreate: true, MaxCommands: -1, MaxPackBytes: -1}
		p.Normalize()
		if p.MaxCommands != DefaultMaxCommands || p.MaxPackBytes != DefaultMaxPackBytes {
			t.Fatalf("negative bounds survived Normalize: (%d,%d)", p.MaxCommands, p.MaxPackBytes)
		}
	})

	t.Run("caller-set bounds are preserved", func(t *testing.T) {
		p := Policy{AllowCreate: true, MaxCommands: 3, MaxPackBytes: 4096}
		p.Normalize()
		if p.MaxCommands != 3 || p.MaxPackBytes != 4096 {
			t.Fatalf("Normalize overwrote caller bounds: (%d,%d)", p.MaxCommands, p.MaxPackBytes)
		}
	})
}

func TestWriteBackPolicyIsCreateAndUpdateInsideCloopOnly(t *testing.T) {
	p := WriteBackPolicy()
	switch {
	case !p.AllowCreate, !p.AllowUpdate:
		t.Fatalf("WriteBackPolicy must permit create and update, got %+v", p)
	case p.AllowDelete, p.AllowFetch:
		t.Fatalf("WriteBackPolicy must not permit delete or fetch, got %+v", p)
	}
	if want := []string{DefaultAllowedRef}; !equalStrings(p.AllowedRefs, want) {
		t.Fatalf("AllowedRefs = %q, want %q", p.AllowedRefs, want)
	}
	if p.IsZero() {
		t.Fatal("WriteBackPolicy reports IsZero, so Mint would substitute a default for it")
	}
	p.Normalize()
	if err := p.Validate(); err != nil {
		t.Fatalf("WriteBackPolicy does not validate: %v", err)
	}
}

// --- Validate ----------------------------------------------------------------

func TestPolicyValidateRefusesAPolicyThatPermitsNothing(t *testing.T) {
	// All four authorities off is the shape a caller who built a Policy{} and
	// expected defaults ends up with. Minting a session for it would produce
	// something that refuses every request it will ever see.
	p := Policy{AllowedRefs: []string{"refs/heads/cloop/**"}}
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate accepted a policy with all four authorities false")
	}
	if !strings.Contains(err.Error(), "permits nothing") {
		t.Fatalf("Validate error = %q, want it to say the policy permits nothing", err)
	}

	// One authority is enough to make it usable.
	for _, grant := range []func(*Policy){
		func(p *Policy) { p.AllowCreate = true },
		func(p *Policy) { p.AllowUpdate = true },
		func(p *Policy) { p.AllowDelete = true },
		func(p *Policy) { p.AllowFetch = true },
	} {
		q := Policy{AllowedRefs: []string{"refs/heads/cloop/**"}}
		grant(&q)
		q.Normalize()
		if err := q.Validate(); err != nil {
			t.Fatalf("Validate rejected %+v: %v", q, err)
		}
	}
}

func TestPolicyValidateRefusesAnEmptyAllowlist(t *testing.T) {
	// Reachable only without Normalize, which is exactly the ordering mistake
	// worth failing loudly on rather than defaulting silently.
	p := Policy{AllowCreate: true}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate accepted a policy with no ref patterns")
	}
}

func TestPolicyValidateRejectsMalformedPatterns(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantMsg string
	}{
		{"outside refs/", "heads/cloop/*", "must name a ref under refs/"},
		{"parent traversal", "refs/heads/../../x", "contains .."},
		{"leading dot-dot component", "refs/../x", "contains .."},
		{"empty path component", "refs/heads//x", "empty path component"},
		{"trailing slash", "refs/heads/cloop/", "ends with /"},
		{"embedded space", "refs/heads/cloop branch", "control character or space"},
		{"newline", "refs/heads/cloop\n*", "control character or space"},
		{"NUL", "refs/heads/cloop\x00*", "control character or space"},
		{"DEL", "refs/heads/cloop\x7f", "control character or space"},
		{"uncompilable glob", "refs/heads/[a-", "not a valid glob"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Bypass Normalize: several of these are patterns Normalize would
			// not have produced, and Validate is the backstop for a policy that
			// arrived from configuration or over the wire.
			p := Policy{AllowedRefs: []string{tc.pattern}, AllowCreate: true}
			err := p.Validate()
			if err == nil {
				t.Fatalf("Validate accepted pattern %q", tc.pattern)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("Validate(%q) = %q, want it to mention %q", tc.pattern, err, tc.wantMsg)
			}
			if !strings.Contains(err.Error(), "ref pattern") {
				t.Fatalf("Validate(%q) = %q, want it to name the offending pattern", tc.pattern, err)
			}
		})
	}
}

func TestPolicyValidateAllowsAWholeNamespaceDeliberately(t *testing.T) {
	// refs/** and refs/* permit everything including refs/heads/main. That is a
	// thing an operator may configure on purpose, so it must not be refused
	// here — refusing it would only move the decision somewhere less visible.
	for _, pat := range []string{"refs/**", "refs/*", "refs/heads/**"} {
		p := Policy{AllowedRefs: []string{pat}, AllowCreate: true}
		p.Normalize()
		if err := p.Validate(); err != nil {
			t.Fatalf("Validate rejected the deliberate whole-namespace pattern %q: %v", pat, err)
		}
	}
}

func TestPolicyValidateBoundsTheAllowlistLength(t *testing.T) {
	atLimit := make([]string, 0, MaxRefPatterns)
	for i := 0; i < MaxRefPatterns; i++ {
		atLimit = append(atLimit, fmt.Sprintf("refs/heads/cloop/task-%d", i))
	}
	p := Policy{AllowedRefs: atLimit, AllowCreate: true}
	p.Normalize()
	if len(p.AllowedRefs) != MaxRefPatterns {
		t.Fatalf("Normalize collapsed %d distinct patterns to %d", MaxRefPatterns, len(p.AllowedRefs))
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate rejected exactly MaxRefPatterns patterns: %v", err)
	}

	over := append(append([]string(nil), atLimit...), "refs/heads/cloop/one-too-many")
	q := Policy{AllowedRefs: over, AllowCreate: true}
	q.Normalize()
	err := q.Validate()
	if err == nil {
		t.Fatalf("Validate accepted %d patterns, over the %d limit", len(over), MaxRefPatterns)
	}
	if !strings.Contains(err.Error(), "at most") {
		t.Fatalf("Validate error = %q, want it to name the limit", err)
	}
}

// --- IsZero ------------------------------------------------------------------

func TestPolicyIsZero(t *testing.T) {
	if !(Policy{}).IsZero() {
		t.Fatal("Policy{}.IsZero() = false")
	}

	tests := []struct {
		name string
		p    Policy
	}{
		{"a named ref", Policy{AllowedRefs: []string{"refs/heads/cloop/**"}}},
		{"create", Policy{AllowCreate: true}},
		{"update", Policy{AllowUpdate: true}},
		{"delete", Policy{AllowDelete: true}},
		{"fetch", Policy{AllowFetch: true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.p.IsZero() {
				t.Fatalf("IsZero() = true for %+v", tc.p)
			}
		})
	}

	// The bounds alone do not make a policy non-zero: a caller who set only
	// MaxCommands still granted nothing, and substituting a default for that is
	// what IsZero is asked about.
	t.Run("bounds alone", func(t *testing.T) {
		if !(Policy{MaxCommands: 4, MaxPackBytes: 100}).IsZero() {
			t.Fatal("a policy with only bounds set no longer reports IsZero; " +
				"Mint would stop substituting WriteBackPolicy for it")
		}
	})
}

// --- AllowsRef ---------------------------------------------------------------

// TestPolicyAllowsRefMatchesTheDocumentedTable walks the table in
// docs/git-interception-proxy.md, which is the specification for this function.
func TestPolicyAllowsRefMatchesTheDocumentedTable(t *testing.T) {
	tests := []struct {
		pattern string
		matches []string
		misses  []string
	}{
		{
			// A bare name is read as a branch; "*" does not cross a "/".
			pattern: "cloop/*",
			matches: []string{"refs/heads/cloop/task-42"},
			misses:  []string{"refs/heads/cloop/task-42/fixup", "refs/heads/main", "refs/heads/cloop"},
		},
		{
			pattern: "refs/heads/cloop/*",
			matches: []string{"refs/heads/cloop/task-42"},
			misses:  []string{"refs/heads/cloop/task-42/fixup", "refs/heads/main", "refs/heads/cloop"},
		},
		{
			// "/**" is any depth strictly below the prefix — the prefix itself
			// is a namespace, not a branch.
			pattern: "refs/heads/cloop/**",
			matches: []string{"refs/heads/cloop/task-42", "refs/heads/cloop/task-42/fixup",
				"refs/heads/cloop/a/b/c"},
			misses: []string{"refs/heads/cloop", "refs/heads/main", "refs/heads/cloopy/x"},
		},
		{
			pattern: "refs/tags/v*",
			matches: []string{"refs/tags/v1.2.0", "refs/tags/v"},
			misses:  []string{"refs/tags/v1/2", "refs/heads/v1.2.0"},
		},
		{
			pattern: "refs/**",
			matches: []string{"refs/heads/main", "refs/tags/v1.2.0", "refs/heads/cloop/task-42/fixup"},
			misses:  []string{"refs", "refsX/heads/main"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			p := Policy{AllowedRefs: []string{tc.pattern}, AllowCreate: true}
			p.Normalize()
			for _, ref := range tc.matches {
				if !p.AllowsRef(ref) {
					t.Errorf("pattern %q (normalized %q) does not admit %q, but the spec says it should",
						tc.pattern, p.AllowedRefs, ref)
				}
			}
			for _, ref := range tc.misses {
				if p.AllowsRef(ref) {
					t.Errorf("pattern %q (normalized %q) admits %q, but the spec says it must not",
						tc.pattern, p.AllowedRefs, ref)
				}
			}
		})
	}
}

func TestPolicyAllowsRefUnionsThePatterns(t *testing.T) {
	p := Policy{
		AllowedRefs: []string{"cloop/*", "refs/tags/v*"},
		AllowCreate: true,
	}
	p.Normalize()
	for _, ref := range []string{"refs/heads/cloop/task-1", "refs/tags/v9"} {
		if !p.AllowsRef(ref) {
			t.Errorf("AllowsRef(%q) = false with allowlist %q", ref, p.AllowedRefs)
		}
	}
	if p.AllowsRef("refs/heads/main") {
		t.Error("AllowsRef(refs/heads/main) = true with a two-pattern allowlist that names neither")
	}
}

func TestPolicyAllowsRefDeniesEverythingWithNoPatterns(t *testing.T) {
	// Un-normalized: an empty allowlist is not "no restriction".
	p := Policy{AllowCreate: true, AllowUpdate: true, AllowDelete: true, AllowFetch: true}
	for _, ref := range []string{"refs/heads/cloop/task-1", "refs/heads/main", ""} {
		if p.AllowsRef(ref) {
			t.Errorf("an empty allowlist admitted %q", ref)
		}
	}
}

// --- Decide ------------------------------------------------------------------

func TestPolicyDecideChecksTheNameBeforeTheDirection(t *testing.T) {
	// A delete of a ref that is not in the allowlist has two problems. The
	// operator reading the audit trail wants the one that names the real
	// mistake — "main is not in the allowlist" — not "delete is not permitted",
	// which would suggest that permitting deletes were the fix.
	p := WriteBackPolicy()
	p.Normalize()

	err := p.Decide(RefUpdate{Old: sha, New: zeroSHA, Ref: "refs/heads/main"})
	if err == nil {
		t.Fatal("Decide permitted a delete of refs/heads/main")
	}
	if !errors.Is(err, ErrRefDenied) {
		t.Fatalf("Decide error %v does not wrap ErrRefDenied", err)
	}
	if !strings.Contains(err.Error(), "allowlist") || !strings.Contains(err.Error(), "refs/heads/main") {
		t.Fatalf("Decide error = %q, want it to name the ref and the allowlist", err)
	}
	if strings.Contains(err.Error(), "may not delete") {
		t.Fatalf("Decide error = %q, want the ref problem reported before the direction problem", err)
	}
	// The refusal names what is permitted, so the person running git push can
	// see what they should have targeted.
	if !strings.Contains(err.Error(), DefaultAllowedRef) {
		t.Fatalf("Decide error = %q, want it to list the allowed patterns", err)
	}
}

func TestPolicyDecideGatesEachDirectionSeparately(t *testing.T) {
	const ref = "refs/heads/cloop/task-42"
	create := RefUpdate{Old: zeroSHA, New: sha, Ref: ref}
	update := RefUpdate{Old: sha, New: otherSHA, Ref: ref}
	del := RefUpdate{Old: sha, New: zeroSHA, Ref: ref}

	tests := []struct {
		name    string
		policy  Policy
		update  RefUpdate
		wantErr string // "" means permitted
	}{
		{"create permitted", Policy{AllowedRefs: []string{DefaultAllowedRef}, AllowCreate: true}, create, ""},
		{"create refused", Policy{AllowedRefs: []string{DefaultAllowedRef}, AllowUpdate: true}, create, "may not create refs"},
		{"update permitted", Policy{AllowedRefs: []string{DefaultAllowedRef}, AllowUpdate: true}, update, ""},
		{"update refused", Policy{AllowedRefs: []string{DefaultAllowedRef}, AllowCreate: true}, update, "may not update existing refs"},
		{"delete permitted", Policy{AllowedRefs: []string{DefaultAllowedRef}, AllowDelete: true}, del, ""},
		{"delete refused", Policy{AllowedRefs: []string{DefaultAllowedRef}, AllowCreate: true, AllowUpdate: true}, del, "may not delete refs"},
		{"fetch alone authorises no write", Policy{AllowedRefs: []string{DefaultAllowedRef}, AllowFetch: true}, create, "may not create refs"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.policy
			p.Normalize()
			err := p.Decide(tc.update)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Decide(%s) = %v, want permitted", tc.update, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Decide(%s) permitted the update, want %q", tc.update, tc.wantErr)
			}
			if !errors.Is(err, ErrRefDenied) {
				t.Fatalf("Decide error %v does not wrap ErrRefDenied", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Decide(%s) = %q, want it to mention %q", tc.update, err, tc.wantErr)
			}
		})
	}
}

func TestPolicyDecideTreatsZeroToZeroAsADeleteAndTheParserRefusesIt(t *testing.T) {
	// Zero to zero is not one of the three authorities. Decide classifies it as
	// a delete — RefUpdate.IsDelete only looks at the new side — so the refusal
	// of the shape itself lives in the parser, before any policy runs.
	zz := RefUpdate{Old: zeroSHA, New: zeroSHA, Ref: "refs/heads/cloop/task-42"}
	if !zz.IsDelete() {
		t.Fatal("a zero-to-zero update no longer reports IsDelete; Decide's classification changed")
	}

	deleteRefused := Policy{AllowedRefs: []string{DefaultAllowedRef}, AllowCreate: true, AllowUpdate: true}
	deleteRefused.Normalize()
	if err := deleteRefused.Decide(zz); err == nil {
		t.Fatal("Decide permitted a zero-to-zero command under a no-delete policy")
	}

	_, err := parseCommand(zeroSHA + " " + zeroSHA + " refs/heads/cloop/task-42")
	if err == nil {
		t.Fatal("parseCommand accepted a zero-to-zero command line")
	}
	if !strings.Contains(err.Error(), "zero to zero") {
		t.Fatalf("parseCommand error = %q, want it to name the zero-to-zero shape", err)
	}
}

// --- DecideAll ---------------------------------------------------------------

func TestDecideAllIsAllOrNothing(t *testing.T) {
	p := WriteBackPolicy()
	p.Normalize()

	good := RefUpdate{Old: zeroSHA, New: sha, Ref: "refs/heads/cloop/task-42"}
	bad := RefUpdate{Old: sha, New: otherSHA, Ref: "refs/heads/main"}

	decisions, ok := p.DecideAll([]RefUpdate{good, bad, good})
	if ok {
		t.Fatal("DecideAll reported ok with a refused command in the list")
	}
	if len(decisions) != 3 {
		t.Fatalf("DecideAll returned %d decisions for 3 commands", len(decisions))
	}
	if !decisions[0].Allowed() || !decisions[2].Allowed() {
		t.Fatalf("DecideAll refused a command inside the allowlist: %v, %v",
			decisions[0].Err, decisions[2].Err)
	}
	if decisions[1].Allowed() {
		t.Fatal("DecideAll permitted a push to refs/heads/main")
	}
	if !errors.Is(decisions[1].Err, ErrRefDenied) {
		t.Fatalf("refused decision %v does not wrap ErrRefDenied", decisions[1].Err)
	}

	// The per-decision record of a command that passed on its own carries no
	// reason: DecideAll reports the verdict per command and the caller's `ok`
	// is what makes the push atomic. The "refused as a whole" wording the
	// client sees is composed in Proxy.refuse, not here.
	if got := decisions[0].Reason(); got != "" {
		t.Fatalf("a passing decision carries reason %q; DecideAll now annotates them", got)
	}

	// Reason is rendered for git's newline-delimited status report, so it must
	// be a single line.
	if r := decisions[1].Reason(); r == "" || strings.ContainsAny(r, "\r\n") {
		t.Fatalf("Reason() = %q, want a non-empty single line", r)
	}
}

func TestDecideAllReportsOKWhenEveryCommandPasses(t *testing.T) {
	p := WriteBackPolicy()
	p.Normalize()
	cmds := []RefUpdate{
		{Old: zeroSHA, New: sha, Ref: "refs/heads/cloop/task-1"},
		{Old: sha, New: otherSHA, Ref: "refs/heads/cloop/task-2/fixup"},
	}
	decisions, ok := p.DecideAll(cmds)
	if !ok {
		t.Fatalf("DecideAll refused an all-allowed push: %v", decisions)
	}
	for i, d := range decisions {
		if !d.Allowed() {
			t.Fatalf("command %d refused: %v", i, d.Err)
		}
	}
}

func TestDecideAllOnAnEmptyCommandList(t *testing.T) {
	// Git probes with an empty command section; there is nothing to authorise
	// and nothing to refuse.
	p := WriteBackPolicy()
	p.Normalize()
	decisions, ok := p.DecideAll(nil)
	if !ok || len(decisions) != 0 {
		t.Fatalf("DecideAll(nil) = (%v, %v), want (empty, true)", decisions, ok)
	}
}

// --- ValidateRefName ---------------------------------------------------------

func TestValidateRefNameAcceptsOrdinaryNames(t *testing.T) {
	for _, ref := range []string{
		"refs/heads/main",
		"refs/heads/cloop/task-42",
		"refs/heads/cloop/task-42/fixup",
		"refs/tags/v1.2.0",
		"refs/remotes/origin/HEAD",
		"refs/heads/feature_x-1.2",
	} {
		if err := ValidateRefName(ref); err != nil {
			t.Errorf("ValidateRefName(%q) = %v, want nil", ref, err)
		}
	}
}

func TestValidateRefNameRejectsWhatGitWould(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		wantMsg string
	}{
		{"empty", "", "empty"},
		{"outside refs/", "heads/main", "does not start with refs/"},
		{"bare HEAD", "HEAD", "does not start with refs/"},
		{"parent traversal", "refs/heads/../../x", "contains .., //, @{ or a backslash"},
		{"double slash", "refs/heads//x", "contains .., //, @{ or a backslash"},
		{"reflog syntax", "refs/heads/main@{1}", "contains .., //, @{ or a backslash"},
		{"backslash", `refs/heads/a\b`, "contains .., //, @{ or a backslash"},
		{"trailing slash", "refs/heads/x/", "ends with / or ."},
		{"trailing dot", "refs/heads/x.", "ends with / or ."},
		{"space", "refs/heads/ --upload-pack=sh", `contains " "`},
		{"tilde", "refs/heads/x~1", `contains "~"`},
		{"caret", "refs/heads/x^", `contains "^"`},
		{"colon", "refs/heads/x:y", `contains ":"`},
		{"question mark", "refs/heads/x?", `contains "?"`},
		{"asterisk", "refs/heads/x*", `contains "*"`},
		{"open bracket", "refs/heads/x[a", `contains "["`},
		{"newline", "refs/heads/x\ny", "control character"},
		{"NUL", "refs/heads/x\x00y", "control character"},
		{"carriage return", "refs/heads/x\ry", "control character"},
		{"DEL", "refs/heads/x\x7f", "control character"},
		{"component starting with a dot", "refs/heads/.hidden", "component starting with ."},
		{"lock suffix", "refs/heads/main.lock", "component ending in .lock"},
		{"lock suffix mid-path", "refs/heads/main.lock/x", "component ending in .lock"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRefName(tc.ref)
			if err == nil {
				t.Fatalf("ValidateRefName(%q) = nil, want a refusal", tc.ref)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("ValidateRefName(%q) = %q, want it to mention %q", tc.ref, err, tc.wantMsg)
			}
		})
	}
}

func TestValidateRefNameBoundsTheLength(t *testing.T) {
	atLimit := "refs/heads/" + strings.Repeat("a", 1024-len("refs/heads/"))
	if err := ValidateRefName(atLimit); err != nil {
		t.Fatalf("ValidateRefName rejected a 1024-byte name: %v", err)
	}
	over := atLimit + "a"
	err := ValidateRefName(over)
	if err == nil {
		t.Fatalf("ValidateRefName accepted a %d-byte name", len(over))
	}
	if !strings.Contains(err.Error(), "1024") {
		t.Fatalf("ValidateRefName error = %q, want it to name the limit", err)
	}
	// The refusal quotes the name, so it must not paste a kilobyte into a log
	// line.
	if len(err.Error()) > 300 {
		t.Fatalf("ValidateRefName error is %d bytes; the offending name is not elided", len(err.Error()))
	}
}

// --- helpers -----------------------------------------------------------------

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
