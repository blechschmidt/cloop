# celprobe — the CEL ground truth for `pkg/celmatch`

`pkg/celmatch` is a hand-written subset of CEL that decides which external CI
pipeline may assume a role on the hub. The operator who writes a rule takes
their mental model from GitHub's and Google's OIDC documentation, both of which
describe *real* CEL — so the property that protects the hub is one-directional:

```
celmatch admits  =>  real CEL admits
```

Stricter is free. Looser is an authorization bypass the operator cannot find by
re-reading their own policy, because their policy means what they think it
means; the evaluator is the thing that disagrees.

This program is how that gets checked against reality rather than against
someone's reading of the spec. It runs every case in `../conformance.json`
through `cel.dev/cel-go` and writes the verdicts to `../cel-verdicts.json`,
which `../../conformance_test.go` then holds the subset against.

## Why it is a separate module

Two reasons, and both matter:

- **cloop must not depend on cel-go.** The subset exists because full CEL is a
  large language and every feature in it is a way for an operator's reading and
  a machine's evaluation to diverge (see the package doc). Linking the thing it
  is deliberately not is self-defeating, and it would add a substantial
  dependency tree to a hub that needs none of it.
- **It still has to be re-runnable.** A one-off script in `/tmp` would make the
  CEL column unverifiable the moment the author's shell closed, which is
  exactly the state that let the corpus be wrong in the first place.

The go tool ignores nested modules *and* `testdata/` directories, so
`go build ./...`, `go vet ./...`, `go test ./...` and `go mod tidy` at the
repository root never see this. That is checked: `tests/arch` asserts nested
modules are excluded from the module graph, and the commit that added this
verified `go mod tidy` leaves `go.mod`/`go.sum` byte-identical.

## Usage

```sh
cd pkg/celmatch/testdata/celprobe

go run .            # report; exits non-zero if ../cel-verdicts.json is stale
go run . -update    # rewrite ../cel-verdicts.json
```

Then regenerate the human-readable side-by-side:

```sh
cd /path/to/cloop
go test ./pkg/celmatch/ -run TestConformance_TableIsCurrent -update
```

## When to re-run it

- **After adding a case to `conformance.json`.** The test fails on a case with
  no recorded CEL verdict rather than letting it go unchecked, so this is not
  optional — but the failure tells you.
- **After bumping cel-go**, to see whether the reference implementation's own
  behaviour moved. It has: the module path was renamed from
  `github.com/google/cel-go` to `cel.dev/cel-go`, and `sub` claim formats
  changed under it on the GitHub side.
- **Never to make a failing test pass.** If the invariant breaks, the subset
  admitted something CEL refuses. Fix the subset.

## Verdict domain

| Verdict | Meaning |
| --- | --- |
| `allow` | evaluated to true — the only verdict that admits |
| `deny` | evaluated to false |
| `error` | evaluated, and the evaluation failed |
| `parse_error` | refused before evaluation (CEL: parse or check) |
| `non_bool` | evaluated to a value that is not a bool |

`assertion` is declared as a `dyn` rather than a concrete map type, because that
is how Google's workload identity federation presents it and it is the
configuration under which CEL's type errors surface at evaluation time instead
of at check time. That is the interesting comparison: `pkg/celmatch` has no
checker, so every type question it asks, it asks during evaluation.
