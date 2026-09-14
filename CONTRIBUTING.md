# Contributing to cloop

Thanks for considering a contribution. This file documents the developer
workflow, including how to build, test, and fuzz the codebase.

## Building

```bash
/usr/local/go/bin/go build -o cloop .
```

Or via the Makefile:

```bash
make build
```

cloop targets Go 1.25 (see `go.mod`). The binary is self-contained — no CGo,
no external state required to run.

## Testing

```bash
make test          # unit tests + e2e
make test-unit     # unit only, with -race and coverage
make test-e2e      # end-to-end CLI tests against the built binary
```

Always run unit tests with the race detector (`make test-unit` enables it) when
touching the orchestrator, state, or WebSocket hub — those code paths have
historically grown subtle data races.

### Keeping the suite fast

`pkg/ui` is the largest package and the one closest to CI's timeout, so it is
worth knowing why it is not slower than it is. Two things dominate, and both
have a fix already in place that new tests should reuse:

- **Creating a project database.** `statedb.Open` applies 29 migrations to a
  new database, which costs ~457ms under `-race` because `modernc.org/sqlite`
  is pure Go and the detector instruments all of it. Test helpers call
  `seedMigratedDB(t, dir)` (see `pkg/ui/dbtemplate_test.go`) to drop a
  pre-migrated database into the directory first, so `Open` finds nothing left
  to apply. A new helper that creates a project directory should do the same.
- **Scanning the dashboard bundle.** Static-analysis tests that walk
  `dashboardSource` run over ~13k lines. Narrow the lines once before looping
  over routes rather than running a regex per (route × line).

## Benchmarking

```bash
make bench                                    # all, short benchtime
make bench BENCHTIME=2s BENCH=BenchmarkAdmit  # one, for a real number
```

The benchmarks cover the control-plane paths whose cost scales with something
no operator sets deliberately — tenants, audit-trail length, plan size:

| Package | Covers |
| --- | --- |
| `pkg/ui` | wire-snapshot marshalling, state diffing, WebSocket fanout at 1/10/100 subscribers |
| `pkg/statedb` | plan save/load, audit append (single and batch), full chain verification |
| `pkg/quota` | per-identity admission, serial and contended, admit and deny |

CI runs them at the default short benchtime and publishes the output as the
`benchmark-results` artifact. That job asserts **no latency bound** on purpose:
run-to-run variance on a shared runner is larger than most regressions worth
catching, so a threshold would fire wrongly far more often than rightly. It
exists to keep the benchmarks compiling and to make two commits comparable by
hand; the order-of-magnitude guard is the job's `timeout-minutes`.

Don't run benchmarks under `-race` — the detector inflates every number
unevenly, so the result measures the instrumentation.

## Fuzzing

cloop ships native Go fuzz targets (`testing.F`) for every parser that ingests
untrusted input — config files, plan import files, the legacy state.json
migration path, the relative-time deadline parser, and the JSON-schema config
validator. None of them should panic on any input.

Run all fuzz targets at the default 30-second budget per target:

```bash
make fuzz
```

Run a single target for longer (useful when triaging a found crash):

```bash
/usr/local/go/bin/go test -run=^$ -fuzz=FuzzImportYAML -fuzztime=5m ./pkg/planio/
```

Override the per-target budget:

```bash
make fuzz FUZZTIME=2m
```

CI runs this same `make fuzz` target on every push (the **Parser fuzzing** job)
at `FUZZTIME=20s`, which is ~3.5 minutes of fuzzing in total. That budget is
sized for the shallow panic a refactor introduces — the accumulated corpus
finds those in seconds — not for discovering something new. A deep campaign is
`make fuzz FUZZTIME=5m` on a machine with time to spare.

The run goes through `scripts/fuzz-ci.sh` rather than calling `go test -fuzz`
directly, because two outcomes look identical to `go test` and must not be
treated alike:

- **A clean budget expiry reported as a failure.** Go's fuzz coordinator
  intermittently reports `context deadline exceeded` as a test failure when the
  `-fuzztime` deadline fires mid-RPC (golang/go#72104). Nothing was found; the
  same target passes on the next run. The script tolerates that one artifact.
- **A committed regression seed.** A fixed crash keeps its input under
  `testdata/fuzz/` forever, so "this corpus directory has files in it" is true
  of every package that has ever had a finding fixed. The script decides
  "reproducer written" against a snapshot of the directory taken immediately
  before the run, so only a *new* file counts.

Everything else — a build error, a panic in the harness, a seed that has
started crashing again — fails.

### Fuzz targets

| Package              | Target                  | Surface                                                    |
| -------------------- | ----------------------- | ---------------------------------------------------------- |
| `pkg/config`         | `FuzzLoadConfig`        | YAML decoding + numeric clamp / env-var post-processing.   |
| `pkg/planio`         | `FuzzImportYAML`        | Plan import — YAML format.                                |
| `pkg/planio`         | `FuzzImportJSON`        | Plan import — JSON format.                                |
| `pkg/planio`         | `FuzzImportTOML`        | Plan import — TOML format.                                |
| `pkg/state`          | `FuzzMigrateLegacyJSON` | Legacy `state.json` → SQLite `state.db` migration path.   |
| `pkg/pm`             | `FuzzParseDeadline`     | Relative (`2h`, `3d`, `1w`) / RFC3339 / date-only parser. |
| `pkg/configvalidate` | `FuzzValidate`          | JSON-schema-style config validator (`Run`).                |

### Adding a new fuzz target

1. Create `pkg/<pkg>/<name>_fuzz_test.go` (any `_test.go` file works; keeping
   `_fuzz_test.go` makes intent obvious).
2. Implement `func FuzzXxx(f *testing.F)`. Seed it with a small corpus of
   real-world fixtures plus pathological inputs (empty bytes, BOMs, multibyte
   boundaries, deeply nested structures, garbage).
3. Inside `f.Fuzz(func(t *testing.T, ...))`, exercise the parser. The fuzz
   function must return cleanly — a parse error is fine, a panic or `t.Fatal`
   on benign-but-malformed input is a real failure.
4. Add the target to `FUZZ_TARGETS` in the `Makefile`, as
   `./pkg/<pkg>/:FuzzXxx`. That list is the only place the set of targets is
   written down — CI runs `make fuzz`, so a target added there is gated on the
   next push with no second edit and no way for the two to disagree about what
   is covered.

### When a fuzz run finds a crash

Go writes the crashing input to `pkg/<pkg>/testdata/fuzz/FuzzXxx/<hash>`. That
file is automatically picked up as a regression seed by every subsequent
`go test` run, so fixing the underlying bug and committing the seed file
produces a permanent regression test.

```bash
# Reproduce locally:
/usr/local/go/bin/go test -run=FuzzXxx/<hash> ./pkg/<pkg>/
```

## Goroutine-leak detection

Critical long-lived subsystems ship a package-local `*_goroutine_leak_test.go`
file that catches background-goroutine leaks before they reach production.
The pattern is documented in detail at the top of
[`pkg/statedb/goroutine_leak_test.go`](pkg/statedb/goroutine_leak_test.go) —
read that file first when adding a new one. It is the fullest of the nine,
because it also explains how the slack threshold is chosen when the subsystem
under test keeps ambient goroutines of its own.

cloop intentionally does NOT depend on `go.uber.org/goleak`. Instead each
test follows a three-piece shape:

1. `const goroutineLeakSlack = 10` (or higher for SQLite-backed packages) —
   absorbs runtime/scheduler/driver ambient flapping while staying well below
   any real per-cycle leak at the chosen N.
2. `settleGoroutineCount() int` — GC, yield, sleep briefly, GC again, then
   sample `runtime.NumGoroutine`. Sleep window is per-package: 50-100ms
   covers most teardown paths; SQLite needs ~200ms for finalisers to settle.
3. `TestXxx_NoGoroutineLeak` — warm-up call → baseline → loop N happy-path
   lifecycles → re-sample → assert delta ≤ slack.

Why not `goleak`? Several driver dependencies (`modernc.org/sqlite`,
`nhooyr.io/websocket`) keep ambient background goroutines that goleak's
default-ignore allowlist does not cover, forcing a per-package
`IgnoreCurrent`/`IgnoreTopFunction` list. The macroscopic delta-vs-baseline
assertion is robust to those drivers without any allowlist maintenance — a
real leak scales with N, ambient noise does not.

Packages that currently ship a leak test: `pkg/orchestrator`, `pkg/ui`,
`pkg/watchdog`, `pkg/statedb`, `pkg/filewatch`, `pkg/compare`,
`pkg/consensus`, `pkg/bench`, `pkg/logtail`. When adding a long-lived
goroutine to any subsystem, add a matching test in that package — copy
the canonical reference file's shape and document the goroutine you're
guarding.

## Unreferenced packages

A new `pkg/<feature>/` that nothing imports fails CI's **Static analysis** job:

```bash
go test ./tests/arch/
```

The gate exists because an unreferenced package is invisible to everything
else — it still builds, it still vets clean, and its own tests still pass.
`pkg/adr` was a complete 433-line feature in that state for months. So when you
add a package, wire it into a command or a caller in the same change; when the
gate fires, the two legitimate answers are to wire it up or to delete it, and
it deliberately prefers neither. `tests/arch/orphan_test.go` has an `exempt`
map for packages that are unreferenced on purpose — it is empty, and an entry
needs an argument a reader can check.

## Committing

After every change, run:

```bash
/usr/local/go/bin/go build -o cloop . && /usr/local/go/bin/go vet ./...
```

Commit messages follow conventional-commit style (`feat(...)`, `fix(...)`,
`test(...)`, `docs(...)`).

Pre-commit hooks must not be bypassed (`--no-verify` is forbidden) — fix the
underlying issue instead.
