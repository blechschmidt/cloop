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
4. Wire the target into the `fuzz` recipe in the `Makefile` so `make fuzz`
   runs it.

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
[`pkg/watchdog/goroutine_leak_test.go`](pkg/watchdog/goroutine_leak_test.go) —
read that file first when adding a new one.

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

## Committing

After every change, run:

```bash
/usr/local/go/bin/go build -o cloop . && /usr/local/go/bin/go vet ./...
```

Commit messages follow conventional-commit style (`feat(...)`, `fix(...)`,
`test(...)`, `docs(...)`).

Pre-commit hooks must not be bypassed (`--no-verify` is forbidden) — fix the
underlying issue instead.
