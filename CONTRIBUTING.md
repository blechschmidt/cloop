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

## Committing

After every change, run:

```bash
/usr/local/go/bin/go build -o cloop . && /usr/local/go/bin/go vet ./...
```

Commit messages follow conventional-commit style (`feat(...)`, `fix(...)`,
`test(...)`, `docs(...)`).

Pre-commit hooks must not be bypassed (`--no-verify` is forbidden) — fix the
underlying issue instead.
