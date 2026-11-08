# Contributing to cloop

Thanks for considering a contribution. This file describes the developer
workflow, including how to build, test and fuzz the code.

## Building

```bash
/usr/local/go/bin/go build -o cloop .
```

Or with the Makefile:

```bash
make build
```

cloop targets Go 1.26 (see `go.mod`). The binary is self-contained: it needs
no CGo and no external state to run.

## Testing

```bash
make test          # unit tests + e2e
make test-unit     # unit only, with -race and coverage
make test-e2e      # end-to-end CLI tests against the built binary
```

When you change the orchestrator, the state code or the WebSocket hub, always
run the unit tests with the race detector (`make test-unit` turns it on).
Those code paths have had subtle data races before.

### Keeping the suite fast

CI's race step is the slowest job, and the longest-running packages
(`pkg/orchestrator`, `pkg/statedb`, `tests/security`) decide how long it takes.
`go test` starts packages in the order they are named, so the step (and
`make test-unit`) lists them through `scripts/race-packages.sh`, longest
first. If a package starts taking minutes, add it to the script's `slow` list.

`pkg/ui` is too big for one job, so CI runs it in the **Test pkg/ui** shard
jobs, each with a share of its top-level tests (`scripts/test-shards.py`). A
new test needs no setup: if the duration table
`scripts/test-durations/pkg-ui.txt` doesn't list it, a hash of its name picks
its shard, and the shards' first step fails if a test is selected by no shard,
or by two. When the shards' times drift apart, refresh the table
(`scripts/test-durations.py ./pkg/ui/ > scripts/test-durations/pkg-ui.txt`).
When they all grow, add a shard to the matrix. `make test-unit` still runs the
whole package.

Every package has a time budget. The race step and each shard fail, naming the
package, when a package takes more than 60% of its 30-minute `-timeout`
(`scripts/test-budget.py`), long before it would actually time out. If yours
is named, `scripts/test-durations.py ./pkg/<name>/ | head -20` shows where the
time goes. A few costs dominate, and each already has a fix that new tests
should reuse:

- **Creating a project database.** `statedb.Open` applies every migration in
  `pkg/statedb/migrations` to a new database. That takes ~1.5 s under `-race`,
  because `modernc.org/sqlite` is pure Go, the race detector instruments all
  of it, and each `ALTER TABLE … ADD COLUMN` re-parses the whole schema. If a
  test needs a project or a database but isn't testing how one is created, use
  `internal/statedbtest`: `statedbtest.Dir(t)` for a project directory,
  `statedbtest.SeedDir(t, dir)` before `state.Init` on a directory you already
  have, and `statedbtest.Open(t)` for a `*statedb.DB`. They copy a database
  that is migrated once per test binary, so `Open` finds nothing left to
  apply. Tests of migrations, schema adoption, version skew or first-open races
  must still start from scratch. `pkg/statedb`'s own tests use `openFresh`,
  `freshPath` and `freshDir` (template_test.go) instead, because a package's
  own tests can't import a package that imports it.
- **Browser drivers.** A `testdata/*_browser.js` driver must clear each CDP
  command's timeout when the reply arrives, and call `process.exit` on
  success. A timer left running keeps node, and the Go test waiting for it,
  alive for up to 20 s after the work is done.
  `TestBrowserDriversReleaseNodeWhenDone` checks this.
- **Long browser crawls.** Keep browser tests that run for minutes out of the
  race step. The race detector can't see into the browser, and on a slow
  runner the two-minute hostile-strings crawl pushed `pkg/ui` past the step's
  30-minute package timeout. `TestHostileStrings_EveryControlInBrowser` and
  `TestHostileMemberIdentities_InBrowser` skip under `-race` (set
  `CLOOP_XSS_CRAWL=1` to run them there anyway) and run in CI's **Hostile
  strings in a real browser** job, which fails unless each prints PASS.
- **Loading the module for static analysis.** `tests/security` type-checks the
  whole module once per test binary (`loadModule`). A new structural check
  should use that result instead of calling `packages.Load` again, which takes
  ~30 s under `-race`.
- **Scanning the dashboard bundle.** Static-analysis tests that walk
  `dashboardSource` go over ~13k lines. Narrow down the lines once before
  looping over routes, so you don't run a regex for every route and line.

## Benchmarking

```bash
make bench                                    # all, short benchtime
make bench BENCHTIME=2s BENCH=BenchmarkAdmit  # one, for a real number
```

The benchmarks cover the control-plane paths whose cost grows with things no
operator sets directly: tenants, audit-trail length and plan size.

| Package | Covers |
| --- | --- |
| `pkg/ui` | wire-snapshot marshalling, state diffing, WebSocket fanout at 1/10/100 subscribers |
| `pkg/statedb` | plan save/load, audit append (single and batch), full chain verification |
| `pkg/quota` | per-identity admission, serial and contended, admit and deny |

CI runs them at the default short benchtime and publishes the output as the
`benchmark-results` artifact. The job checks no latency bound. On a shared
runner, the variance between runs is larger than most regressions worth
catching, so a threshold would fail on noise far more often than on a real
regression. The job keeps the benchmarks compiling and lets you compare two
commits by hand, and its `timeout-minutes` catches slowdowns of an order of
magnitude.

Don't run benchmarks under `-race`. The race detector slows everything down
unevenly, so the results would measure the instrumentation.

## Fuzzing

cloop has native Go fuzz targets (`testing.F`) for every parser that reads
untrusted input: config files, plan import files, the legacy state.json
migration path, the relative-time deadline parser and the JSON-schema config
validator. None of them may panic on any input. Two more fuzz a property
instead of a parser: that `cloop hub doctor` and the hub agree about a
redirect URL, and that the hub's router can serve every redirect URL the hub
accepts.

Run all fuzz targets with the default budget of 30 seconds per target:

```bash
make fuzz
```

Run a single target for longer (useful when you investigate a crash it found):

```bash
/usr/local/go/bin/go test -run=^$ -fuzz=FuzzImportYAML -fuzztime=5m ./pkg/planio/
```

Override the per-target budget:

```bash
make fuzz FUZZTIME=2m
```

CI runs the same `make fuzz` target on every push (the **Parser fuzzing** job)
with `FUZZTIME=20s`, which is about six minutes of fuzzing in total across its
18 targets. That is enough to catch the shallow panics a refactor introduces,
which the accumulated corpus finds in seconds, but not to discover new bugs.
For a deep run, use `make fuzz FUZZTIME=5m` on a machine with time to spare.

The run goes through `scripts/fuzz-ci.sh` instead of calling `go test -fuzz`
directly, so that two harmless outcomes aren't mistaken for findings:

- **A clean budget expiry reported as a failure.** Go's fuzz coordinator
  sometimes reports `context deadline exceeded` as a test failure when the
  `-fuzztime` deadline fires in the middle of an RPC (golang/go#72104). Nothing
  was found, and the same target passes on the next run. The script tolerates
  this one case.
- **A committed regression seed.** A fixed crash keeps its input under
  `testdata/fuzz/` permanently, so every package that has ever had a finding
  fixed has files in its corpus directory. The script compares the directory
  with a snapshot taken just before the run, so only a new file counts as a
  reproducer.

Everything else fails the run, including a build error, a panic in the
harness, and a seed that has started crashing again.

### Fuzz targets

| Package              | Target                  | Surface                                                    |
| -------------------- | ----------------------- | ---------------------------------------------------------- |
| `pkg/config`         | `FuzzLoadConfig`        | YAML decoding + numeric clamp / env-var post-processing.   |
| `pkg/planio`         | `FuzzImportYAML`        | Plan import, YAML format.                                 |
| `pkg/planio`         | `FuzzImportJSON`        | Plan import, JSON format.                                 |
| `pkg/planio`         | `FuzzImportTOML`        | Plan import, TOML format.                                 |
| `pkg/state`          | `FuzzMigrateLegacyJSON` | Legacy `state.json` → SQLite `state.db` migration path.   |
| `pkg/pm`             | `FuzzParseDeadline`     | Relative (`2h`, `3d`, `1w`) / RFC3339 / date-only parser. |
| `pkg/configvalidate` | `FuzzValidate`          | JSON-schema-style config validator (`Run`).                |
| `pkg/hubdoctor`      | `FuzzRedirectVerdictMatchesStartup` | `ui.oidc.redirect_url`: `cloop hub doctor` says the hub will not start exactly when `oidcauth.New` refuses it. |
| `pkg/ui`             | `FuzzOIDCCallbackRoutes` | Every redirect URL `oidcauth.New` accepts registers in the real route table and routes the browser's return to the callback. |
| `pkg/exposure`       | `FuzzDecideNeverOpensAnOpenHub` | `--listen` / `ui.listen`: a hub without sign-in or the acknowledgement binds a loopback IP literal or is refused, and every accepted address is a well-formed `host:port`. |
| `pkg/executor/resultframe` | `FuzzScanner` | The project result frame a Kubernetes Pod prints into its own log: on any input and any chunking the scanner neither panics nor holds more than one line, decides the same way however the stream was cut, and lets no frame line into the transcript. |
| `pkg/executor/resultframe` | `FuzzRoundTrip` | Every payload `resultframe.Write` accepts comes back byte for byte through any chunking, past transcript around it. |
| `pkg/executor/gitcreds` | `FuzzNoCredentialLeavesItsGrantsHost` | Over (origin URL, grant host, allowlist pattern): a workspace credential is leased only for an origin on its grant's own forge host, is bound to that host, and scopes its header there. |
| `pkg/forgehost` | `FuzzCanonical` | The one host comparison every credential path uses: canonical forms are stable, `Equal` agrees with them, and nothing equal to `github.com` is a suffix, prefix or look-alike of it. |
| `pkg/requirements` | `FuzzParseSpecFile` | `.cloop/requirements.yaml`, which the hub parses as a project's executor sent it: any input either reads as requirements within the database's bounds (which then export and read back) or is refused with line-numbered problems, and never causes a panic. |
| `pkg/requirements` | `FuzzSpecFileRoundTrip` | Every requirement the database can hold comes back from an exported spec file exactly as it went in. |

### Adding a new fuzz target

1. Create `pkg/<pkg>/<name>_fuzz_test.go`. Any `_test.go` file works, but the
   `_fuzz_test.go` suffix makes the purpose clear.
2. Implement `func FuzzXxx(f *testing.F)`. Seed it with a small corpus of
   real-world fixtures plus pathological inputs (empty bytes, BOMs, multibyte
   boundaries, deeply nested structures, garbage).
3. Inside `f.Fuzz(func(t *testing.T, ...))`, exercise the parser. The fuzz
   function must return cleanly. A parse error is fine, but a panic, or a
   `t.Fatal` on harmless but malformed input, is a real failure.
4. Add the target to `FUZZ_TARGETS` in the `Makefile`, as
   `./pkg/<pkg>/:FuzzXxx`. That list is the only place where the targets are
   listed. CI runs `make fuzz`, so the next push runs the new target with no
   other change.

### When a fuzz run finds a crash

Go writes the crashing input to `pkg/<pkg>/testdata/fuzz/FuzzXxx/<hash>`.
Every later `go test` run uses that file as a regression seed, so when you fix
the bug and commit the file, you get a permanent regression test.

```bash
# Reproduce locally:
/usr/local/go/bin/go test -run=FuzzXxx/<hash> ./pkg/<pkg>/
```

## Goroutine-leak detection

Important long-lived subsystems have a package-local
`*_goroutine_leak_test.go` file that catches leaked background goroutines
before they reach production. The top of
[`pkg/statedb/goroutine_leak_test.go`](pkg/statedb/goroutine_leak_test.go)
documents the pattern in detail, so read it before you add a new one. It is
the most complete of the nine, because it also explains how to choose the
slack threshold when the subsystem under test keeps background goroutines of
its own.

cloop doesn't use `go.uber.org/goleak`. Instead, each test has three parts:

1. `const goroutineLeakSlack = 10` (or higher for SQLite-backed packages). It
   absorbs the coming and going of the runtime's, scheduler's and drivers'
   background goroutines, while staying well below any real per-cycle leak at
   the chosen N.
2. `settleGoroutineCount() int`: run the GC, yield, sleep briefly, run the GC
   again, then read `runtime.NumGoroutine`. The sleep is set per package:
   50-100ms covers most teardown paths, and SQLite needs ~200ms for its
   finalisers to settle.
3. `TestXxx_NoGoroutineLeak`: warm-up call → baseline → loop N happy-path
   lifecycles → re-sample → assert delta ≤ slack.

Why not `goleak`? Some dependencies keep background goroutines that goleak's
default ignore list doesn't cover: `modernc.org/sqlite` does, and so did the
WebSocket library (one per open connection) until cloop moved from
`nhooyr.io/websocket` to `github.com/coder/websocket`. Each package would need
its own `IgnoreCurrent`/`IgnoreTopFunction` list, updated with every
dependency bump. Comparing the total count with a baseline works with those
drivers and needs no list to maintain, because a real leak grows with N and
background noise doesn't.

Packages that currently have a leak test: `pkg/orchestrator`, `pkg/ui`,
`pkg/statedb`, `pkg/filewatch`, `pkg/compare`, `pkg/consensus`, `pkg/bench`,
`pkg/logtail`, `pkg/executor/kubernetes`. When you add a long-lived
goroutine to a subsystem, add a matching test in that package. Copy the
structure of the reference file and document the goroutine you're guarding.

## Static checks

Three CI jobs check the source code itself instead of its behaviour. Each runs
in parallel with the tests, and you can reproduce each one locally with a
single command:

| CI job | What it gates | Locally |
| --- | --- | --- |
| **Static analysis** | `go vet`; `gofmt`; every release platform compiles; `tests/arch` (unreferenced packages, retired modules and the other structural rules there); `go mod tidy` leaves `go.mod` and `go.sum` alone | `go vet ./...`, `go test ./tests/arch/`, and `gofmt -l $(git ls-files '*.go')`, which must print nothing |
| **Vulnerability scan** | `govulncheck`: a known-vulnerable symbol this code can reach | `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` |
| **Lint** | `golangci-lint` with staticcheck's SA checks, `unused` and `ineffassign`, tests included | `make lint` |

### Lint

```bash
make lint                                         # what CI's Lint job runs
make lint LINT_ARGS=--new-from-rev=origin/main    # only what this branch adds
```

`make lint` installs the golangci-lint version pinned in the Makefile
(`GOLANGCI_LINT_VERSION`) into `dist/tools/` and runs it with
[`.golangci.yml`](.golangci.yml). CI runs the same two make targets, so a
finding there reproduces locally. The first run type-checks the module and its
dependencies, which takes a minute or two. golangci-lint caches its analysis,
so later runs take seconds.

Every enabled check must report zero findings for the job to pass, and each
reports a class of bug, not a style preference: staticcheck's **SA** checks
(misuse of the standard library, concurrency mistakes, code that can't do what
it says, deprecated APIs), **unused** and **ineffassign**. On its first run,
the gate found a command that resolved its model from the configuration and
then ignored it, a documented `CLOOP_SOAK_KEEP` that nothing read, and TLS
configs setting a field Go has ignored since 1.18. The style families (ST, QF,
S1) stay off, and so does **errcheck**. It reports over 4,500 unchecked
errors, most of them intentional (a best-effort `Close`, a write to a client
that has gone away), which is too many for a gate to start from. It needs a
baseline of its own first.

Fix a finding instead of silencing it. If a finding is wrong (a test that
writes to a nil map because it needs a collector to panic, or a nil `Context`
that is the input under test), silence it on that line. Name the linter, and
put the reason after a second `//`:

```go
m["boom"] = 1 //nolint:staticcheck // SA5000 is the point: assignment to entry in nil map
```

Never write `//nolint:staticcheck — reason`. golangci-lint reads everything
after the colon as a comma-separated list of linter names, so that directive
names a linter called `staticcheck — reason`. golangci-lint warns about an
unknown linter and silences nothing.

To move to a newer linter, change `GOLANGCI_LINT_VERSION` in the Makefile, run
`make lint`, and fix what the new version reports in the same change.

### Retired modules

`nhooyr.io/websocket` is deprecated in favour of `github.com/coder/websocket`,
its maintained successor with the same API. `go test ./tests/arch/` fails if
the old path is imported anywhere, including tests, or named in `go.mod`
(`TestNoRetiredModules`). To retire another module, add it to `retired` in
`tests/arch/retiredmodules_test.go`.

## Unreferenced packages

A new `pkg/<feature>/` that nothing imports fails CI's **Static analysis** job:

```bash
go test ./tests/arch/
```

Nothing else catches an unreferenced package: it still builds, passes
`go vet`, and passes its own tests. `pkg/adr`, a complete 433-line feature,
sat unused like that for months. So when you add a package, wire it into a
command or a caller in the same change. When the gate fails, either wire the
package up or delete it. `tests/arch/orphan_test.go` has an `exempt` map for
packages that are meant to be unreferenced. It is empty, and an entry needs a
reason that a reader can check.

## Guarantees are requirements

cloop's documentation makes promises that a test can check: the hub starts no
process on its own host except through an executor, every mutating route
enforces RBAC through `authz.Enforced`, a state-changing request needs the
hub's origin, the hub's environment never reaches a sandbox, migrations stay
additive, the audit catalog has no drift, the dashboard's first paint stays
within its byte budget (`eagerWireBudgetBytes` in
`pkg/ui/assetbudget_test.go`, so a new tab or panel goes into a deferred
script), and every feature or fix has a changelog entry. Each of these is a
requirement in [`.cloop/requirements.yaml`](.cloop/requirements.yaml), cloop's
specification of itself, and points at the test that proves it. The format is
described in
[Requirements as code](docs/guides/requirements.md#requirements-as-code). CI's
**cloop's own requirements hold** job checks every approved requirement on
every push:

```bash
make requirements-check
```

builds cloop from the checkout, lints the spec, and runs
`cloop requirements check --file .cloop/requirements.yaml --json`. That runs
each requirement's tests in turn, reports what each found on stderr as it
goes, and exits 1 if a requirement doesn't hold. Like the unit suite, it runs
hermetically: in a fresh `HOME`, with every `CLOOP_*` variable unset along
with everything else `hometest.Isolate` clears (`scripts/requirements-check.sh`
says what and why), so an agent's inherited `CLOOP_SECRET_KEY` has no effect.
Like `make changelog-check`, it needs the full history and the tags. When the
job fails, its last step annotates each failing requirement by its `R-<n>` on
the requirement's line in the spec, and `scripts/ci-why.sh <sha>` reads the
annotations back.

A new guarantee needs a requirement and a test, added in the change that makes
the promise:

1. Write the test, and keep it narrow: the functions that show the guarantee
   holds and, for a structural check, a control case that plants a violation
   and expects the check to catch it.
2. Add a requirement with the next number (an id is never reused, even after
   its requirement is deleted), `status: approved`, a one-sentence title
   ("… shall …") and details that say what holds and which page promises it.
   Its test is a single command, either:
   - `go test ./<dir> -run '^(TestA|TestB)$'`, with package directories and
     the test names anchored. A pattern that matches no test passes, so
     `go test ./tests/docs` fails on a name that isn't a test in a directory
     the command tests (`TestRequirementsCiteOnlyRealTests`). That way a
     renamed test fails there instead of turning its requirement into one that
     always holds; or
   - `make <target>`.

   If the test loads the module or compiles `pkg/ui`, give it `timeout: 20m`.
3. Check it the way CI will: `cloop requirements validate` and
   `cloop requirements lint --file .cloop/requirements.yaml --strict` (the job
   fails on lint errors, such as an approved `must` with no test), then
   `make requirements-check`.
4. Prove it where a proof can tell you something.
   `cloop requirements prove R-<n>` runs its tests on the commit before the
   test's implementation and on yours, and reports whether they fail without
   the change and pass with it
   ([Red-green proofs](docs/guides/requirements.md#red-green-proofs)). The
   proof is stored with the project's requirements on its hub, and the
   Requirements tab shows it on the requirement's card.

To change what a guarantee says, or the test that proves it, edit the spec and
get the change reviewed like code. A guarantee the project no longer makes
becomes `status: deprecated`, which keeps its id and its history. When a test
moves or is renamed, update its requirement's command to match.

## When CI is red

Reading a job's log needs admin rights on the repository. Without them,
`GET /repos/blechschmidt/cloop/actions/jobs/{id}/logs` answers 403 "Must have
admin rights to Repository". Anyone can read a job's annotations, with or
without a token, so CI writes the reason a job failed into its annotations.

Every `run:` step in `.github/workflows/ci.yml` runs under
[`scripts/ci-step.sh`](scripts/ci-step.sh), the workflow's default shell. It
runs the step's script under `bash -e`, as GitHub does for a step that names
no shell, and records its output and exit status without changing either.
When a job fails, its last step, **Say why the job failed**, passes the record
to [`scripts/ci-annotate`](scripts/ci-annotate/main.go). That reads go's
output (plain, `-v` or `-json`) and annotates each cause it finds:

| Cause | Annotation title | What it carries |
| --- | --- | --- |
| A failing test | `<package> <Test>` (the leaves of nested subtests) | Its first ~30 lines of output; it points at the last `file:line` the test logged |
| A panic or fatal error | `<package> <Test>: panic: …` | The panic and the top frames below the runtime's and the testing package's |
| A data race | `<package> <Test>: data race in <function>` | Both accesses' first frames, and the test |
| A timeout | `<package> <Test>: test timed out after …` | The tests still running, and where their goroutines were |
| A build, vet or setup failure | `<package>: build failed` (or `vet failed`, `setup failed`) | The compiler's or vet's output, pointing at the first error |
| A package that failed with no failing test | `<package>: failed outside any test` | What the package printed outside its tests |
| A failed step with no go output | `A step exited N: <its first command>` | Its last forty lines |

GitHub keeps ten error annotations per step and fifty per job, so the causes
are ranked. The first failed step's causes come first, and within a step, a
package that didn't build, crashed, hung or raced comes before a failing test.
What doesn't fit is folded into the last annotation, which lists it. The run's
summary page has every finding in full. A step that annotates its own output,
as the security suite does from its `-json` stream (`go run ./scripts/ci-annotate
FILE`), is left alone by the job's last step. Give no step a `shell:` of its
own, or its output isn't recorded. `go test ./tests/ciscripts/` checks that no
step has one, and that every job ends with the step that says why it failed.

To read why a commit's CI failed, from a machine with no token:

```bash
scripts/ci-why.sh                    # HEAD's push runs
scripts/ci-why.sh 34f170cd           # any commit; a SHA this clone lacks is looked up
scripts/ci-why.sh --job Lint HEAD    # one job's annotations, whether it passed or not
```

It prints each run's result and, for each job that didn't pass, the step it
failed at, a link to its log, and its annotations. That uses three or four of
the sixty requests an hour that GitHub allows an address without a token, and
the script tells you how many are left. Setting `GITHUB_TOKEN` lifts the
limit. You can get the same annotations from a log you have locally:

```bash
go test ./pkg/x/ 2>&1 | tee x.log
go run ./scripts/ci-annotate -summary x.md x.log    # x.md: the full report
```

## Asking the secret broker on an executor's behalf

A `secretbroker.Requester` is what a lease, an egress session or a grant query
is matched as. Build one with `secretbroker.RequesterFor(records, executorID,
scope)`, or `secretbroker.NewRequester` over the `RecordedExecutor` that
`secretbroker.LookupExecutor` returns. Never build one as a struct literal:
`go test ./tests/arch/` rejects that anywhere in production code. The
constructor takes the executor's labels from the hub's own record of it
(`executorstore.Records`), which is what a grant to `label:region=eu` is
matched against. Struct literals are how a dozen dispatch paths came to leave
the labels out, so that label grants delivered nothing. Never fill in a
`RecordedExecutor` from what a device's agent reports about itself. The gate
allows building one only in the functions listed in
`tests/arch/requester_test.go`, each with its reason.

## Opening a SQLite database

Open cloop's databases with `statedb.Open` when you want the project store and
its migrations, and with `statedb.OpenConn(path, statedb.ReadWrite)` or
`statedb.OpenConn(path, statedb.ReadOnly)` for a handle of your own. Don't use
a bare `sql.Open`, which `go test ./tests/arch/` rejects in production code.
`OpenConn` puts the connection policy in the data source name, so the driver
applies it to every connection the pool opens: `busy_timeout` before any other
statement, foreign keys, `BEGIN IMMEDIATE` for writers and `mode=ro` for
readers. A `PRAGMA busy_timeout` run with `Exec` after opening only affects
the connection that ran it. That is why taskqueue's writes failed with
`SQLITE_BUSY` as soon as the pool replaced that connection. Tests may open
databases however they like.

## Documentation site

The **Documentation site** workflow (`.github/workflows/docs.yml`) publishes
the guides under `docs/` to <https://blechschmidt.github.io/cloop/> on every
push to `main` that changes them:

```bash
make docs-serve       # live preview on http://127.0.0.1:8000
make docs-site        # the strict build CI runs: dead links and anchors fail it
make docs-freshness   # is the published site as new as main's docs?
```

Every build is stamped: `build.json` at the site root names the commit it was
built from. A deploy can stall without anything failing. On 2026-09-30 GitHub
held one deploy `waiting` on the `github-pages` environment for days, every
later deploy queued behind it, and the site served a days-old build while all
checks were green. `make docs-freshness` reads the live stamp and compares it
with main's newest commit that touches the docs (a path in `docs.yml`'s
`on.push.paths`). It fails when the site is more than six hours behind
(`DOCS_MAX_LAG_HOURS`), and lists every docs run that is waiting or pending,
and since when. The **Documentation site freshness**
workflow runs it every three hours. It isn't part of CI, because no commit can
fix a hold on GitHub's side.

When it fails because a deploy is held, cancel the run it names in the Actions
tab (**Cancel workflow**). The newest pending deploy then publishes. If none
is pending, start the Documentation site workflow by hand (**Run workflow** on
`main`).

## Committing

After every change, run:

```bash
/usr/local/go/bin/go build -o cloop . && /usr/local/go/bin/go vet ./... && make lint
```

Commit messages follow conventional-commit style (`feat(...)`, `fix(...)`,
`test(...)`, `docs(...)`).

A `feat`, `fix` or `perf` commit changes what users run, so it needs an entry
in `CHANGELOG.md` under `## [Unreleased]` that names its task, `(Task N)`, as
its subject does. A commit that names no task must add its own line. Put a
security fix under **Security**: the *Released installer* workflow fails once a
security fix has waited 14 days for a release. CI's **Every feature and fix
has a changelog entry** job checks every commit since the latest release tag.
Run it locally with `make changelog-check`. `docs`, `test`, `ci` and `release`
commits are exempt.

Don't bypass pre-commit hooks (`--no-verify` is forbidden). Fix the underlying
issue instead.

## Cutting a release

A release is a tag on a commit of main whose CI is green, including the
*Upgrade rehearsal* job. The steps, in order:

1. **The commit that will be tagged** moves `CHANGELOG.md`'s `[Unreleased]`
   entries under `## [x.y.z] - YYYY-MM-DD` with an introduction, and adds the
   release to `publishedReleases` in
   [`pkg/version/releases.go`](pkg/version/releases.go): its tag, the executor
   protocol its binaries speak (`ProtocolVersion` in
   `pkg/executor/remote/proto.go`) and its sequence. The sequence is that
   commit's own `git rev-list --count --first-parent HEAD`, one more than
   before the commit. Bump the Helm chart's version if its templates changed
   since the last release.
2. **Push it and wait for CI** to pass every job on that commit, including the
   *Upgrade rehearsal* job. It rehearses a rolling upgrade from the latest
   published release to that commit, with both real binaries on one database
   and one cluster
   ([Rehearsing a rolling upgrade](docs/operations/runbook.md#rehearsing-a-rolling-upgrade)).
   A failed job means a new commit, and so a new sequence, before any tag.
   Don't cut a release while the rehearsal fails: what it found is what every
   hub on the latest release will run into when it upgrades.
3. **Tag the commit** with an annotated tag and push the tag. Never move a
   pushed tag, because the Go checksum database is append-only. Cut the next
   version instead.
4. **The Release workflow** builds every platform, checks that the binary
   reports the tag and its sequence, and rehearses the upgrade once more
   before it signs or uploads anything, this time from the previous published
   release to the binary it is about to publish. If that rehearsal fails,
   nothing is published. Fix the problem on main and cut the next version.
5. **The Released installer workflow**, which the release triggers, must pass
   both jobs.
