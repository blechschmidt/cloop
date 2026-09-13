.PHONY: build test test-unit test-e2e test-e2e-update e2e-stack fuzz bench clean \
        docs-check docs-stage docs-site docs-serve release-dist

BINARY := cloop
GO := /usr/local/go/bin/go

# Documentation site. The toolchain is pure Python and pinned in
# website/requirements.txt; no Go is involved, and the venv lives under dist/
# so `make clean` and .gitignore only need to know about one directory.
DIST := dist
DOCS_VENV := $(DIST)/docs-venv
DOCS_MKDOCS := $(DOCS_VENV)/bin/mkdocs
DOCS_PORT ?= 8000

# Per-target fuzz time. 30s is enough to catch shallow panics on every parser
# without making the target painful to run locally; CI may set a longer budget.
FUZZTIME ?= 30s

## build: compile the cloop binary
build:
	$(GO) build -o $(BINARY) .

## test: run all tests (unit + e2e)
test: test-unit test-e2e

## test-unit: run unit tests with race detector and coverage
test-unit:
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic \
		$(shell $(GO) list ./... | grep -v 'tests/e2e')

## test-e2e: run end-to-end integration tests against the built binary
test-e2e: build
	$(GO) test -v -timeout 120s ./tests/e2e/

## test-e2e-update: regenerate golden files from current binary output
test-e2e-update: build
	$(GO) test -v -timeout 120s ./tests/e2e/ -update

## e2e-stack: bring up the docker-compose evaluation stack, run one real task
##            through a remote executor, and tear it down.
##
## This is the test the unit suite cannot be: it boots the hub, the identity
## provider, the TLS proxy and an executor as separate containers, and proves
## the thing they exist for end to end — the readiness gate goes red with
## nothing to dispatch to, an executor enrolls itself with a bootstrap token,
## and a task runs on it against a source tree it fetched over https.
##
## Needs docker with the compose plugin. KEEP=1 leaves the stack up for
## poking at afterwards.
e2e-stack:
	./deploy/eval/e2e.sh

## fuzz: run each fuzz target for $(FUZZTIME) (default 30s) — see CONTRIBUTING.md
##       targets: pkg/config, pkg/planio (yaml/json/toml), pkg/state, pkg/pm,
##                pkg/configvalidate. None should panic on hostile input.
fuzz:
	$(GO) test -run=^$$ -fuzz=FuzzLoadConfig      -fuzztime=$(FUZZTIME) ./pkg/config/
	$(GO) test -run=^$$ -fuzz=FuzzImportYAML      -fuzztime=$(FUZZTIME) ./pkg/planio/
	$(GO) test -run=^$$ -fuzz=FuzzImportJSON      -fuzztime=$(FUZZTIME) ./pkg/planio/
	$(GO) test -run=^$$ -fuzz=FuzzImportTOML      -fuzztime=$(FUZZTIME) ./pkg/planio/
	$(GO) test -run=^$$ -fuzz=FuzzMigrateLegacyJSON -fuzztime=$(FUZZTIME) ./pkg/state/
	$(GO) test -run=^$$ -fuzz=FuzzParseDeadline   -fuzztime=$(FUZZTIME) ./pkg/pm/
	$(GO) test -run=^$$ -fuzz=FuzzValidate        -fuzztime=$(FUZZTIME) ./pkg/configvalidate/

## bench: benchmark the hub control-plane hot paths
##
## Covers the four things whose cost scales with something no operator sets
## deliberately: the wire snapshot and WebSocket fanout (pkg/ui), the
## hash-chained audit trail and plan persistence (pkg/statedb), and per-identity
## quota admission (pkg/quota).
##
## Deliberately not run under -race: the detector inflates every number by
## roughly an order of magnitude and unevenly, so a race-instrumented
## benchmark measures the instrumentation. Correctness under concurrency is
## the unit suite's job (see TestConcurrentAdmissionNeverOverAdmits).
##
## BENCHTIME tunes the per-benchmark budget. The default is what CI uses —
## enough to keep them compiling and to catch an order-of-magnitude blowup,
## not enough for a number worth quoting. For a real measurement, run with a
## time budget on an idle machine:
##
##     make bench BENCHTIME=2s BENCH=BenchmarkBroadcastStateDiff
##
## BENCH selects a subset by regexp (default: all).
BENCHTIME ?= 10x
BENCH ?= .
bench:
	$(GO) test -run='^$$' -bench='$(BENCH)' -benchtime=$(BENCHTIME) -benchmem \
		-timeout 30m ./pkg/ui/ ./pkg/statedb/ ./pkg/quota/

# ---------------------------------------------------------------------------
# Documentation site (https://blechschmidt.github.io/cloop/)
# ---------------------------------------------------------------------------
# The site is not a second copy of the docs: scripts/build-docs.py stages this
# repository's own Markdown, mirroring the repository layout so the relative
# links between pages survive, and derives the navigation from docs/README.md.
# CI runs these same targets, so a local build and the published site cannot
# drift.

$(DOCS_VENV): website/requirements.txt
	@echo "==> creating the documentation venv from website/requirements.txt"
	@python3 -m venv $(DOCS_VENV)
	@$(DOCS_VENV)/bin/pip install --quiet --upgrade pip
	@$(DOCS_VENV)/bin/pip install --quiet -r website/requirements.txt
	@touch $(DOCS_VENV)

## docs-check: structural check — every page indexed, every relative link resolves
docs-check:
	@./scripts/check-docs.sh

## docs-stage: assemble dist/docs-src and dist/mkdocs.yml from docs/ and README.md
docs-stage:
	@python3 scripts/build-docs.py

## docs-site: build the documentation site into dist/docs-site (strict)
docs-site: $(DOCS_VENV) docs-check docs-stage
	@echo "==> mkdocs build --strict"
	@$(DOCS_MKDOCS) build --strict -f $(DIST)/mkdocs.yml
	@echo "==> site built: $(DIST)/docs-site/index.html"

## docs-serve: live-preview the documentation site (http://127.0.0.1:$(DOCS_PORT))
docs-serve: $(DOCS_VENV) docs-stage
	@echo "==> mkdocs serve on http://127.0.0.1:$(DOCS_PORT)  (re-run to pick up docs/ edits)"
	@$(DOCS_MKDOCS) serve --strict -f $(DIST)/mkdocs.yml -a 127.0.0.1:$(DOCS_PORT)

## release-dist: build the release artifacts for VERSION into dist/release
##
## The same script the Release workflow runs, so a release can be reproduced
## and inspected locally before a tag is pushed — which is the only way to
## find out that a platform stopped compiling before users do.
##
##     make release-dist VERSION=v0.0.1
##
## Produces one cloop_<version>_<os>_<arch>.tar.gz per platform plus a
## checksums.txt, in the layout `cloop upgrade` expects to find on the release.
## Tarballs are reproducible: the same commit and version yield identical
## bytes, so these checksums can be compared against the published ones.
release-dist:
	@test -n "$(VERSION)" || { echo "usage: make release-dist VERSION=v0.0.1"; exit 2; }
	@GO=$(GO) ./scripts/build-release.sh $(VERSION) $(DIST)/release

## clean: remove build artifacts, coverage reports and the documentation site
clean:
	rm -f $(BINARY) coverage.out
	rm -rf $(DIST)
