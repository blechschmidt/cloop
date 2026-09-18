.PHONY: build test test-unit test-e2e test-e2e-update e2e-stack fuzz bench clean \
        docs-api docs-audit docs-check docs-stage docs-site docs-serve release-dist \
        terraform-test

BINARY := cloop

# The Go toolchain, taken from PATH rather than hardcoded to an absolute path.
#
# It was /usr/local/go/bin/go, which is where this project's toolchain lives on
# a developer box and nowhere on a GitHub runner: setup-go installs into the
# tool cache and puts that on PATH. So `make bench` died with "no such file or
# directory" before running a single benchmark, and the Benchmarks job had
# never once passed — failing in 0.0s, which looks nothing like the benchmark
# regression the job exists to catch. The docs jobs kept passing throughout,
# because their targets are pure Python and never expand $(GO).
#
# PATH is also the more correct source on CI even where an absolute path would
# resolve: it yields the toolchain setup-go pinned from go.mod, whereas
# /usr/local/go/bin/go would be whatever the runner image ships, quietly
# bypassing the pin that ci.yml's vulnerability scan asserts is in effect.
#
# Override when the toolchain is not on PATH:  make build GO=/usr/local/go/bin/go
GO ?= go

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

## icons: re-rasterise the favicon set from pkg/ui/assets/icon.svg
##
## Only needed after editing icon.svg — the rendered PNGs and the ICO are
## committed, because `go build` must work without an SVG toolchain and
## //go:embed cannot run a converter. TestIconsAreInSyncWithTheirSource fails
## if the mark is edited without running this.
##
## Requires librsvg2-bin and python3-pil.
icons:
	@./scripts/build-icons.sh

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
##
## This list is the single source of truth. CI's Parser fuzzing job runs this
## same target with a shorter budget rather than repeating the targets in YAML,
## so a target added here is gated there without a second edit — which is what
## CONTRIBUTING.md has always told contributors to expect, and what was not
## previously true: these seven were defined, documented, and run by nothing.
FUZZ_TARGETS := \
	./pkg/config/:FuzzLoadConfig \
	./pkg/planio/:FuzzImportYAML \
	./pkg/planio/:FuzzImportJSON \
	./pkg/planio/:FuzzImportTOML \
	./pkg/state/:FuzzMigrateLegacyJSON \
	./pkg/pm/:FuzzParseDeadline \
	./pkg/configvalidate/:FuzzValidate

## Through scripts/fuzz-ci.sh rather than a `go test -fuzz` per line, because
## two of its distinctions matter locally as much as in CI: Go intermittently
## reports a clean -fuzztime expiry as a failure (golang/go#72104), and a
## committed regression seed is not a fresh finding. Both are in the script's
## header.
fuzz:
	@GO=$(GO) FUZZTIME=$(FUZZTIME) ./scripts/fuzz-ci.sh $(FUZZ_TARGETS)

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

## docs-api: regenerate docs/reference/http-api.md from the route tables
#
# The page is generated rather than written, so this is the only correct way to
# change it. `go test ./tests/docs` fails when the checked-in copy no longer
# matches the routes pkg/ui and pkg/apiserver register.
docs-api:
	@$(GO) test ./tests/docs -run TestHTTPAPIReference -update -count=1
	@echo "==> regenerated docs/reference/http-api.md"

## docs-audit: regenerate docs/reference/audit-events.md from the action registry
#
# Same arrangement as docs-api, for the same reason: the page is rendered from
# pkg/auditaction rather than written, so this is the only correct way to change
# it. `go test ./tests/docs` fails when the checked-in copy stops matching the
# registry, and `go test ./tests/arch` fails when an emission site names an
# action the registry does not have.
docs-audit:
	@$(GO) test ./tests/docs -run TestAuditEventsReference -update-audit -count=1
	@echo "==> regenerated docs/reference/audit-events.md"

## docs-check: structural check — every page indexed, every relative link resolves
docs-check:
	@./scripts/check-docs.sh

## terraform-test: fmt, validate and unit-test the deployment Terraform modules
##
## The modules provision an identity provider, not cloop, so `go test` cannot
## see them at all — and a broken one fails at `terraform apply` on an
## operator's tenant, which is the worst place to find out. `terraform test`
## mocks the provider, so this needs no Azure credentials and no network beyond
## the provider download.
##
## It does not replace tests/docs/terraform_azure_test.go: that gates the
## module against *cloop* (the callback route, the role ladder, the config
## keys), which Terraform cannot check and Go can. This gates the module
## against itself.
TF ?= terraform
TF_MODULES := deploy/terraform/azure-entra-id

terraform-test:
	@command -v $(TF) >/dev/null 2>&1 || { \
	  echo "==> $(TF) not installed — skipping (CI gates this; see .github/workflows/ci.yml)"; \
	  exit 0; \
	}
	@for m in $(TF_MODULES); do \
	  echo "==> $$m: fmt"; \
	  $(TF) fmt -check -recursive -diff $$m || { \
	    echo "::error::$$m is not terraform-fmt clean — run: $(TF) fmt -recursive $$m"; exit 1; }; \
	  echo "==> $$m: init"; \
	  $(TF) -chdir=$$m init -backend=false -input=false >/dev/null || exit 1; \
	  echo "==> $$m: validate"; \
	  $(TF) -chdir=$$m validate || exit 1; \
	  for ex in $$m/examples/*/; do \
	    echo "==> $$ex: validate"; \
	    $(TF) -chdir=$$ex init -backend=false -input=false >/dev/null || exit 1; \
	    $(TF) -chdir=$$ex validate || exit 1; \
	  done; \
	  echo "==> $$m: test"; \
	  $(TF) -chdir=$$m test || exit 1; \
	done

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
