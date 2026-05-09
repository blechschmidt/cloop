.PHONY: build test test-unit test-e2e test-e2e-update fuzz clean

BINARY := cloop
GO := /usr/local/go/bin/go

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

## clean: remove build artifacts and coverage reports
clean:
	rm -f $(BINARY) coverage.out
