.PHONY: build test test-unit test-e2e test-e2e-update clean

BINARY := cloop
GO := /usr/local/go/bin/go

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

## clean: remove build artifacts and coverage reports
clean:
	rm -f $(BINARY) coverage.out
