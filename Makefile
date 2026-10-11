# Tool versions are pinned here and used by CI as well. The tools run through
# "go run", so they never become dependencies in go.mod.
GOLANGCI_LINT_VERSION := v2.14.0
GOVULNCHECK_VERSION   := v1.8.0
GITLEAKS_VERSION      := v8.30.1

GOLANGCI_LINT := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
GOVULNCHECK   := go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
GITLEAKS      := go run github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION)

# Disposable PostgreSQL for database tests, on a port that does not collide with a
# local installation.
TEST_DB_CONTAINER := nyktus-test-db
TEST_DB_IMAGE     := postgres:16-alpine
TEST_DB_PORT      := 55432
TEST_DB_URL       := postgres://postgres:postgres@localhost:$(TEST_DB_PORT)/postgres?sslmode=disable

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-z-]+:.*## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build the nyktus binary into bin/
	go build -trimpath -o bin/nyktus ./cmd/nyktus

.PHONY: test
test: ## Run unit tests; database tests are skipped
	go test -race -count=1 ./...

.PHONY: test-db
test-db: ## Run all tests including database tests (needs db-up)
	NYKTUS_TEST_DATABASE_URL='$(TEST_DB_URL)' NYKTUS_REQUIRE_DB_TESTS=1 go test -race -count=1 ./...

# Packages and their database tests run in parallel, one per CPU each, and every
# test holds its own connections, so the default of 100 connections runs out on
# machines with many cores.
.PHONY: db-up
db-up: ## Start the disposable test database
	docker run --detach --rm --name $(TEST_DB_CONTAINER) \
		--env POSTGRES_PASSWORD=postgres \
		--publish 127.0.0.1:$(TEST_DB_PORT):5432 \
		$(TEST_DB_IMAGE) \
		-c max_connections=400
	@until docker exec $(TEST_DB_CONTAINER) pg_isready --username postgres --quiet; do sleep 1; done

.PHONY: db-down
db-down: ## Stop and remove the test database
	docker stop $(TEST_DB_CONTAINER)

.PHONY: lint
lint: ## Run linters and formatting checks
	$(GOLANGCI_LINT) run

.PHONY: fmt
fmt: ## Format the code
	$(GOLANGCI_LINT) fmt

.PHONY: vuln
vuln: ## Report known vulnerabilities in reachable code
	$(GOVULNCHECK) ./...

.PHONY: secrets
secrets: ## Scan the git history for committed secrets
	$(GITLEAKS) git --redact --no-banner

.PHONY: tidy
tidy: ## Verify that go.mod and go.sum are tidy
	go mod tidy -diff

.PHONY: check
check: lint test vuln tidy ## Run all checks that do not need a database
