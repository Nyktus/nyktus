# Tool versions are pinned here and used by CI as well. The tools run through
# "go run", so they never become dependencies in go.mod.
GOLANGCI_LINT_VERSION := v2.14.0
GOVULNCHECK_VERSION   := v1.8.0
GITLEAKS_VERSION      := v8.30.1

GOLANGCI_LINT := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
GOVULNCHECK   := go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
GITLEAKS      := go run github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION)

# The sensor is a Go module of its own (sensor/), so that the server never
# becomes one of its dependencies and its go.mod stays short. There is no
# go.work: every target that checks Go code runs for both modules.
SENSOR_DIR := sensor

# Disposable PostgreSQL for database tests, on a port that does not collide with a
# local installation.
TEST_DB_CONTAINER := nyktus-test-db
TEST_DB_IMAGE     := postgres:16-alpine
TEST_DB_PORT      := 55432
TEST_DB_URL       := postgres://postgres:postgres@localhost:$(TEST_DB_PORT)/postgres?sslmode=disable

# The environment of the tests that need the database; CI sets the same.
TEST_DB_ENV := NYKTUS_TEST_DATABASE_URL='$(TEST_DB_URL)' NYKTUS_REQUIRE_DB_TESTS=1

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-z-]+:.*## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# The web console is a Node.js project of its own (web/). Its build is embedded
# into the server binary, so "build" runs it first; "go build" and "go test" work
# without it and serve no pages.
WEB_DIR := web

$(WEB_DIR)/node_modules: $(WEB_DIR)/package-lock.json
	cd $(WEB_DIR) && npm ci --ignore-scripts
	touch $@

.PHONY: web-build
web-build: $(WEB_DIR)/node_modules ## Build the web console into web/dist
	rm -rf $(WEB_DIR)/dist/*
	cd $(WEB_DIR) && npm run build

.PHONY: web-lint
web-lint: $(WEB_DIR)/node_modules ## Type-check the web console
	cd $(WEB_DIR) && npm run lint

.PHONY: web-test
web-test: $(WEB_DIR)/node_modules ## Run the tests of the web console
	cd $(WEB_DIR) && npm test

.PHONY: web-audit
web-audit: $(WEB_DIR)/node_modules ## Report known vulnerabilities in the packages of the web console
	cd $(WEB_DIR) && npm audit --audit-level=high

.PHONY: build
build: web-build ## Build the web console, then the nyktus and nyktus-sensor binaries into bin/
	go build -trimpath -o bin/nyktus ./cmd/nyktus
	cd $(SENSOR_DIR) && go build -trimpath -o ../bin/nyktus-sensor ./cmd/nyktus-sensor

.PHONY: test
test: ## Run unit tests; database tests are skipped
	go test -race -count=1 ./...
	cd $(SENSOR_DIR) && go test -race -count=1 ./...

# The race detector slows the suite down by a factor of four. This target is for
# the loop while you work; "test-db" runs in CI and before every push.
.PHONY: test-fast
test-fast: ## Run all tests including database tests without the race detector (needs db-up)
	$(TEST_DB_ENV) go test -count=1 ./...
	cd $(SENSOR_DIR) && go test -count=1 ./...

.PHONY: test-db
test-db: ## Run all tests including database tests (needs db-up)
	$(TEST_DB_ENV) go test -race -count=1 ./...
	cd $(SENSOR_DIR) && go test -race -count=1 ./...

# Packages and their database tests run in parallel, one per CPU each, and every
# test holds its own connections, so the default of 100 connections runs out on
# machines with many cores. The database is disposable, so it does not wait for
# the disk: a crash loses it, and the next "make db-up" starts a new one.
.PHONY: db-up
db-up: ## Start the disposable test database
	docker run --detach --rm --name $(TEST_DB_CONTAINER) \
		--env POSTGRES_PASSWORD=postgres \
		--publish 127.0.0.1:$(TEST_DB_PORT):5432 \
		$(TEST_DB_IMAGE) \
		-c max_connections=400 \
		-c fsync=off \
		-c synchronous_commit=off \
		-c full_page_writes=off
	@until docker exec $(TEST_DB_CONTAINER) pg_isready --username postgres --quiet; do sleep 1; done

.PHONY: db-down
db-down: ## Stop and remove the test database
	docker stop $(TEST_DB_CONTAINER)

# The development environment: PostgreSQL and every server role, built from the
# working tree. The encryption key is generated once and kept in a file that Git
# ignores.
DEV_COMPOSE := docker compose --file deploy/dev/compose.yaml

deploy/dev/.env:
	umask 077 && echo "NYKTUS_ENCRYPTION_KEYS=1:$$(openssl rand -base64 32)" > $@

.PHONY: dev-up
dev-up: deploy/dev/.env ## Build and start the development environment (console on http://localhost:8080)
	$(DEV_COMPOSE) up --build --detach --wait
	@echo "Setup URL of the first administrator, if none exists yet:"
	@$(DEV_COMPOSE) logs console | grep -o 'http://localhost:8080/setup#token=[^ ]*' | tail -1 || true

.PHONY: dev-down
dev-down: ## Stop the development environment and keep its data
	$(DEV_COMPOSE) down

.PHONY: dev-reset
dev-reset: ## Stop the development environment and delete its data
	$(DEV_COMPOSE) down --volumes

.PHONY: lint
lint: ## Run linters and formatting checks
	$(GOLANGCI_LINT) run
	cd $(SENSOR_DIR) && $(GOLANGCI_LINT) run

.PHONY: fmt
fmt: ## Format the code
	$(GOLANGCI_LINT) fmt
	cd $(SENSOR_DIR) && $(GOLANGCI_LINT) fmt

.PHONY: vuln
vuln: ## Report known vulnerabilities in reachable code
	$(GOVULNCHECK) ./...
	cd $(SENSOR_DIR) && $(GOVULNCHECK) ./...

.PHONY: secrets
secrets: ## Scan the git history for committed secrets
	$(GITLEAKS) git --redact --no-banner

.PHONY: tidy
tidy: ## Verify that go.mod and go.sum are tidy
	go mod tidy -diff
	cd $(SENSOR_DIR) && go mod tidy -diff

.PHONY: check
check: lint test vuln tidy web-lint web-test web-audit ## Run all checks that do not need a database
