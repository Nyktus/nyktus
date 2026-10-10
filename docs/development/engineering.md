# Engineering Guidelines

These guidelines describe how code in Nyktus is written. They complement the [secure coding guidelines](secure-coding.md) and the [testing guidelines](testing.md).

## Principles

- **Simple over clever.** Choose the most direct solution that is correct. Introduce an abstraction when a second real use exists, not in anticipation of one. Security enforcement points, such as the authorization hook of the router, are the exception: they exist before their first user, so that no feature can be added without passing through them.
- **Explicit over implicit.** No hidden control flow, no global mutable state, no `init()` side effects.
- **Delete rather than disable.** Unused code, feature flags for hypothetical needs and commented-out code are removed. Version control remembers.
- **One way to do a thing.** When a helper exists for a concern (error responses, outbound HTTP, pagination), use it. Do not add a second one.
- **Fail fast at startup.** Invalid configuration, unrenderable templates and an inconsistent catalog stop the process before it accepts traffic. Constructors reject missing required dependencies, such as a nil logger, and invalid declarations, such as a malformed route, with a panic at wiring time instead of failing the first request.

## Go

### Formatting and static analysis

Code is formatted with `gofmt` and checked by the linters configured in the repository. A lint finding is fixed, not suppressed. Where a suppression is unavoidable, it names the linter and gives a reason on the same line.

### Package structure

- Packages are organized by domain (honeytokens, honeypots, scenarios, incidents, alerting, catalog), not by technical layer.
- Package boundaries that carry security meaning are enforced by the linter, for example: the sensor never imports server packages, and trigger code never imports inventory or alerting packages.
- Everything that is not intended for import by other modules lives under `internal/`.
- Interfaces are declared by the consumer, kept small, and only introduced where there is more than one implementation or a test needs a seam.
- Package names are short, lowercase and singular. Avoid `util`, `common` and `helpers`.
- Code below the HTTP layer reads the request ID and the client address through `internal/platform/request`, never through `httpx`, so that domain packages such as the audit log do not depend on HTTP.

### Errors

- Return errors, do not panic. A panic signals a programming error, never an expected condition.
- Wrap errors with context using `%w`. The context describes the operation, for example `fmt.Errorf("load honeytoken %s: %w", id, err)`.
- Expected conditions are sentinel errors (`ErrNotFound`, `ErrConflict`) checked with `errors.Is`. Never compare error strings.
- Handle an error once: either log it or return it, not both.

### Context and concurrency

- Every function that performs I/O takes a `context.Context` as its first parameter.
- Every goroutine has an owner who can stop it and wait for it. Background loops end when their context is cancelled.
- Shared state is protected by a mutex or owned by a single goroutine. Run tests with `-race`.

### Time

Timestamps are stored and compared in UTC. Code that depends on the current time receives a clock, so tests do not depend on the wall clock.

Expiry of data in the database, such as of sessions, setup tokens and account locks, is evaluated in SQL against `clock_timestamp()`. Every console process then applies the same clock, and tests move the stored times instead of the clock.

### Configuration

Configuration is read from the environment once at startup, parsed into a typed struct and validated in full. Components receive their configuration explicitly. No package reads environment variables on its own.

- Variables use the prefix `NYKTUS_`.
- Every secret can alternatively be read from a file through the same name with the suffix `_FILE`, so that container secrets never appear in the process environment.
- Only the configuration of the enabled roles is required. A process running only the `trigger` role does not need mail or identity provider settings.

## HTTP API

- Request and response types are explicit structs. Database models are never serialized directly.
- Errors use one response envelope. `5xx` responses go through the shared helper, which logs the error with request context and returns a generic message.
- API routes live under `/api/v1`. Health endpoints for orchestrators live at the root.
- Route paths consist of literal segments and `{name}` wildcards only. The router rejects subtree patterns (trailing slash, `{name...}`), `{$}` and host patterns: `http.ServeMux` answers them with redirects before authorization runs, and they have no OpenAPI equivalent. Requests with unclean paths (`//`, `/./`, `/../`) and `CONNECT` requests receive the JSON `404` instead of the mux's redirects.
- A `GET` route also answers `HEAD` with the same access, as `http.ServeMux` does. `HEAD` is not documented separately.

### OpenAPI specification

- `api/openapi.yaml` is the contract. It is written by hand; there is no generated server code, because it would bypass the access declarations of the router. A change to an endpoint updates the specification in the same pull request. Code loads it through the `api` package, never through a relative file path.
- Every operation declares its access in `x-access`: `public`, `authenticated` or a permission in the form `resource:action`. `httpx.Permission.Valid` is the only definition of that format.
- Operations that are not public document `401` explicitly, and operations that require a permission also document `403`. Ranges such as `4XX` and `default` do not count, so that every denial is visible in the specification.
- Operations are defined inline. `$ref` path items are not supported. Specification extensions (`x-...`) are allowed on the paths object and on path items.
- A test compares method, path and access of every operation with the router, in both directions. It covers the attack surface, not response bodies; those are covered by handler tests.

### Authorization

- Routes are registered with `httpx.Public`, `httpx.Authenticated` or `httpx.Require(permission)`. Routes that are not public pass through the authorizer before the handler runs, so permission checks happen in one place.
- The authorizer only decides. It returns the request with the principal, `ErrUnauthenticated`, `ErrForbidden` or another error. The router writes the `401` (with a `WWW-Authenticate` challenge), `403` or generic `500` response, so a denied request can never go unanswered.
- Recording denied requests is the authorizer's job, because only it knows the principal. It writes requests denied with `403` to the audit log; the access log records the status of every request, including `401`.

## Logging

Logging uses `log/slog` with JSON output. Request-scoped code uses the `...Context` variants so that request ID and actor are attached automatically. Attributes that become known only after a middleware has passed the context on, such as the authenticated principal, are added with `logging.AddToScope`. The request ID middleware opens the scope, so the access log and the recover log record them as well.

| Level | Use |
|---|---|
| `Error` | An operation failed unexpectedly and the request or job could not complete. |
| `Warn` | A best-effort step failed and the flow continued, such as a notification that could not be sent. |
| `Info` | Security-relevant events and lifecycle events: started, stopped, incident opened, alert delivered. |
| `Debug` | Details of the regular flow, disabled by default. |

Messages are short, lowercase constants in the form `"<component>: <what happened>"`, for example `"migrate: applied migration"`. Everything variable, including the failed operation in error helpers, goes into attributes. Constant messages keep logs searchable and aggregatable; the linter enforces this.

## Comments

Comments are written in English and explain *why*, not *what*. Good code makes the *what* obvious.

Write a comment when:

- the reason for a decision is not visible in the code, such as a protocol constraint or a security property,
- the code deliberately deviates from the obvious approach,
- an exported identifier needs a doc comment (starting with its name, as Go convention requires).

Do not write:

- comments that restate the code,
- history: "fixed", "previously", "changed because", dates, ticket or work package identifiers. This belongs in the commit message,
- commented-out code,
- `TODO` without a link to an issue.

Every source file starts with a license header:

```go
// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later
```

## Database

- Schema changes are numbered migrations in `migrations/`, named `NNNN_description.sql` and applied by `nyktus migrate` with the database owner role. Migrations are forward-only and run in a transaction each.
- A released migration is never edited. The runner stores a checksum of every applied migration and refuses to run when one has changed.
- Grants for the per-role database users live in migrations, next to the tables they cover. They go to the group role of the server role, such as `nyktus_console`, never to a login role.
- A migration revokes all privileges on a new table or function before it grants any. Default privileges set by an operator, for example for a monitoring role, would otherwise widen the grants of a server role without notice.
- Columns that the database generates, such as identifiers and creation times, are excluded from the column-level `INSERT` and `UPDATE` grants, so an application role cannot forge them.
- Columns that record when something happened, such as the time of an audit entry, default to `clock_timestamp()`. `now()` returns the start of the transaction, so the rows of one transaction would share a time and lose their order, and a transaction that waited for a lock would record a time before the action.
- Stores run their queries on a `db.Querier`, which a connection pool and a transaction both implement. A caller combines several stores in one transaction with `pgx.BeginFunc`, for example an action and its audit entry.
- Primary keys are random UUIDs from `gen_random_uuid()`. Sequential identifiers would reveal the number of accounts or decoys and the order in which they were created.
- Constraints that a store maps to an error or that tests assert on carry explicit names, such as `users_email_key`. Stores map violations by SQLSTATE and constraint name, never by message text. Primary keys of database-generated identifiers keep the default name, because no caller can violate them.
- `GRANT` and `REVOKE` only warn when the executing role lacks the privilege to change a grant. A migration that changes privileges therefore verifies the result and raises an exception if it does not hold.
- A condition that applies only sometimes, such as the cursor of the first page, belongs in a separate statement, not in `$1 IS NULL OR ...`. pgx prepares statements, and PostgreSQL may switch to a generic plan after a few executions, which cannot use such a condition to seek into an index. A test that forces the generic plan and checks the `Index Cond` of `EXPLAIN` keeps a query that relies on an index from falling back to a scan.
- Each migration does one thing and is reviewed like code.
- Comments in the schema explain non-obvious constraints and design decisions, not column names.

## Web console

- Vue 3 with the Composition API and TypeScript in strict mode.
- Translations are typed, so a missing key is a compile error.
- No runtime dependency on external resources. Fonts, icons and images ship with the build.

## Dependencies

Prefer the standard library. A new dependency needs the justification described in the [secure coding guidelines](secure-coding.md#dependencies-and-supply-chain). Prefer well-established libraries for security-critical concerns such as OpenID Connect, cryptographic primitives and protocol parsing, over writing them yourself.

- The `toolchain` directive in `go.mod` names the minimum Go release with all known standard library fixes. Raise it when `govulncheck` reports a vulnerability fixed in a newer Go release.
- Development tools such as linters and scanners are pinned in the `Makefile` and run through `go run`. They are never added to `go.mod`, so they do not enter the dependency graph of the product.

## Documentation

- Behavior, configuration and API changes update the documentation in the same pull request.
- Architecture decisions that are not obvious from the code are recorded in `docs/development/`.

## Working on a change

- Stay within the scope of the change. Problems you notice elsewhere become an issue, unless they block the current work.
- Keep commits atomic and follow the commit conventions in [CONTRIBUTING.md](../../CONTRIBUTING.md).
