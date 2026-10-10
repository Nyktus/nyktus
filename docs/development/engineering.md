# Engineering Guidelines

These guidelines describe how code in Nyktus is written. They complement the [secure coding guidelines](secure-coding.md) and the [testing guidelines](testing.md).

## Principles

- **Simple over clever.** Choose the most direct solution that is correct. Introduce an abstraction when a second real use exists, not in anticipation of one.
- **Explicit over implicit.** No hidden control flow, no global mutable state, no `init()` side effects.
- **Delete rather than disable.** Unused code, feature flags for hypothetical needs and commented-out code are removed. Version control remembers.
- **One way to do a thing.** When a helper exists for a concern (error responses, outbound HTTP, pagination), use it. Do not add a second one.
- **Fail fast at startup.** Invalid configuration, unrenderable templates and an inconsistent catalog stop the process before it accepts traffic.

## Go

### Formatting and static analysis

Code is formatted with `gofmt` and checked by the linters configured in the repository. A lint finding is fixed, not suppressed. Where a suppression is unavoidable, it names the linter and gives a reason on the same line.

### Package structure

- Packages are organized by domain (honeytokens, honeypots, scenarios, incidents, alerting, catalog), not by technical layer.
- Package boundaries that carry security meaning are enforced by the linter, for example: the sensor never imports server packages, and trigger code never imports inventory or alerting packages.
- Everything that is not intended for import by other modules lives under `internal/`.
- Interfaces are declared by the consumer, kept small, and only introduced where there is more than one implementation or a test needs a seam.
- Package names are short, lowercase and singular. Avoid `util`, `common` and `helpers`.

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

### Configuration

Configuration is read from the environment once at startup, parsed into a typed struct and validated in full. Components receive their configuration explicitly. No package reads environment variables on its own.

- Variables use the prefix `NYKTUS_`.
- Every secret can alternatively be read from a file through the same name with the suffix `_FILE`, so that container secrets never appear in the process environment.
- Only the configuration of the enabled roles is required. A process running only the `trigger` role does not need mail or identity provider settings.

## HTTP API

- Request and response types are explicit structs. Database models are never serialized directly.
- Errors use one response envelope. `5xx` responses go through the shared helper, which logs the error with request context and returns a generic message.
- API routes live under `/api/v1`. Health endpoints for orchestrators live at the root.
- The OpenAPI specification in `api/openapi.yaml` is the contract. It is written by hand; there is no generated server code, because it would bypass the access declarations of the router. A change to an endpoint updates the specification in the same pull request.
- Every operation in the specification declares its access in `x-access`: `public`, `authenticated` or a permission in the form `resource:action`. Operations that are not public document `401`, and operations that require a permission also document `403`. A test compares method, path and access of every operation with the router, in both directions. A `GET` route also answers `HEAD` with the same access, as `http.ServeMux` does; `HEAD` is not documented separately.
- Routes are registered with `httpx.Public`, `httpx.Authenticated` or `httpx.Require(permission)`. Routes that are not public pass through the authorizer before the handler runs, so permission checks happen in one place. The authorizer only decides; the router writes the `401` (with a `WWW-Authenticate` challenge), `403` or `500` response.

## Logging

Logging uses `log/slog` with JSON output. Request-scoped code uses the `...Context` variants so that request ID and actor are attached automatically.

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
- Grants for the per-role database users live in migrations, next to the tables they cover.
- `GRANT` and `REVOKE` only warn when the executing role lacks the privilege to change a grant. A migration that changes privileges therefore verifies the result and raises an exception if it does not hold.
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
