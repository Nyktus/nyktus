# Testing Guidelines

Tests are the specification of Nyktus's behavior. A change without tests is incomplete, and a security property without a test is not a property.

## Test levels

| Level | Scope | Dependencies |
|---|---|---|
| Unit | A package in isolation | None. No network, no database, no clock. |
| Handler | An HTTP handler with its router and middleware, via `net/http/httptest` | Hand-written fakes for stores and queues. |
| Store | SQL against a real PostgreSQL instance | A disposable database, enabled by an environment variable. |
| End-to-end | All processes, the reverse proxy and real sockets | The test stack. |
| Load | Throughput, latency and resource use under sustained load | The test stack. A separate program, not `go test`. |

Unit and handler tests run with a plain `go test ./...` and need no external services.

## Rules

### Every bug fix has a regression test

The test must fail without the fix. Verify this by reverting the fix locally before you submit.

### Security properties have explicit tests

Each of these properties needs its own test, named after the property:

- Trigger responses are identical for valid, unknown, disabled and failing tokens, apart from an operator-configured redirect target.
- The trigger database role cannot select from any table and resolves only single values through the lookup function.
- The server refuses database roles with privileges beyond their grants, with one case for every privilege the check covers.
- Migrations leave PUBLIC without privileges on the schema, and fail when they cannot achieve that.
- An event is never stored without its processing job.
- Login and password reset return identical status codes and bodies for existing and unknown accounts, and for accounts rejected by the local login policy.
- Health checks never record an event, open an incident or raise an alert.
- The setup endpoint accepts only the current setup token and returns `404` once an administrator exists, including after a restart.
- Generated artifacts contain no product name, attribution or metadata that identifies Nyktus.
- Every registered route declares its authentication and permission. The test enumerates the router, so a new route without a declaration fails the build.
- Denied requests are rejected before the resource is loaded.
- Read-only roles and API keys without a write scope cannot write. A demoted user's keys lose the corresponding permissions.
- Unsigned or tampered catalog packages are rejected without explicit confirmation. Archives with traversal paths or oversized entries are rejected.
- The SSRF guard blocks every reserved address range.

### Fakes, not mocking frameworks

Stores are interfaces, and tests use hand-written fakes backed by maps. Fakes can record calls when a test needs to assert on them. Generated mocks with expectation DSLs are not used: they are harder to read and couple tests to call order instead of behavior.

### Store tests run against PostgreSQL

Fakes cannot find a mismatch between a `SELECT` list and a `Scan`, a missing index or a wrong lock. Every store method has at least one test against a real database.

- `dbtest.New` creates an empty database for each test and drops it afterwards, so tests and packages run in parallel without shared state.
- Database tests run when `NYKTUS_TEST_DATABASE_URL` points to a server that allows creating databases. `make db-up` starts one, `make test-db` runs the suite against it. Without the variable the tests are skipped; CI sets `NYKTUS_REQUIRE_DB_TESTS=1`, which turns a skip into a failure.
- Constraint and permission behavior is tested with the same database roles that production uses, one per server role.

### Concurrency is tested deterministically

- Never assert on elapsed time or use `time.Sleep` to order events. Use barriers, channels or explicit clock control.
- To prove that a row lock is taken, hold the lock in one transaction and try `SELECT ... FOR UPDATE NOWAIT` from a second one. A lock inside a CTE must be tested by running the CTE body on its own, because PostgreSQL may never evaluate a CTE when another branch of the join is empty.
- Run the full suite with `-race` in CI.

### Drift between curated data and code is tested

When data is maintained in two places, for example technique identifiers in the catalog and the bundled ATT&CK reference list, a test asserts that both agree. Generated files, such as the published catalog index, are compared against golden files that can be regenerated with an explicit flag.

### End-to-end tests

- A test that passes on its own proves little. Verify new end-to-end tests in a full suite run, where shared state such as rate-limit buckets and lockout counters becomes visible.
- Measure API coverage by operation (method and path), not by path.
- Contract tests against the OpenAPI specification only prove that documented fields are correct. Schemas must set `additionalProperties: false` for the test to catch undocumented fields.
- Rate-limit assertions account for the time the test took: compare against `burst + rate × elapsed`, not a fixed burst.

## Conventions

- Test names describe behavior: `TestLogin_LockedAccountWithWrongPassword_ReturnsGeneric401`.
- Prefer table-driven tests when cases share setup and differ in input.
- Use `t.Helper()` in helpers and `t.Cleanup()` for teardown.
- Assertions show what was expected and what was received.
- Test data is built through small builders or fixtures, not copied between tests.
