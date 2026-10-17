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

- Trigger responses are identical for valid, unknown, disabled and failing tokens, apart from an operator-configured redirect target. For the DNS role, this covers rcode, flags, every section and the TTLs, over a real UDP and TCP server, including a panic during recording.
- The trigger and DNS database roles cannot select from any table and resolve only single values through their own function.
- The DNS role refuses names outside its zones (no recursion) and answers no queries in the class `CHAOS`.
- The server refuses database roles with privileges beyond their grants, with one case for every privilege the check covers.
- The database role of every server role passes that check after all migrations and has no privileges beyond its grants.
- Migrations leave PUBLIC without privileges on the schema, and fail when they cannot achieve that.
- An event is never stored without its processing job, and its job stays until the event is assigned to an incident, also when processing fails.
- An event belongs to exactly one incident. A scenario, and a resource that stands alone, has at most one open incident, also when several workers process events of different resources of one scenario at once, a closed incident is never opened again, and every incident has exactly one alert. An event keeps the scenario of its resource at the time it was recorded.
- Login and password reset return identical status codes and bodies for existing and unknown accounts, and for accounts rejected by the local login policy.
- Health checks never record an event, open an incident or raise an alert.
- The setup endpoint accepts only the current setup token and returns `404` once an administrator exists, including after a restart.
- Generated artifacts contain no product name, attribution or metadata that identifies Nyktus.
- Every registered route declares its authentication and permission. The test enumerates the router, so a new route without a declaration fails the build.
- Denied requests are rejected before the resource is loaded.
- The console can add and read audit entries but never change or delete them.
- Read-only roles and API keys without a write scope cannot write. A demoted user's keys lose the corresponding permissions.
- An invalid catalog entry, such as an unknown technique, an unknown field or a template that does not render, keeps the server from starting. Templates cannot use constructs outside the allowed set.
- The SSRF guard blocks every reserved address range.
- The console can write the secrets of alert channels but never read them, and the secrets are stored encrypted and bound to their channel.
- Every periodic task removes exactly what has expired, also at the boundary, and nothing that is still valid; its lower bounds hold in the database; two workers run it without errors and without running it twice; and no role other than the worker can execute its functions.
- An incident without events closes after its inactivity, open or acknowledged, with an audit entry of the system and only the lock of the incident: an event that waits for it meanwhile opens a new incident with a new alert.
- The metrics contain no inventory and no personal data, and labels hold only fixed values.
- Mail is sent only to a server with a verified certificate, never in plain text outside development; a server without STARTTLS receives nothing after the greeting, and the password goes only over TLS. Every header rejects line breaks and other control characters, and a message reaches all of its recipients or none.
- Every alert reaches every enabled channel once, also when two workers look for deliveries at the same time; a failing channel never holds up the others; retries, backoff and dead deliveries are tested by moving the stored times, never by waiting; secrets of channels and the password of the SMTP server never reach the log, also when a request fails.

### Checks are tested against violations

A test that guards a rule, such as a linter configuration, the specification check or a validation, is only trusted after it has failed on a deliberate violation. Change the code or data so that the rule is broken, watch the test fail, and restore it. Mention this in the pull request.

### Test what a real client receives

`httptest.ResponseRecorder` records what the handler wrote, which can differ from what a client receives over `net/http`. It keeps the body of a `HEAD` response, for example, which a real server discards. Assert on status and headers for `HEAD`, and use a real server through `httptest.NewServer` when the transport matters.

### Fakes, not mocking frameworks

Stores are interfaces, and tests use hand-written fakes backed by maps. Fakes can record calls when a test needs to assert on them. Generated mocks with expectation DSLs are not used: they are harder to read and couple tests to call order instead of behavior.

### Store tests run against PostgreSQL

Fakes cannot find a mismatch between a `SELECT` list and a `Scan`, a missing index or a wrong lock. Every store method has at least one test against a real database.

- `dbtest.New` creates an empty database for each test and drops it afterwards, so tests and packages run in parallel without shared state.
- Database tests run when `NYKTUS_TEST_DATABASE_URL` points to a server that allows creating databases. `make db-up` starts one, `make test-db` runs the suite against it. Without the variable the tests are skipped; CI sets `NYKTUS_REQUIRE_DB_TESTS=1`, which turns a skip into a failure.
- Constraint and permission behavior is tested with the same database roles that production uses, one per server role. `schematest.Console` returns a migrated database and a login role that is a member of `nyktus_console`, as the console connects in production. Store tests use it instead of the superuser, so a missing grant fails the test.
- Group roles are global to the server and shared by all tests. `dbtest.GroupRole` creates one idempotently and safely under concurrency; tests never drop them. A test that needs a missing role uses a unique name instead.
- Packages and their tests run in parallel, and every test holds its database connections until it ends. Cases of one test share a database, each with its own rows, instead of creating a database per parallel subtest. Subtests that need a database of their own run one after another.
- `dbtest` and `schematest` are for tests only. The linter rejects them in other code.

### Concurrency is tested deterministically

- Never assert on elapsed time or use `time.Sleep` to order events. Use barriers, channels or explicit clock control.
- To prove that a row lock is taken, hold the lock in one transaction and try `SELECT ... FOR UPDATE NOWAIT` from a second one. A lock inside a CTE must be tested by running the CTE body on its own, because PostgreSQL may never evaluate a CTE when another branch of the join is empty.
- A statement inside a PL/pgSQL function cannot be explained on its own without copying it. To prove that it seeks into an index, also with the generic plan, call the function on a connection with `plan_cache_mode = force_generic_plan` and `enable_seqscan = off` and compare `idx_tup_read` of the index in `pg_stat_user_indexes` before and after, with `pg_stat_force_next_flush()` and `pg_stat_clear_snapshot()`: a seek returns only the rows beyond the condition, a scan of the whole index every row.
- To prove that a table lock is taken, probe it from a second transaction with a `NOWAIT` mode that conflicts with the lock under test and with nothing else the first transaction does. Every `INSERT`, `UPDATE` and `DELETE` holds `ROW EXCLUSIVE`, so a probe in `EXCLUSIVE` mode would also fail without the lock under test. `ROW SHARE` conflicts only with `EXCLUSIVE` and `ACCESS EXCLUSIVE`.
- A lock that must be taken before a check, such as "no administrator exists yet", is proven by ordering: hold the lock and change the checked state in one transaction, wait until the code under test is blocked on the lock (poll `pg_locks` for a waiter on the table, or `pg_stat_activity` for a session of the test database with `wait_event_type = 'Lock'` when the waiter waits for a row), commit, and assert the outcome.
- Run the full suite with `-race` in CI.

### Drift between curated data and code is tested

When data is maintained in two places, for example technique identifiers in the catalog and the bundled ATT&CK reference list, a test asserts that both agree. The same applies to values that code generates and the schema checks, such as request IDs and the constants of a type with a `CHECK` list: a test writes what the code produces, not a copy of it, to the database. Generated files, such as the published catalog index, are compared against golden files that can be regenerated with an explicit flag.

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
