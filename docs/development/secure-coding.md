# Secure Coding Guidelines

Nyktus runs inside sensitive networks, accepts traffic from attackers by design, and stores a map of every decoy in an environment. A vulnerability in Nyktus is worse than the same vulnerability in an ordinary application: it can blind the detection layer or hand an attacker the list of assets to avoid.

These rules apply to every change. The key words "must", "must not" and "should" are used as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119). A deviation from a "must" requires a documented reason in the code review and, where it is a lasting property of the system, in this document.

## Threat model

| Surface | Who talks to it | What must hold |
|---|---|---|
| Trigger endpoints (HTTP, DNS) | Anyone on the internet, including the attacker | Never reveal whether a value is a live honeytoken. Never fail visibly. Never enumerate the inventory. |
| Console and API | Authenticated users, API keys | Strict authentication, least privilege, no information leaks across permission boundaries. |
| Sensor | Attackers inside the monitored network | Emulate, never execute. Bounded resources. No real functionality. |
| Inventory | Readers of the console, API and database | Treated as the most sensitive data in the system. Whoever reads it can avoid every decoy. |
| Catalog | Contributors, maintainers | Only valid data is loaded. The catalog can never execute code. |
| Alert path | Worker and outbound integrations | Survives a compromise of the monitored environment. Cannot be turned against internal systems. |

The inventory comprises honeytokens, honeypots, artifacts, scenarios and their placement notes.

**Out-of-band operation.** Documentation and defaults must guide operators to run the console and the alert path outside the environment they monitor. An attacker with domain administrator rights in the monitored network must not be able to read the inventory or suppress alerts. Trigger endpoints for exfiltration-class decoys must be reachable from the internet, because stolen data is opened on the attacker's infrastructure.

## Enforce at the root

Security decisions are made in one place and reused, never repeated at every call site.

- Every route declares its authentication requirement and its required permission when it is registered. A route without a declaration must not start. Handler-level checks are defense in depth, not the primary control.
- Access is resolved by one function that checks every precondition: account status, role and, for API keys, scopes. A new way to reach a resource must go through it.
- An empty or unknown permission is never a wildcard. Routes that only need a signed-in caller declare that explicitly instead of passing an empty permission.
- When a fix is needed for a class of bugs, fix the shared function and add a test for the class, not only the instance.

## Server roles

The server binary runs one or more roles (`console`, `trigger`, `dns`, `worker`). Each role connects to the database with its own database role that grants only what the role needs.

- The `trigger` and `dns` roles have no privilege on any table. They hand exactly one trigger value at a time to a dedicated `SECURITY DEFINER` function, which resolves it, writes the event and its job if the resource is enabled, and returns only what the response and the log need. They cannot list honeytokens or honeypots, cannot read alert channels, users or audit data, and cannot write an event without its job or a job of their own. A compromised internet-facing host can test a value it already found, but never obtain the inventory. The migration revokes everything in the schema from these roles at its end and verifies that nothing beyond the function remains, so that default privileges set by an operator cannot widen them.
- Trigger code depends on one narrow interface that resolves a value and records its request in one call, never on the full store. A lookup without a record does not exist.
- The `worker` role reads events and writes incidents and their alerts through column-level grants, but reads no inventory, accounts or audit entries: every event carries what its incident needs. It cannot change what an event recorded or the triage of an incident, other than closing an incident without events for at least a day. Its periodic tasks remove or change data of other tables only through `SECURITY DEFINER` functions, one per purpose, that decide in the schema what has expired and enforce their own lower bounds, so that a compromised worker can at most remove what is due anyway, and its login needs no access to accounts. It refuses to start if its login reaches tables beyond its own or holds a privilege that its group role lacks, such as one granted to the login directly, and the migration verifies the grants of the group role in both directions.
- No role runs with `SUPERUSER` or `BYPASSRLS`. Migrations run with a separate owner role, never with an application role.
- The operator creates one group role per server role, such as `nyktus_console`, before the first migration. Migrations grant privileges to these group roles but never create roles, so the owner role needs no `CREATEROLE`. A migration that needs a group role checks that it exists and stops with a clear error otherwise.
- The server refuses to start outside development if a role's database user is a superuser, can bypass row-level security, can create roles or databases, can start replication, is a member of `pg_read_all_data`, `pg_write_all_data`, `pg_read_server_files`, `pg_write_server_files` or `pg_execute_server_program`, or owns the database or the schema.

## Trigger endpoints

Trigger endpoints receive requests for honeytokens. Their responses must not tell an observer anything about the token.

- **Identical responses.** A valid, unknown, disabled or expired token, a token of the wrong type, and an internal error must all produce the same status code, headers and body bytes. The only permitted difference is a redirect target that the operator configured for that honeytoken. No early return may skip work in a way that produces a different response.
- **Errors stay internal.** Database or queue failures are logged and answered with the same response as success.
- **No fingerprints.** Trigger responses must not carry product names, version information, `Server` or `X-Powered-By` headers, or any header that only Nyktus would send.
- **Small bodies.** Request bodies on trigger endpoints are limited to 64 KiB.
- **Atomic recording.** An event and the job that processes it are written in one transaction. A recorded event without a corresponding job must be impossible.
- **Form, not state.** The response depends only on the form of the request, compared in lower case: a path that ends with `.gif` receives the same image, every other request the same redirect. The URL of an image honeytoken therefore ends with `.gif`. Answering an image only for valid image values would reveal them.
- **Every request is answered.** Unknown paths, methods other than `GET` and `HEAD`, database errors, timeouts and panics receive the default response. The trigger uses neither the router nor the middleware of the console, whose JSON errors, request IDs and redirects of unclean paths would identify it, and writes redirects itself, because `http.Redirect` adds an HTML body.
- **Accepted limits.** Response times are not equalized: an active value writes an event, an unknown one does not, but only someone who knows a value can measure it, and that request is recorded. Malformed requests that `net/http` rejects before any handler runs (`400`, `431`) are answered by the Go server; the reverse proxy in front of the trigger keeps them away. When recording fails, the trigger does not know the redirect target of the honeytoken and sends the client to the default target; someone who knows a URL with a configured target could notice this while the database is unavailable or the connection pool exhausted, for example by a flood that the reverse proxy did not limit.
- **Recording outlives the client.** The database call runs with its own deadline, detached from the request, so a client that closes the connection right away cannot keep its request from being recorded.
- **Startup check.** Outside development, the trigger refuses to start unless its login can execute its recording functions, those for honeytokens and for sensors, and nothing else: no table, no other function, no `CREATE` on the schema, and no membership in another role, counted with `MEMBER` because a member that does not inherit can still `SET ROLE`. A login of the console, set up by mistake, never reaches the internet-facing host.
- **One process, all roles.** A process that runs several roles issues the setup token only after every role has started, so that a role that fails to start leaves no valid token behind.
- **Sensor reports.** Sensors report sessions and heartbeats to the trigger with a `POST` to `/`, authenticated by the secret of a honeypot as a bearer token. The trigger answers every report like any other `POST`, whatever became of it: a valid or wrong secret, a disabled or deleted honeypot, a refused or duplicate report, a failing database. A request whose header does not have the form of a secret is not looked up. The trigger hashes the secret and hands the hash to a database function, which finds the honeypot by it; it never reads the inventory. Reports are versioned and decoded strictly, so a version or member that the server does not know is not stored but logged with a reason from a fixed list, never with content. A sensor is not trusted: it names neither service, severity nor technique, and the server derives the kind of event from the content, takes the age of the session within fixed bounds, cuts and cleans every text it chose like the headers of a request, and the schema refuses what the trigger would replace. A password never reaches the database: a report carries its length only, and no column could hold one. A heartbeat only moves the time of the last report of a honeypot and never records an event. The limit of events per honeypot drops the sessions beyond it without a trace in the response: the sensor cannot tell, and a distributed brute force of more than ten sessions a minute is stored in part, the rest only counted in the log. This is accepted, because a limit that the sensor could see would be a signal to the attacker as well. The table of the techniques of a kind of event exists in Go and in the database function, and the status of a honeypot has its limit in the database and in `honeypot.OfflineAfter`; tests compare each pair, so that a change of one fails until the other follows.
- **Bounded recording.** At most a fixed number of events per honeytoken or honeypot and minute is stored; further requests are counted in memory and logged. Header values are cut to fixed lengths and stripped of characters that are not printable (control characters, line separators, characters that reorder or hide text, spaces other than U+0020) before they are stored, and the path, which holds the value, never reaches the log. Neither do the secret of a sensor nor anything an attacker typed into a honeypot.

### DNS

The DNS role is a trigger endpoint as well. The rules above apply where they are not specific to HTTP; in addition:

- **Form, not state.** The answer depends only on the form of the query and the rate of its source: every name under a zone receives the same records, the configured addresses for `A` and `AAAA` and no data with the SOA record otherwise. The configured addresses have no built-in default, because one would be the same in every installation. Names are compared in lower case, because resolvers randomize the case (DNS 0x20), and the question is returned as it was asked.
- **Answer first.** Nothing in the answer depends on the result of the recording, so the answer is written before the query is recorded. Response times are therefore equal for every value, and a slow database never delays an answer. Queries wait for recording in a bounded queue and are recorded with a deadline of their own, detached from the server; a query that finds the queue full, or waited more than five minutes, is counted in the log, not recorded. The event keeps the time the query arrived: the DNS role passes how long the query waited, measured with its own monotonic clock so that the clocks of two hosts need not agree, and the database accepts a delay of at most five minutes. The limit of events counts the time of writing, which the database sets, so that a compromised DNS role cannot evade it with earlier times.
- **What is a hit.** A query is recorded if the label directly below a zone is a trigger value, whatever its type, also with further labels in front of it: a resolver that minimizes the names it sends asks for `<value>.<zone>` first. The event stores the zone, the labels in front of the value with every character other than a letter, a digit, `-` or `_` replaced, the type and the transport, never the full name.
- **Authoritative only.** Names outside the zones, classes other than `IN` (such as `version.bind` in `CHAOS`) and zone transfers receive `REFUSED`; opcodes other than `QUERY` receive `NOTIMP`; responses receive no answer. The DNS role is never a resolver.
- **No amplification.** An answer over UDP is never larger than the buffer of the client or three times the query; a larger one is truncated, so that the client repeats it over TCP. UDP queries are limited per source network; beyond the limit, every second query receives an empty truncated answer and the others none. The table of sources is bounded; a source that finds it full is treated as over its limit. TCP connections are bounded in number, lifetime and queries.
- **Panics.** The server of the DNS library does not recover panics, so the handler and every recording recover their own.
- **The resolver is the client.** The recorded address is the source of the query, usually a resolver. The EDNS client subnet is not stored: anyone who sends a query directly can fill it.
- **Logs.** The queried name holds the trigger value and never reaches the log.
- **Accepted limits.** The DNS library answers malformed messages and messages without exactly one question itself, and its behavior in such corner cases can identify a server built on it, as it does for the many name servers that use it, but not Nyktus. Repeated lookups that a resolver answers from its cache within the TTL never reach the DNS role.

### Health endpoints

Operators can poll the health of a honeytoken or honeypot. This deliberately reveals state, so it is fenced:

- Health checks use a dedicated health secret that is never derived from, embedded with or rotated together with the trigger value. A trigger value must never resolve on a health endpoint.
- Unknown health secrets return `404` (or `NXDOMAIN`) with no timing or size difference that reveals anything else.
- Response bodies are static and minimal, sent with `Cache-Control: no-store`.
- A health check must never record an event, open an incident or raise an alert. This invariant has a dedicated test.

## HTTP handlers

Every handler must satisfy the following:

1. **Body size limit.** Wrap the body with `http.MaxBytesReader` before reading it. The default limit is 1 MiB.
2. **Strict decoding.** Decode JSON with unknown fields rejected and trailing data treated as an error.
3. **Validation at the boundary.** Validate every field: length limits, allowed values, URL and email syntax (`net/mail.ParseAddress`, `net/url.Parse` with explicit scheme and host checks). Do not write fragile regular expressions for formats the standard library parses.
4. **Permission before lookup.** Check the caller's permission before loading the resource, so a denied request cannot reveal whether a specific resource exists.
5. **No generic relinking.** Relations that carry security meaning, such as the scenario a resource belongs to, change only through a dedicated, validated operation, not through a generic `PATCH`. A `PATCH` is not generic if it accepts only fields that its request type declares, validates each of them on its own, and gives a security-relevant field, such as the role of an account, the same checks and consequences as a dedicated operation would.
6. **Secrets are shown once.** API keys, webhook secrets, recovery codes and activation links are returned only in the response that creates them. Every later response masks them.
7. **Generic errors.** Clients receive a generic message for every `5xx`. Error details, `err.Error()` strings and stack traces go to the log only, correlated by request ID.
8. **Audit.** Security-relevant writes create an audit log entry (see [Logging and audit](#logging-and-audit)).

Every HTTP server sets `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout` and `IdleTimeout`, and a recover middleware turns panics into a logged `500` that still passes through the regular response middleware. If the response had already started, the panic is logged and the connection aborted, so a client never receives a truncated body that looks complete.

**Client IP.** Every server, including the trigger endpoints, takes the client address from the socket unless the socket address lies within the configured trusted proxy ranges. Only then is `X-Forwarded-For` evaluated, from right to left: addresses within the trusted ranges are skipped, and the first other address is the client. Entries may carry a port; an entry that is not an address ends the search. A chain of proxies works without counting hops. A fixed hop count is not used, because it trusts the header even when a client bypasses the proxy. `X-Real-IP` is ignored.

Requests that match no route receive a JSON `404`, also when only the method differs. The default responses of `net/http` are not used: their plain-text bodies identify the server as written in Go, and the `Allow` header of a `405` lists the methods of a route. The same applies to the redirects of `http.ServeMux` for unclean paths and subtree patterns, which would also answer before authorization runs.

## Authentication

### Accounts and enrollment

There is no public registration.

- **First start.** While no administrator exists, the server generates a setup URL containing a one-time token on every start and prints it to standard output. The setup page creates the first administrator with an email address, a display name and a password, and accepts only that token. Without it, whoever reaches a fresh instance first could claim it.
- Once an administrator exists, the setup endpoint is permanently disabled and returns `404`, including after restarts.
- **Further accounts** are created by administrators in the console or just in time through OpenID Connect. Creating an account yields a single-use, expiring activation link through which the user sets their own password. The link is shown to the administrator once and can additionally be sent by email when a mail server is configured.
- Administrators never set or see another user's password.

Local accounts sign in with their email address and password. The display name is shown in the console and the audit log and plays no part in authentication. Addresses are compared in lower case and NFC normalization, so every spelling of an address maps to one account.

### Passwords

- Hash with Argon2id (memory 64 MiB, iterations 3, parallelism 4) and a random salt per hash. Hashes are stored in the PHC string format, and verification reads the parameters from the stored hash, so the parameters can be raised without invalidating existing passwords.
- Accept passwords from 12 to 128 characters, counted as Unicode code points after NFC normalization. Reject invalid UTF-8. Normalization makes the same password typed on different systems produce the same hash. The upper bound protects the hashing step from denial of service.
- Limit the number of concurrent hash operations. Each one allocates the full Argon2id memory, so parallel login attempts could otherwise exhaust the memory of the server. A rate limit at the reverse proxy is no substitute, because it applies per client.
- The database accepts only encoded Argon2id hashes in the password column, so a plain-text password can never be stored by mistake.
- Login must take the same time whether or not the account exists: verify against a precomputed dummy hash when no user is found.
- A password is verified before the account is locked, because hashing must not hold a row lock. Whatever the verification permits, such as a new session or a new password, therefore checks under the lock that the stored hash is still the one that was verified. Otherwise a sign-in racing a password reset starts a session that the reset should have prevented.

### Account enumeration

- Login and password reset do not reveal whether an account exists. Password reset returns the same status code **and the same body** for known and unknown addresses. Bodies must not contain fields that are only present on success.
- Per-address cooldowns on outgoing mail answer silently with the regular success response. A `429` would reveal that the address exists.

### Lockout

- Five failed attempts lock the account for 15 minutes. Counters are persistent, not per session.
- The lock is revealed only after a correct password. A wrong password on a locked account returns the same generic `401` as any other failure.
- The second factor has its own failure counting under the same lockout.
- Failures count for every known account, including pending ones, so anyone who knows an address can lock it. An action that proves access to the account without the password, such as an activation link, ends the lock.

### Single-use tokens

Setup tokens, activation tokens, password reset tokens, recovery codes and second-factor challenges:

- are generated from at least 32 bytes of `crypto/rand` (recovery codes: at least 80 bits),
- are stored only as a SHA-256 hash,
- expire, and are consumed atomically on use (`DELETE ... RETURNING` or equivalent).

### Sessions

- Sessions are server-side. The client holds an opaque token of at least 32 bytes from `crypto/rand`, and the database stores only its SHA-256 hash.
- The session cookie is `HttpOnly`, `Secure` and `SameSite=Strict` and carries the `__Host-` prefix, so that browsers accept it only with `Path=/` and without `Domain`, and a page on another subdomain can neither set nor replace it. A narrower path would rule out the prefix and is no security boundary within one origin. Session tokens are never stored in `localStorage` or `sessionStorage`.
- `SameSite=Strict` does not stop requests from other subdomains of the same site. Requests that change state and carry an `Origin` header must therefore come from the origin of the console, otherwise they are rejected with `403`. Clients other than browsers send no `Origin` header and are not affected.
- Sessions have a sliding idle timeout and an absolute maximum lifetime.
- The authorizer reads the session and the account with every request, so a deactivated account or a changed role takes effect with the next request.
- Sessions are revoked immediately on logout, password change, second-factor removal, role change and account deactivation.
- Every successful login issues a new session token. A token that existed before authentication is never promoted to an authenticated session.

### Second factor

- Every local account can enable TOTP (RFC 6238) with recovery codes. It is optional.
- TOTP secrets are encrypted at rest.
- The challenge between password and second factor is short-lived and single-use: it starts at most one session. A wrong code keeps it, so that a typo does not cost the password again; the codes it can try are bounded by the lockout, which ends it.
- A change that rotates the session of the caller first checks under the lock of the account that this session still exists, so that a session revoked by a concurrent change does not obtain a new one.
- A correct password does not reset the count of failed sign-ins while the second factor is missing. Otherwise whoever knows the password could reset the count between guesses of the code.
- A code is accepted only for a later time step than the last accepted one, checked under the lock of the account, so that it cannot be used twice. Recovery codes are consumed.
- `session.RevokeAll` also removes the challenges of the account, so that every change that ends the sessions, such as a new password or the removal of the factor, also ends the sign-ins that wait for a code.
- The setup, the new recovery codes and the removal, also by an administrator, require a session, never an API key. An administrator confirms the removal of another account's factor with their own password, because the removal and a reset link together would let a taken-over session take over the account. Wrong codes count as failed sign-ins wherever they are entered, also when a setup is confirmed. Setup asks for the password; new recovery codes and the removal ask for the password and a code.
- Accounts that sign in through OpenID Connect do not get a local second factor. The identity provider is responsible for it.

### Local login and OpenID Connect

- OpenID Connect is configured exclusively through the environment. Secrets are read from environment variables or files and are never stored in the database or logged.
- Local login is restricted by policy while OpenID Connect is enabled: `admins` (default), `all` or `off`. Without OpenID Connect, every account signs in with its password. A login rejected by the policy returns the same generic `401` as wrong credentials, after the same password verification, and before the lockout is revealed. Every local login is recorded in the audit log.
- An unreachable identity provider at startup produces a warning and a later retry, never a failed start. Otherwise an identity provider outage would also lock out the local administrators.
- The `state` parameter is 32 bytes from `crypto/rand`, single-use, short-lived and bound to the browser through an `HttpOnly` cookie with a token of its own. The database stores only the SHA-256 hashes of both, and consumes the sign-in atomically with both hashes.
- PKCE with `S256` and a `nonce` are mandatory. The nonce in the ID token is verified explicitly.
- `email_verified` must be asserted as true by the identity provider. Missing or false values are rejected.
- An identity from the identity provider is **never linked automatically** to an existing local account, even when the email addresses match. Such a login is rejected with a generic error and recorded in the audit log. Otherwise anyone who controls an address in the identity provider could take over a local administrator.
- Requests to the identity provider do not use the SSRF-guarded client: the issuer is configured by the operator, not supplied by a user, and the provider is often reachable only internally. They use a client of their own with timeouts, which refuses plain `http` outside development, also for redirects and for the endpoints that discovery names.
- Claims are taken only from the verified ID token, never from the userinfo endpoint. A token for several audiences must name the console in `azp`.
- An account of the identity provider is identified by issuer and subject, never by its email address, and has no password. Changes that the password confirms are refused for it.
- A user without a matching group claim is denied, and an existing account is deactivated. There is no fallback role. The role follows the groups with every sign-in, under the lock of the active administrators, so that the groups never demote or deactivate the last one.
- The identity provider never creates the first administrator: sign-ins through it are rejected until the setup is complete.
- Where a local account confirms an action with its password, an account of the identity provider confirms by signing in there again with `prompt=login` and `max_age=0`. The provider must report an `auth_time` after the start of the reauthentication, for the identity and the role of the account of the session; the session is then marked for five minutes. The mark belongs to the session, is checked under the lock of the account, and is never accepted in place of a password from a local account.
- The page to which a reauthentication returns is a path of the console, validated in the application and in the schema, never a URL.

### API keys

- Keys belong to the team, not to the administrator who created them. Only administrators create, list and revoke them. A key outlives changes to the account of its creator, including its deletion; it ends only when it expires or is revoked.
- Keys have a fixed, recognizable prefix so that secret scanners can detect leaked keys.
- Keys are stored as a SHA-256 hash. Lookup uses a non-secret key identifier, and the comparison is constant-time.
- Keys carry scopes in the form `resource:action`, for example `incidents:read` or `honeytokens:write`. A key holds its scopes and nothing else, independent of any role.
- The scopes that keys may carry are a list of their own in `internal/auth/access`, a subset of the permissions. Keys never manage accounts or keys: a key with `users:write` could take over every account through password reset links, and one with `api_keys:write` could issue itself a successor. The database checks only the form of a scope, as with audit actions; the authorizer grants nothing beyond the list. A scope to change a resource requires the scope to read it, such as `honeytokens:write` with `honeytokens:read`, because every change returns the resource, also a change that changes nothing; a key that seems unable to read would read it anyway.
- Every key has an expiry date, at most three years after its creation, which the administrator chooses. Keys record their last use. In the audit log, a key is an actor of its own, with its identifier and a copy of its name.
- Keys are managed only with a session, and creating one requires the password of the administrator, because a key outlives the session. The creations are serialized under the lock of the active administrators, so that the limit of keys holds. Routes that change how an account authenticates, its session or the keys declare `SessionOnly()` and reject keys with `403`.
- Authenticated routes that are not session-only admit keys, and the specification lists `bearerKey` exactly for the routes that a key can reach; a test compares both with the router and the scopes that keys may carry.
- A request with an API key, a bearer token with the key prefix, authenticates with it alone; other credentials in the `Authorization` header are ignored, so that a reverse proxy with basic authentication or an identity-aware proxy does not lock out sessions. Every invalid key receives the same `401` as a request without credentials, without an audit entry.
- Sensors do not use API keys. They authenticate with their own per-honeypot secret.

## Authorization

- Role checks fail closed. An unknown or empty role or scope has no permissions.
- Read-only roles are enforced on the server for sessions and API keys alike.
- Read access to the inventory is a sensitive permission. Integrations that only need incidents get a key without inventory scopes.
- Deleting a scenario with its honeytokens or artifacts (`?honeytokens=delete`, `?artifacts=delete`) needs `scenarios:write` only, as applying a deception creates them with it, and every resource it removes has an audit entry of its own. Deleting it with its honeypots (`?honeypots=delete`) also needs `honeypots:write`, because no deception creates them: only that permission puts a honeypot into a scenario. The handler checks it before anything is loaded and records a denial like the authorizer. Detaching resources (`keep`) needs `scenarios:write` only, so that a scenario can always be deleted. Changing a single resource, including its scenario, needs the permission of the resource.

## Database

- Use parameterized queries only. SQL is never assembled with `fmt.Sprintf` or string concatenation. Dynamic identifiers, such as sort columns, come from an allowlist in code.
- Map database errors to sentinel errors in the store layer and compare with `errors.Is`. Detect constraint violations by SQLSTATE (`23505` for unique violations), never by message text.
- Invariants that span several statements run in one transaction. Where concurrent requests can race, take the row lock explicitly and prove it with a test (see the [testing guidelines](testing.md)).
- The schema is the last line of defense: use `NOT NULL`, `CHECK`, foreign keys and unique constraints for every invariant the database can express.
- The schema is the last line of defense, not the first. PostgreSQL writes the complete failing row of a constraint violation to its server log, so a row with a secret, a password hash or a plain-text password passed by mistake would end up there. Stores validate every field before they write such a row.
- Connection pools have explicit upper limits.

## Outbound requests

Several features send requests to user-supplied URLs: webhooks and chat integrations. Every such request goes through the SSRF-guarded client. The identity provider and the SMTP server are configured by the operator and are the exceptions, see [Local login and OpenID Connect](#local-login-and-openid-connect) and [Mail](#mail).

The guard lives in `internal/platform/ssrf`.

- **Validation on save.** The scheme must be `https` (plain `http` only in development, and only where explicitly allowed). The URL carries no user information or fragment and only printable ASCII. Host names such as `localhost`, `*.local` and `*.internal`, names of a single label, which the search domains of the host complete, and names whose last label is a number, which a resolver may read as an IPv4 address, are rejected. All resolved addresses are checked; a name with one blocked address among public ones is rejected as a whole. A blocked target and a name that does not resolve produce the same error, so that the check does not reveal which internal names exist.
- **Blocked ranges.** Every address that is not globally reachable: loopback, private (RFC 1918, RFC 4193), link-local including cloud metadata addresses, carrier-grade NAT, documentation and benchmarking ranges, multicast, broadcast, reserved and unspecified addresses, and IPv6 forms that embed or tunnel to IPv4 addresses (mapped, compatible, translated, 6to4, Teredo). The well-known NAT64 prefix is unwrapped and its embedded IPv4 address checked, because on networks that reach IPv4 only through NAT64 every target resolves to it. `netip` alone is not enough: it counts most of these ranges as global unicast.
- **Internal targets.** An operator, never a user of the console, can allow internal networks, such as the network of a SOAR platform. This never opens loopback, link-local or metadata addresses, and lifts the rules for internal names, which such targets carry.
- **Enforcement on connect.** The client resolves the name itself when it connects, checks every address and dials exactly an address it checked, so that nothing learned between validation and use, such as a rebound DNS answer, changes the target. A `net.Dialer.Control` function checks the dialed address once more. Every request is checked like a saved URL before it is sent.
- **No redirects.** The client returns a redirect instead of following it. A feature that needs to follow one sends each hop through the guard on its own.
- **No proxy from the environment.** `HTTP_PROXY` and `HTTPS_PROXY` are ignored, because the guard would check the address of the proxy, not the target.
- **Bounded responses.** A request ends after ten seconds, response headers are limited to 16 KiB and bodies to 64 KiB.
- **No oracle.** Test endpoints return a generic error and never the underlying network error, so they cannot be used to scan ports.
- **Error classes.** A blocked target is a configuration error and is not retried.

Arbitrary ports on public hosts are allowed, because self-hosted integrations need them. This residual risk is accepted and documented.

### Alert channels

The alert path must survive a compromise of the monitored environment, including a taken-over session of an administrator.

- The URL of a channel, with its path and query, and the value of its header are secrets: a chat webhook accepts messages from whoever knows its URL. They are encrypted, bound to the channel and their purpose, never returned, also not on creation, and never logged; types that carry them redact them in `String`, `GoString`, `LogValue` and `MarshalJSON`.
- The console writes the secrets but its database role cannot read them back. A change replaces a secret without comparing it, so the audit log counts it as changed.
- The recipients of a channel of the type `email` are no secret: an address grants nothing to whoever knows it. They are stored and returned as they are, may appear in logs, and are confirmed with the password like a URL. Every address is a bare `local@domain`, checked by the SMTP client.
- Every change other than a new name decides where alerts go, what authenticates them or whether they go at all, and is confirmed with the password through `session.Service.Confirm`, like the creation of an API key. This includes enabling a channel again, whose target may have changed hands meanwhile. A channel is deleted only once it is disabled, so that `DELETE` needs no body.
- API keys never manage channels, not even by reading them.
- Only the worker connects to receivers, also for tests, so that one host needs outbound access and no answer of the console reveals the network. A delivery records the status code and the class of a failure, never the response or the error, which names the URL.
- A message carries no inventory and no personal data, because it often leaves for a service of a third party. Mail names its recipients and nothing else of a person.

### Mail

Mail goes through one client, `internal/platform/smtp`; the linter rejects `net/smtp` elsewhere.

- The SMTP server is configured by the operator, not by a user of the console, and is often reachable only internally. Like the identity provider, it is not reached through the SSRF guard. The client reads no proxy from the environment.
- The certificate of the server is always verified, with TLS 1.2 or later. With STARTTLS, a server that does not offer it is refused before anything but the greeting is sent, so that nobody on the way can strip TLS and read the password. The password, with `AUTH PLAIN` or, where a server offers only that, `AUTH LOGIN`, goes only over TLS or to the loopback interface; `net/smtp` recognizes TLS only on a `*tls.Conn`, so nothing may wrap it. Plain SMTP exists for development only.
- A conversation is bounded in time, and the replies of the server in size, because `net/textproto` reads a reply without a limit.
- Every header and the body consist of printable ASCII, and every address is a bare `local@domain` without display name, comment or quoting, checked before the client connects. No value can end a header and start another one.
- A message is sent only once the server has accepted every recipient. Errors keep the code of a refusal, never its text or the password.

## Secrets and cryptography

- Use `crypto/rand` for every value with security relevance. `math/rand` is not used for identifiers, tokens or secrets.
- Compare secrets with `crypto/subtle.ConstantTimeCompare` or `hmac.Equal`.
- Encrypt secrets at rest with AES-256-GCM through `internal/platform/secretbox`. Stored values carry the ID of their key to allow key rotation. The keys come from configuration, in development as well, and are never derived from another secret. Pass associated data that names the purpose and the owner of a value, so that a value copied into another record fails to decrypt.
- Outbound webhooks are not signed. A receiver authenticates them by a secret in the URL or a header of the channel, which HTTPS protects on the way. A signature would protect only the receiver against forged alerts, which the secret prevents as well, and most receivers check a token, not a signature; a signature scheme such as Standard Webhooks can be added if receivers ask for it.
- The server validates its configuration at startup and refuses to run with missing or weak secrets outside development.
- Secrets never appear in logs, error messages, URLs (except trigger and health secrets, which are designed for it) or client-side state.

## Catalog

The deception catalog lives in `catalog/` and is embedded at build time. It is reviewed like code; there are no signatures and no import at runtime, because a signature over embedded data proves nothing that the review and the signature of the release binary do not.

- Entries are JSON, decoded strictly, and declare their schema version. An unknown field or an unsupported schema version is an error.
- Every entry is validated when the server starts and in tests: schema, technique and Engage identifiers against the bundled reference lists, and a test render of every template in every language. An invalid entry keeps the server from starting.
- The catalog contains data and templates only. It never contains or loads executable code. The template engine allows only text, field references, conditions on fields and one escaping function per format, and exposes no function that performs I/O, so that rendering is bounded by the size of the template.

## Generated artifacts

Honeytokens, scenarios and artifacts produce files and snippets that operators place in their environment.

- Templates that produce HTML use `html/template`. Text templates run with `missingkey=error`.
- Built-in templates are parsed and test-rendered at startup. A template that does not render prevents the server from starting.
- **Executable and interpreted formats** (scripts, shortcuts, configuration files) receive only server-generated values, such as trigger values and random credentials from `crypto/rand`, or values that match an allowlist pattern for that format.
- **Inert formats** (plain text, documents) may contain free text from users or generators, escaped for the target format.
- **No markers.** Generated artifacts never contain anything that identifies Nyktus or the catalog: no product names, attribution notices, comments, metadata fields or recognizable formatting conventions. The catalog checks the text of its templates when it loads; applying a deception checks every rendered artifact again, because values from outside the catalog reach it, such as the persona, the address of the trigger and the zone of the DNS role.
- **Snapshots.** Applying a deception stores its artifacts and its guide as rendered, with secrets generated once, and never renders them again: what was placed must stay what the console shows.
- **No hack-back.** A decoy may only cause a passive callback, such as a DNS lookup or an HTTP request. It must never execute code that harms, persists on, or collects data from the system that opens it beyond what the callback itself transmits.

## Output encoding

- Mail is plain text in printable ASCII, see [Mail](#mail). A value with a line break or another control character is rejected before it reaches a header or the body, never silently stripped: a stripped value could still change what the header says.
- CSV exports neutralize formula injection: every field starting with `=`, `+`, `-`, `@`, tab or carriage return is prefixed with `'`.
- Attacker-controlled values, such as user agents or captured credentials, are always treated as untrusted data in every output: console, email, chat messages, exports and logs.

## Sensor

The sensor runs inside the monitored network and talks to attackers directly.

- It runs as an unprivileged user with the smallest possible dependency set. It never executes, interprets or forwards attacker input.
- Emulated services offer no real functionality. A mail decoy accepts messages but never relays them. No service may act as a proxy.
- Connections, read sizes, sessions and runtimes are bounded so the sensor cannot be used to exhaust the host or amplify traffic.
- The sensor authenticates to the server with a per-honeypot secret over TLS.
- The sensor reports one event per attacker session, summarizing all protocol steps, and sends it when the session ends or after a short maximum delay. An incident raises a single alert when it opens, so its first event must describe what the attacker did, not only the handshake.

## Logging and audit

- Logs are structured (`log/slog`, JSON). Request-scoped logs use the `...Context` variants so that request ID and actor are attached automatically.
- Never log passwords, session tokens, API keys, secrets, one-time codes or complete request bodies. Types that carry such values or password hashes implement `slog.LogValuer` and omit them, so that logging the whole value cannot leak them. Attacker-controlled values are logged as structured attributes, never concatenated into the message.
- The audit log records every security-relevant write and every authentication event with the actor and the authentication method, including the API key identifier where applicable. For updates it records the names of changed fields, not their values, so the audit log does not become a second copy of the inventory. Resources are recorded by type and identifier, never by name.
- An audit entry is written in the transaction of the action it records. An action never takes effect without its entry, and a failed entry fails the action.
- The audit log is append-only for the application. The console's database role can insert and read entries, but never update or delete them. No role deletes entries; the worker removes those beyond the retention through a `SECURITY DEFINER` function that refuses a retention below 90 days.
- Entries keep a copy of the actor's address and display name, taken from the account by the database, so they stay readable after the account is deleted.
- Metrics report aggregates only, read through a `SECURITY DEFINER` function, and their labels name fixed states or tasks, never a resource, an address or a name. A new metric is added to the function and to the description in `internal/metrics`, which rejects every metric it does not describe. Whether incidents are open tells an intruder whether they were noticed, so only administrators and keys with `metrics:read` read them.
- Requests without valid credentials are not audited, so anonymous clients cannot flood the audit log; the access log records them. Requests denied for a missing permission are audited.
- Entries that a signed-in user can cause at will without changing anything, such as denied requests and reads of personal data, are recorded at most once per user, API key, action, outcome and minute (`audit.Store.RecordUnlessRepeated`). Each key counts on its own, so that the requests of a leaked key cannot hide behind those of another key or a session. Writes, sign-ins and sign-outs are always recorded. A failed sign-in for an unknown account does not record the submitted address, which is attacker input and sometimes holds a mistyped password.

## Web console

- `v-html` and `innerHTML` are used only with static, hardcoded strings. Every exception needs a justification in review.
- Authentication state in the client is a cache of the user profile, never a credential.
- Post-login redirects accept internal paths only.
- Secrets shown once after creation are discarded from client state afterwards.
- Links with `target="_blank"` carry `rel="noopener noreferrer"`.
- The Content Security Policy uses `script-src 'self'` without `unsafe-eval`, and `frame-ancestors 'none'`.
- The console loads no external resources at runtime: no CDNs, web fonts, analytics or tracking. All assets ship with the build.
- Client-side validation exists for usability. The server is the only authority.

## Deployment

- Only the reverse proxy and, where used, the DNS port are exposed. Application processes bind to loopback or an internal network.
- TLS 1.2 or later, HSTS, `X-Content-Type-Options: nosniff`, a strict `Referrer-Policy`, and no server version tokens.
- Rate limits apply to every route that reaches the API, with stricter limits on authentication endpoints. All entry points share the same limit zones so clients cannot gain budget by switching host names.
- Containers run as a non-root user with a read-only root filesystem, all capabilities dropped and `no-new-privileges` set.
- When roles are split across hosts, the database accepts connections from the internet-facing host only for the restricted trigger database role, over TLS.

## Dependencies and supply chain

- Every new dependency needs a justification in its pull request: why the standard library is not enough, how well the project is maintained, its license compatibility with the AGPL, and its transitive footprint.
- CI runs `govulncheck` and `npm audit` and fails on known vulnerabilities in reachable code.
- GitHub Actions are pinned to a full commit SHA, and workflows declare minimal `permissions`.
- Releases ship with checksums, signatures and a software bill of materials.

## Review checklist

Before requesting review, check every item that applies to your change:

- [ ] Request bodies are size-limited and decoded strictly.
- [ ] All input is validated at the boundary.
- [ ] Every new route declares its authentication and permission. Permission is checked before the resource is loaded. The route and its `401`/`403` responses are documented in the OpenAPI specification.
- [ ] Secrets are masked after creation and absent from logs and errors.
- [ ] Trigger responses, over HTTP and DNS, are identical for every outcome. Trigger code resolves single values only and never enumerates the inventory.
- [ ] Health checks cannot create events, incidents or alerts.
- [ ] Outbound requests to user-supplied URLs use the SSRF-guarded client.
- [ ] SQL is parameterized. Constraint errors are mapped by SQLSTATE.
- [ ] Security-relevant writes are audited without copying sensitive values.
- [ ] Free text reaches generated artifacts only in inert formats. Artifacts carry no marker that identifies Nyktus.
- [ ] Catalog entries are validated at startup and in tests, and templates use only the allowed constructs.
- [ ] New dependencies are justified.
- [ ] Tests cover the security property, not only the happy path.
