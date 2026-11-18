# Contributing to Nyktus

Thank you for your interest in Nyktus. This document describes how to propose changes and what we expect from a contribution.

Nyktus is a security product. We value correctness, clarity and security over feature count, and we review every change with that in mind.

## Before you start

- **Vulnerabilities** go through [SECURITY.md](SECURITY.md), never through public issues.
- **Bugs and small fixes**: open an issue or a pull request directly.
- **Features, new dependencies and architectural changes**: open an issue first and wait for a maintainer to agree on the approach. This saves you from work that cannot be merged.
- **New or improved deceptions** go into `catalog/`. Its content is licensed under CC BY-SA 4.0, not under the license of the code.

## Guidelines

Every contribution follows these documents:

- [Engineering guidelines](docs/development/engineering.md): code structure, errors, logging, comments, dependencies.
- [Secure coding guidelines](docs/development/secure-coding.md): the security rules for every component.
- [Testing guidelines](docs/development/testing.md): what to test and how.

## Development setup

You need Go (the version in `go.mod`), Docker for the test database, and `make`.

```sh
make db-up      # disposable PostgreSQL on port 55432
make test-fast  # all tests, including database tests, without the race detector
make test-db    # all tests, including database tests, with the race detector (run before you push)
make lint       # linters and formatting checks
make db-down
```

`make help` lists all targets.

### Try the current state

You need Docker with Compose. The development environment builds the web console and the server from your working tree and starts PostgreSQL, the migrations, the console with the worker, the trigger and the DNS role:

```sh
make dev-up     # first start takes a while; prints the setup URL of the first administrator
make dev-down   # stop, keep the data
make dev-reset  # stop, delete the data
```

| Service | Address |
|---|---|
| Console and worker | <http://localhost:8080> |
| Trigger | <http://localhost:8081> |
| DNS role, zone `d.nyktus.test` | `localhost:8053` over UDP and TCP |
| PostgreSQL | `localhost:55433`, logins `nyktus_owner` and `nyktus_*_login`, password `dev` |

Everything listens on the loopback address only, and the passwords are public: the environment is for development data. `make dev-up` creates the encryption key once in `deploy/dev/.env`, which Git ignores. If you lose the setup URL, run `docker compose --file deploy/dev/compose.yaml logs console`, or restart the console with `docker compose --file deploy/dev/compose.yaml restart console`.

### Run the binaries yourself

You need Go (the version in `go.mod`), Node.js 24, Docker, Make and Git. To build a release instead of the current development state, check out its tag first.

Build the binaries and start a disposable PostgreSQL on port 55432, whose data is gone when the container stops (`make db-down`):

```sh
make build
make db-up
```

Create the group roles, the owner, the database and the logins:

```sh
docker exec -i nyktus-test-db psql --username postgres --set ON_ERROR_STOP=1 < deploy/postgres/roles.sql

docker exec -i nyktus-test-db psql --username postgres --set ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE nyktus_owner LOGIN PASSWORD 'owner-pass';
CREATE DATABASE nyktus OWNER nyktus_owner ENCODING 'UTF8';
CREATE ROLE nyktus_console_login LOGIN PASSWORD 'console-pass' IN ROLE nyktus_console;
CREATE ROLE nyktus_trigger_login LOGIN PASSWORD 'trigger-pass' IN ROLE nyktus_trigger;
CREATE ROLE nyktus_worker_login LOGIN PASSWORD 'worker-pass' IN ROLE nyktus_worker;
SQL
```

Put the settings into a file that only you can read, because it holds the encryption key, then apply the migrations and start the server:

```sh
umask 077
cat > nyktus.env <<'EOF'
export NYKTUS_ENV=development
export NYKTUS_ENCRYPTION_KEYS="1:$(openssl rand -base64 32)"
export NYKTUS_TRIGGER_URL=http://127.0.0.1:8081
export NYKTUS_TRIGGER_DEFAULT_REDIRECT=https://www.example.com/
export NYKTUS_CONSOLE_DATABASE_URL='postgres://nyktus_console_login:console-pass@127.0.0.1:55432/nyktus?sslmode=disable'
export NYKTUS_TRIGGER_DATABASE_URL='postgres://nyktus_trigger_login:trigger-pass@127.0.0.1:55432/nyktus?sslmode=disable'
export NYKTUS_WORKER_DATABASE_URL='postgres://nyktus_worker_login:worker-pass@127.0.0.1:55432/nyktus?sslmode=disable'
EOF
. ./nyktus.env
NYKTUS_DATABASE_URL='postgres://nyktus_owner:owner-pass@127.0.0.1:55432/nyktus?sslmode=disable' bin/nyktus migrate
bin/nyktus serve --roles=console,worker,trigger
```

The server prints the setup URL of the first administrator. The console runs on http://127.0.0.1:8080, the trigger on http://127.0.0.1:8081, and `bin/nyktus-sensor` is built next to the server.

## Pull requests

- Keep a pull request focused on one change. Separate refactorings from behavior changes.
- Add or update tests. A bug fix includes a regression test that fails without the fix.
- Update the documentation when behavior, configuration or the API changes. It lives in [`Nyktus/nyktus-docs`](https://github.com/Nyktus/nyktus-docs): open a matching pull request there and link the two.
- Describe the security impact in the pull request, even if it is "none".
- All checks must pass before review.

## Commits

Pull requests are squash-merged. The pull request title becomes the commit message on `main` and the entry in the changelog, so it must follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). A check enforces this:

```
feat(alerting): deliver alerts to Microsoft Teams workflows
fix(trigger): return identical responses for disabled honeytokens
docs(catalog): describe the template schema
```

Write the subject in the imperative mood and use the description to explain *why* the change is needed.

| Type | Use | Changelog |
|---|---|---|
| `feat` | New functionality for users | Features |
| `fix` | Bug fix | Bug Fixes |
| `perf` | Performance improvement | Performance |
| `refactor`, `docs`, `test`, `build`, `ci`, `chore` | Everything else | not listed |

A breaking change adds `!` after the type, for example `feat(api)!: ...`, and explains the migration path in the description. Security fixes are published through security advisories, not only in the changelog.

### Developer Certificate of Origin

Every commit must be signed off to certify that you wrote the change or otherwise have the right to submit it under the project's license, as described in the [Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s
```

This adds a `Signed-off-by: Your Name <you@example.com>` trailer. Sign off with a name you are known by, which does not have to be your full legal name, and an email address you can be reached at. Anonymous sign-offs and pseudonyms that hide who submitted a change cannot be accepted.

## AI-assisted contributions

You may use AI tools, under the same standard as any other contribution:

- You are responsible for every line you submit, and you must be able to explain it in review.
- Do not submit generated code you have not read, understood and tested.
- Mention substantial AI assistance in the pull request description.

[AGENTS.md](AGENTS.md) provides instructions for coding agents working in this repository.

## License

By contributing, you agree that your contributions are licensed under the [GNU Affero General Public License v3.0 or later](LICENSE), the same license that covers the project.
