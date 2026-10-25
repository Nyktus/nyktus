# AGENTS.md

Instructions for coding agents working in this repository. Human contributors start with [CONTRIBUTING.md](CONTRIBUTING.md).

## Project

Nyktus is a self-hosted deception platform: honeytokens, honeypots and artifacts, grouped into scenarios, built from a deception catalog mapped to MITRE ATT&CK and MITRE Engage. It is a security product. Correctness and security take priority over speed and feature count.

The project is in early development. Prefer a clean design over compatibility with earlier drafts. There are no released versions and no installations to migrate.

## Required reading

Read these before changing code. They are binding:

- [docs/development/secure-coding.md](docs/development/secure-coding.md)
- [docs/development/engineering.md](docs/development/engineering.md)
- [docs/development/testing.md](docs/development/testing.md)

## Stack

| Component | Technology |
|---|---|
| Server | Go, PostgreSQL (no other infrastructure services) |
| Sensor | Go, separate binary with a minimal dependency set |
| Web console | Vue 3, TypeScript, Vite, embedded into the server binary (`web/`, build output in `web/dist`) |
| Deception catalog | Data and templates in `catalog/`, embedded at build time |
| Documentation | VitePress, in its own repository [`Nyktus/nyktus-docs`](https://github.com/Nyktus/nyktus-docs), published at docs.nyktus.org |

One instance serves one organization. There is no multi-tenancy.

## Architecture

The server binary `nyktus` runs one or more roles in a process:

| Role | Responsibility | Exposure |
|---|---|---|
| `console` | API and web console | Internal |
| `trigger` | HTTP trigger and health endpoints | Internet |
| `dns` | Authoritative DNS for DNS honeytokens | Internet |
| `worker` | Incident correlation, alert delivery, scheduled jobs | Internal, outbound only |

Roles communicate only through PostgreSQL and use separate database roles with least privilege. The `trigger` and `dns` roles have no table read access: they resolve one trigger value at a time through a database function and can never enumerate the inventory. The sensor `nyktus-sensor` runs inside monitored networks and reports to the trigger endpoint.

## Repository layout

```
api/                OpenAPI specification of the console API
cmd/nyktus/         server binary
sensor/             honeypot sensor for monitored networks: a Go module of its own
                    (nyktus.org/nyktus/sensor) with the binary in sensor/cmd/nyktus-sensor
internal/           application packages, organized by domain
catalog/            the deception and artifact catalog, embedded at build time
migrations/         PostgreSQL migrations
web/                web console
deploy/             reference deployment configuration
tools/              generators for embedded data and web types, run by developers, never by the server
docs/development/   contributor documentation and guidelines
docs/public/        the published deception catalog, generated; the documentation site copies it
```

Directories are created when their first code lands. Do not add placeholder files. The one exception is `web/dist/.gitkeep`, which keeps the directory that the embedding of the web console needs, see [Web console](docs/development/engineering.md#web-console).

## Domain language

Use these terms consistently in code, API and documentation:

| Term | Meaning |
|---|---|
| Honeytoken | A trigger primitive (URL, image, QR code, DNS name) that raises an event when it is requested or resolved. Write "honeytoken", not "canary token". |
| Honeypot | A network service emulated by the sensor. |
| Artifact | A template in the catalog for a file that a person places to make a scenario believable. A slot bound to a honeytoken makes it a lure, without one it is pocket litter. An artifact never raises an event itself. |
| Scenario | A group of honeytokens, honeypots and artifacts that together tell one believable story. A resource belongs to at most one scenario or stands alone. |
| Deception | A story in the catalog: honeytokens, persona, a guide and the artifacts it recommends. Applying it creates a scenario with its resources. Deceptions are not runtime objects. |
| Catalog | The versioned collection of deceptions and artifacts, including technique mappings and guides. |
| Event | A single recorded interaction with a honeytoken or honeypot. |
| Incident | Correlated events: one open incident per scenario, or per resource that has no scenario. Triage happens on incidents. |
| Alert | The single notification sent when an incident opens. |

ATT&CK techniques describe attacker behavior and are attached to honeytokens, honeypots, events and incidents. Engage activities describe defender actions and are attached to deceptions and scenarios. A scenario also carries out the lures, pocket litter, artifact diversity and personas that follow from what it holds; an artifact names none, because Engage tells a lure from pocket litter by intent, not by kind of file.

## Non-negotiable invariants

Never weaken these without an explicit decision by a maintainer:

1. Trigger endpoints respond identically for every outcome, carry no product fingerprint and never enumerate the inventory.
2. An event and its processing job are written in one transaction.
3. Health checks never record an event, open an incident or raise an alert.
4. Every route declares its authentication and required permission. Permission is checked before a resource is loaded.
5. Secrets are shown once, masked afterwards, and never logged.
6. Every request to a user-supplied URL goes through the SSRF-guarded client.
7. SQL is parameterized.
8. The catalog is validated before the server starts and never contains executable code.
9. Executable artifact formats receive only server-generated or allowlisted values. Artifacts carry no marker that identifies Nyktus. Decoys only ever cause a passive callback.
10. Nothing is loaded from external sources at runtime, and nothing phones home.

## Working rules

- Keep changes within the scope of the task. Report unrelated problems instead of fixing them on the side.
- Do not add a dependency without asking. Explain why the standard library is not enough.
- Write or update tests with every change. A bug fix includes a regression test that fails without the fix.
- Update the documentation when behavior, configuration or the API changes. The user documentation lives in `Nyktus/nyktus-docs`: open the matching pull request there and link the two. That repository copies `api/openapi.yaml` and `docs/public/deception-catalog.json` from a pinned commit of this one, so a change to either needs a new pin there.
- Comments explain *why*, in English. No history, no ticket identifiers, no commented-out code. See [Comments](docs/development/engineering.md#comments).
- Every new source file starts with the SPDX header described in the engineering guidelines.
- Commits follow Conventional Commits and carry a DCO sign-off (`git commit -s`).
- Do not commit secrets, `.env` files or generated build output. The types in `web/src/api/generated.ts` are committed on purpose, see [OpenAPI specification](docs/development/engineering.md#openapi-specification).
- `.localdev/` contains private planning notes. It is not part of the repository. Never reference it from tracked files.

## Commands

| Command | Purpose |
|---|---|
| `make test` | Unit tests with the race detector; database tests are skipped |
| `make db-up` / `make db-down` | Start or stop a disposable PostgreSQL on port 55432 |
| `make test-db` | All tests, including database tests, with the race detector |
| `make test-fast` | All tests, including database tests, without the race detector |
| `make lint` | Linters and formatting checks |
| `make fmt` | Format the code |
| `make check` | Lint, unit tests, vulnerability scan and `go.mod` check |
| `make dev-up` / `make dev-down` / `make dev-reset` | Start, stop or reset the development environment in `deploy/dev/` (Docker Compose: PostgreSQL and all server roles, built from the working tree) |
| `make build` | Build the web console, then `bin/nyktus` and `bin/nyktus-sensor` |
| `make web-build` / `web-lint` / `web-test` / `web-audit` | Build, type-check and test the web console in `web/`, and audit its packages (need Node.js) |

The sensor is a second Go module without a `go.work`; the targets above that check Go code run for both modules. Run `make lint` and `make test-db` before you consider a change complete. Tool versions are pinned in the `Makefile`; do not install linters globally or add tools to `go.mod`.
