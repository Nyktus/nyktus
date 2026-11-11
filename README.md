# Nyktus

The open Cyber-Deception Platform.

Nyktus helps you detect intruders, insider threats and data breaches by placing believable decoys, like honeytokens and honeypots, across your infrastructure.

With a built-in Deception Catalog, Nyktus provides powerful guides for creating realistic decoy scenarios to catch attackers in the act. Every guide is mapped to MITRE ATT&CK techniques and follows the MITRE Engage approach to planning deception.

## Feature highlights

- **Believable decoys.** The built-in catalog turns a story, such as a stolen finance backup, into a scenario with the honeytokens, honeypots and example files it needs.
- **Honeytokens and honeypots in one place.** URLs, images, QR codes and DNS names, plus a lightweight sensor that emulates network services inside your network.
- **Seamless integration.** Nyktus can be integrated into your existing environment. It offers a well documented REST API, and sends you alerts to your favorite channel.
- **Self-hosted.** Run Nyktuson your own infrastructure. No telemetry, no phone-home, no external resources at runtime.

## Getting started

The [quickstart](https://docs.nyktus.org/getting-started/quickstart) runs the released containers with Docker Compose on one machine and takes a honeytoken and a honeypot through to an incident. [Deploy](https://docs.nyktus.org/operate/deploy) describes an installation that holds real data.

Refer to our documentation at https://docs.nyktus.org for deception concepts, deployment guides and API reference.

## Build from source

You need Go 1.26 or later, Node.js 24, Docker, Make and Git. To build a release instead of the current development state, check out its tag first.

The shortest way to try your own build is the development environment:

```
git clone https://github.com/nyktus/nyktus.git
cd nyktus
make dev-up
```

The command builds the images from the source, starts the server and prints the setup link of the first administrator. Open it in your browser and create the account. The console runs on http://localhost:8080. This environment is for development and evaluation only. Its passwords are public, so never use it for real data.

To run the binaries yourself, build them and start a disposable PostgreSQL on port 55432, whose data is gone when the container stops (`make db-down`):

```
make build
make db-up
```

Create the group roles, the owner, the database and the logins:

```
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

```
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

## Why deception

Log-based detection collects everything and searches for the needle afterwards. Deception works the other way round: you place signals that have no legitimate use. Nobody opens a decoy SSH config by accident, and nobody resolves a DNS name that only exists inside a backup archive. When a decoy fires, someone is where they should not be.

This makes Nyktus a good fit for teams without a security operations center, and a low-noise source for teams that already run a SIEM.

## What Nyktus provides

- **Honeytokens** (often called canary tokens): URLs, images, QR codes and DNS names that fire when they are requested or resolved.
- **Honeypots**: a lightweight sensor that emulates network services inside your environment and reports every attacker session.
- **Scenarios**: honeytokens and honeypots grouped into one coherent story, such as a stolen finance backup.
- **Deception catalog**: ready-made guides for believable scenarios, from credential files and configuration snippets to documents and cloud credentials, each with the honeytokens and honeypots it asks for and example files to adapt. The catalog ships with Nyktus. Every guide is mapped to MITRE ATT&CK techniques and follows the MITRE Engage approach to planning deception.
- **Incidents**: every interaction is recorded as an event. Events are grouped into one incident per scenario, or per honeytoken or honeypot that stands alone. You get one alert per incident, not one per request.
- **Alerting**: delivery by email and webhook, plus integrations for common chat tools.

## Design principles

- **Self-hosted and compact.** Your decoy inventory never leaves your infrastructure. Nyktus needs nothing but PostgreSQL. There is no telemetry, no phone-home and no external resource loaded at runtime.
- **High signal.** A decoy has no legitimate use, so every alert deserves attention.
- **Out-of-band.** The console and the alert path belong outside the environment they watch. An attacker who controls the monitored network should neither see which assets are decoys nor be able to suppress the alert. The internet-facing trigger endpoints can run on a separate host and cannot enumerate the decoy inventory.
- **Secure by default.** Security is a property of the code, not a configuration option. See the [secure coding guidelines](docs/development/secure-coding.md).

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md) first.

## Security

Please do not report vulnerabilities through public issues. See [SECURITY.md](SECURITY.md).

## License

Nyktus is licensed under the [GNU Affero General Public License v3.0 or later](LICENSE). The deception catalog in `catalog/` is licensed under CC BY-SA 4.0, with an additional permission that lets you use generated decoys without attribution. Third-party data that Nyktus ships, such as MITRE ATT&CK, is listed with its notices in [NOTICE](NOTICE).

MITRE, ATT&CK and MITRE Engage are trademarks of The MITRE Corporation. Nyktus is not affiliated with or endorsed by MITRE.
