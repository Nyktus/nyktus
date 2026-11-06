# Nyktus

The open Cyber-Deception Platform.

Nyktus helps you detect intruders, insider threats and data breaches by placing believable decoys, like honeytokens and honeypots, across your infrastructure.

With a built-in Deception Catalog, Nyktus provides powerful guides for creating realistic decoy scenarios to catch attackers in the act. Every guide is mapped to MITRE ATT&CK techniques and follows the MITRE Engage approach to planning deception.

## Getting started

To try Nyktus on your machine, you need Docker, Make and Git:

```
git clone https://github.com/nyktus/nyktus.git
cd nyktus
make dev-up
```

The command builds the images from the source, starts the server and prints the setup link of the first administrator. Open it in your browser and create the account. The console runs on http://localhost:8080.

This environment is for development and evaluation only. Its passwords are public, so never use it for real data. The documentation describes how to run Nyktus in production.

Refer to our documentation at https://docs.nyktus.org for deception concepts, deployment guides and API reference.

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
