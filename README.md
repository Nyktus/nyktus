# Nyktus

Deploy honeytokens and honeypots across your infrastructure to detect intruders, insider threats, data breaches and misconfigured systems. The deception catalog helps you build believable decoys, mapped to MITRE Engage.

> [!IMPORTANT]
> Nyktus is in early development and not ready for production use. Interfaces, configuration and the database schema will change without notice until the first tagged release.

## Why deception

Log-based detection collects everything and searches for the needle afterwards. Deception works the other way round: you place signals that have no legitimate use. Nobody opens a decoy SSH config by accident, and nobody resolves a DNS name that only exists inside a backup archive. When a decoy fires, someone is where they should not be.

This makes Nyktus a good fit for teams without a security operations center, and a low-noise source for teams that already run a SIEM.

## What Nyktus provides

- **Honeytokens** (often called canary tokens): URLs, images, QR codes and DNS names that fire when they are requested or resolved.
- **Honeypots**: a lightweight sensor that emulates network services inside your environment and reports every attacker session.
- **Artifacts**: supporting content that makes a decoy environment believable without firing itself.
- **Scenarios**: honeytokens, honeypots and artifacts grouped into one coherent story, such as a stolen finance backup.
- **Deception catalog**: signed, versioned packages of ready-made blueprints for believable scenarios, from credential files and configuration snippets to documents and cloud credentials. The official catalog ships with Nyktus, and further packages can be imported in full or in part. Every blueprint is mapped to MITRE ATT&CK techniques, and the accompanying guides follow the MITRE Engage approach to planning deception.
- **Incidents**: every interaction is recorded as an event. Events are grouped into one incident per scenario, or per honeytoken or honeypot that stands alone. You get one alert per incident, not one per request.
- **Alerting**: delivery by email and webhook, plus integrations for common chat tools.

## Design principles

- **Self-hosted and compact.** Your decoy inventory never leaves your infrastructure. Nyktus needs nothing but PostgreSQL. There is no telemetry, no phone-home and no external resource loaded at runtime.
- **High signal.** A decoy has no legitimate use, so every alert deserves attention.
- **Out-of-band.** The console and the alert path belong outside the environment they watch. An attacker who controls the monitored network should neither see which assets are decoys nor be able to suppress the alert. The internet-facing trigger endpoints can run on a separate host and cannot enumerate the decoy inventory.
- **Secure by default.** Security is a property of the code, not a configuration option. See the [secure coding guidelines](docs/development/secure-coding.md).

## What deception cannot detect

A honeytoken fires only when someone acts on it: requesting a URL, resolving a DNS name or using a credential. Opening a stolen database dump in a viewer, or reading exfiltrated documents offline, triggers nothing. Nyktus reliably detects the *use* of stolen data and credentials, not the theft itself.

## Getting started

Installation instructions will be published with the first release.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md) first.

## Security

Please do not report vulnerabilities through public issues. See [SECURITY.md](SECURITY.md).

## License

Nyktus is licensed under the [GNU Affero General Public License v3.0 or later](LICENSE). The deception catalog is published separately under CC BY-SA 4.0, with an additional permission that lets you use generated decoys without attribution.

MITRE, ATT&CK and MITRE Engage are trademarks of The MITRE Corporation. Nyktus is not affiliated with or endorsed by MITRE.
