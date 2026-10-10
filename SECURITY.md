# Security Policy

Nyktus runs inside sensitive networks and its database describes every decoy in an environment. We treat vulnerability reports with priority.

## Supported versions

Until version 1.0, only the latest release and the `main` branch receive security fixes.

## Reporting a vulnerability

Do not open a public issue, discussion or pull request for a vulnerability.

Report it privately through one of these channels:

1. **GitHub private vulnerability reporting** (preferred): [open a draft advisory](https://github.com/nyktus/nyktus/security/advisories/new).
2. **Email**: [security@nyktus.org](mailto:security@nyktus.org).

Please include:

- the affected component and version or commit,
- a description of the issue and its impact,
- steps to reproduce, ideally a minimal proof of concept,
- any known mitigation.

## What to expect

- An acknowledgement of your report within 7 days.
- An initial assessment within 14 days.
- Coordinated disclosure: we publish an advisory once a fix is available, and no later than 90 days after the report unless we agree on a different timeline with you.
- Credit in the advisory, unless you prefer to remain anonymous.

## Scope

In scope:

- the server, the sensor and the web console,
- the official deception catalog packages, including their signing and import,
- the reference deployment configuration.

We also treat **reliable ways to identify Nyktus decoys or sensors** as vulnerabilities. Publishing a fingerprint would help attackers avoid decoys in every installation, so please report these privately as well.

Out of scope:

- vulnerabilities in third-party dependencies that do not affect Nyktus (please report them upstream),
- findings that require an already compromised administrator account or host,
- volumetric denial of service,
- missing hardening headers without a demonstrated impact.

## Safe harbor

We will not take legal action against anyone who researches and reports a vulnerability in good faith, in line with this policy. Only test against installations you own or are authorized to test.
