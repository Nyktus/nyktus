# Deception catalog

The catalog holds the deceptions that ship with Nyktus: blueprints of scenarios, such as an SSH configuration whose jump host is a [DNS honeytoken](dns.md), or a guide for an image honeytoken in a Word document. A deception describes the [honeytokens](honeytokens.md) it creates, the values it asks you for so that its files fit your environment, and the files it renders, together with a guide that tells you where to place them and how to test them.

The catalog is part of the server binary and the same in every installation. Nyktus checks it when the console starts: a server whose catalog does not validate does not start. Nothing is loaded at runtime. New deceptions come with new releases of Nyktus; to add your own, put them into `catalog/` and build Nyktus yourself, as `catalog/README.md` describes.

## Reading the catalog

Every role reads the catalog, as do [API keys](api-keys.md) with the scope `catalog:read`. The catalog holds no inventory: it says what deceptions exist, not which ones you use.

- `GET /api/v1/catalog/deceptions` lists every deception, ordered by identifier. The list is complete and not paged.
- `GET /api/v1/catalog/deceptions/<id>` returns one deception with what applying it creates and asks for.

Texts are in English. Add `?lang=de` for German.

```sh
curl --fail-with-body 'https://nyktus.example.com/api/v1/catalog/deceptions/ssh-config?lang=en' \
  --cookie cookies.txt
```

```json
{
  "id": "ssh-config",
  "category": "network",
  "title": "SSH configuration with a jump host",
  "summary": "An SSH client configuration that reaches the hosts of a domain through a jump host. ...",
  "techniques": ["T1021.004"],
  "engage_activities": ["EAC0005", "EAC0011"],
  "honeytokens": [
    {"key": "JumpHost", "type": "dns", "label": "Jump host", "techniques": ["T1021.004"], "severity": "medium"}
  ],
  "persona": [
    {"key": "Domain", "kind": "host", "label": "Internal domain", "example": "corp.example.com"},
    {"key": "Account", "kind": "name", "label": "Account", "example": "j.doe"}
  ],
  "secrets": [],
  "artifacts": [
    {"key": "config", "file_name": "config", "format": "config"}
  ]
}
```

| Field | Meaning |
|---|---|
| `category` | What the deception pretends to be: `identity`, `network`, `data`, `endpoint` or `application`. |
| `techniques` | The [MITRE ATT&CK](honeytokens.md#techniques) techniques that a trigger of the deception suggests. |
| `engage_activities` | The engagement activities of MITRE Engage, version 1.0, that the deception carries out, such as `EAC0005` (Lures) and `EAC0011` (Pocket Litter). |
| `honeytokens` | The honeytokens that applying the deception creates, with the techniques and the [severity](honeytokens.md#severity) that each receives. A deception chooses a higher severity than the default of the type for a honeytoken that nobody but an intruder has a reason to use, such as the host in a `.netrc`. |
| `persona` | The values that you enter when you apply the deception, so that its files fit your environment. `example` only illustrates a value: a deception has no default, because a value that every installation shares would identify the files as decoys. `host` is a host name, `name` an account name, and `text` free text, which appears only in files that a person reads. |
| `secrets` | Random values, such as passwords, that Nyktus generates when you apply the deception. |
| `artifacts` | The files that the deception renders. A deception without artifacts consists of its guide, for example because you write the document yourself. |

## Applying a deception

Applying a deception creates a [scenario](scenarios.md) with its honeytokens and its files, the artifacts, and renders its guide. Administrators and users with the role `user` apply deceptions, with a session or with an [API key](api-keys.md) that carries the scope `scenarios:write`; the permission covers the honeytokens and artifacts that applying creates.

```sh
curl --fail-with-body https://nyktus.example.com/api/v1/catalog/deceptions/ssh-config/apply \
  --header 'Content-Type: application/json' \
  --data '{"name": "Admin workstation ws07", "language": "en", "persona": {"Domain": "corp.example.com", "Account": "j.doe"}}' \
  --cookie cookies.txt
```

| Field | Content |
|---|---|
| `name`, `notes` | The name and the notes of the new scenario, with the rules of a [scenario](scenarios.md#creating-a-scenario). |
| `language` | Optional, `en` by default, or `de`: the language of the guide and of the names of the honeytokens, which are the labels of the deception. |
| `persona` | A value for every value of the persona of the deception, by its key, and nothing else. Each must match its kind: `host` a host name in lowercase letters, digits, hyphens and dots, `name` an account name of up to 64 letters, digits, dots, hyphens and underscores, and `text` one line of up to 200 characters. There are no defaults. |

The answer, with status `201`, contains the `scenario`, its `honeytokens` and its `artifacts`:

- The honeytokens belong to the scenario, are enabled, and have the techniques and the severity of the deception. Change them like any other [honeytoken](honeytokens.md).
- The [artifacts](artifacts.md) are rendered with the URLs of the honeytokens, under the address of the trigger, and the names of DNS honeytokens under the first zone of `NYKTUS_DNS_ZONES`. Secrets, such as passwords, are generated once and exist only in the artifacts. The answer lists the artifacts without their content; download each with `GET /api/v1/artifacts/<id>/content` and record where you placed it in its placement notes.
- `GET /api/v1/scenarios/<id>/guide` returns the guide, rendered for this scenario: where to place the artifacts and how to test them.

Everything is created together or not at all. The scenario is a snapshot: a later release of Nyktus with a changed catalog does not change its artifacts or its guide.

| Status and code | Reason |
|---|---|
| `400` `invalid_request` | A field is invalid; the message names it, for the persona with its key. |
| `404` `not_found` | The catalog has no such deception. |
| `422` `dns_not_configured` | The deception has a DNS honeytoken, but the console knows no zone of the [DNS role](dns.md). Set `NYKTUS_DNS_ZONES` for the console. |
| `422` `artifact_reveals_decoy` | An artifact would contain a word that reveals what it is, such as "canary" or the identifier of the deception. Nyktus checks every artifact it renders, because values that the catalog does not control reach them: the persona, the address of the trigger and the zone of the DNS role. Choose other values; a zone such as `canary.example.com` makes every DNS honeytoken suspicious. |

## What the files contain

Files rendered from the catalog never name Nyktus or what they are: the catalog rejects templates whose text contains words such as the product name, "honeytoken" or "decoy". Values that a tool interprets, such as host names in an SSH configuration, can only be host names, account names, URLs of honeytokens or random values, so that no value can add a directive to the file. A file only causes a DNS lookup or an HTTP request; it never runs code on the system that opens it.

The catalog is public, so anyone can read its templates. Enter persona values that fit your environment, and adapt the files to the place where you put them.
