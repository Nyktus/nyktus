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
    {"key": "JumpHost", "type": "dns", "label": "Jump host", "techniques": ["T1021.004"]}
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
| `honeytokens` | The honeytokens that applying the deception creates, with the techniques that each receives. |
| `persona` | The values that you enter when you apply the deception, so that its files fit your environment. `example` only illustrates a value: a deception has no default, because a value that every installation shares would identify the files as decoys. `host` is a host name, `name` an account name, and `text` free text, which appears only in files that a person reads. |
| `secrets` | Random values, such as passwords, that Nyktus generates when you apply the deception. |
| `artifacts` | The files that the deception renders. A deception without artifacts consists of its guide, for example because you write the document yourself. |

## What the files contain

Files rendered from the catalog never name Nyktus or what they are: the catalog rejects templates whose text contains words such as the product name, "honeytoken" or "decoy". Values that a tool interprets, such as host names in an SSH configuration, can only be host names, account names, URLs of honeytokens or random values, so that no value can add a directive to the file. A file only causes a DNS lookup or an HTTP request; it never runs code on the system that opens it.

The catalog is public, so anyone can read its templates. Enter persona values that fit your environment, and adapt the files to the place where you put them.
