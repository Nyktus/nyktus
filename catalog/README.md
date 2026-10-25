# Deception catalog

This directory holds the catalog of Nyktus. It has two kinds of entries:

- A **deception** is a story: the honeytokens it creates, the values of the persona it asks for, the artifacts it recommends and a guide that tells the administrator what the story is, how to place the files and what limits its trigger has.
- An **artifact** is a template of a file that a person places to make a scenario believable. It asks for its own values of the persona, may generate secrets, and may carry honeytokens in slots. It exists on its own: a deception recommends artifacts, but an artifact needs no deception.

An artifact never raises an event. A slot that is bound to a honeytoken makes the file a lure, because whoever opens it triggers the honeytoken; an artifact without a bound slot is pocket litter.

Nyktus embeds the directory when it is built and validates every entry when the server starts; an entry that does not validate keeps the server from starting. `go test ./internal/catalog/...` runs the same validation and compares every rendered artifact and guide with its golden file under `internal/catalog/testdata/golden/`, and the published catalog `docs/public/deception-catalog.json` with what the API returns. After a change, regenerate them with `go test ./internal/catalog/... -update` and review the diff.

The entries are licensed under CC BY-SA 4.0, with an additional permission for the files that Nyktus renders from them when it applies a deception or renders an artifact, such as artifacts and guides; see [LICENSE](LICENSE). The permission does not cover other files made from the entries, such as the published catalog.

## Layout

Every entry is a directory, named after its identifier, such as `ssh-config`. It contains its definition and the templates that it references, nothing else:

```
deceptions/
  ssh-config/
    deception.json
    guide.en.md.tmpl
    guide.de.md.tmpl
artifacts/
  ssh-config/
    artifact.json
    config.tmpl
```

Identifiers are lowercase letters and digits, separated by single hyphens, at most 64 characters. A deception and an artifact may have the same identifier. The identifier of an artifact is unique in the catalog: it names the artifact in the API and in what applying a deception stores. An artifact that belongs to one deception carries its identifier; a deception with several files names them `<deception>-<part>`, such as `postgres-backup-beacon-restore`.

## `deception.json`

```json
{
  "schema_version": 2,
  "id": "ssh-config",
  "category": "network",
  "title": {"en": "...", "de": "..."},
  "summary": {"en": "...", "de": "..."},
  "techniques": ["T1021.004"],
  "engage_activities": ["EAC0005"],
  "honeytokens": [
    {"key": "JumpHost", "type": "dns", "label": {"en": "Jump host", "de": "Jump-Host"}, "techniques": ["T1021.004"]}
  ],
  "persona": [
    {"key": "Domain", "kind": "host", "label": {"en": "Internal domain", "de": "Interne Domain"}, "example": "corp.example.com"}
  ],
  "artifacts": ["ssh-config"],
  "guide": {"en": "guide.en.md.tmpl", "de": "guide.de.md.tmpl"}
}
```

Unknown members are an error. `persona`, `artifacts` and the `techniques` of a honeytoken may be empty; every other member is required.

| Member | Rules |
|---|---|
| `schema_version` | `2`. |
| `id` | The name of the directory. |
| `category` | `identity`, `network`, `data`, `endpoint` or `application`. |
| `title`, `summary` | A text in English (`en`) and German (`de`) each: one line, up to 100 and 500 characters. |
| `techniques` | 1 to 20 distinct identifiers of MITRE ATT&CK techniques that a trigger suggests, from the version that Nyktus bundles. |
| `engage_activities` | 1 to 20 distinct engagement activities of MITRE Engage that the story of the deception carries out, such as `EAC0005` (Lures). Applying the deception adds those that follow from what the scenario holds, see below. |
| `honeytokens` | 1 to 10 honeytokens that applying the deception creates, each with a `key`, a honeytoken `type` (`web_url`, `web_image` or `dns`), a `label` in both languages, up to 20 `techniques`, which the honeytoken receives, and optionally a `severity` (`low`, `medium`, `high` or `critical`), without which the honeytoken has the default of its type. Choose `high` for a honeytoken that nobody but an intruder has a reason to use, such as credentials in a file. |
| `persona` | Up to 10 values that the administrator enters when applying the deception, each with a `key`, a `kind` (`host`, `name` or `text`), a `label` and an `example` of that kind, which the console shows. It holds the values of the recommended artifacts as well. |
| `artifacts` | Up to 20 identifiers of the artifacts that the deception recommends. Applying the deception renders all of them, in this order. |
| `guide` | The templates of the guide in Markdown, one per language. |

Keys of honeytokens and the persona start with an uppercase letter and contain letters and digits.

### Recommending artifacts

A deception binds its honeytokens to the slots of its artifacts by key: the slot `JumpHost` of an artifact takes the honeytoken `JumpHost` of the deception. The catalog is valid only if

- every required slot has a honeytoken of its key, of a type that the slot accepts; an optional slot without a honeytoken stays empty,
- every value of the persona that an artifact asks for is a value of the deception, of the same kind (labels and examples may differ),
- every honeytoken and every value of the persona is referenced by the guide or by an artifact, so that nothing is asked for in vain, and
- no artifact contains the identifier of the deception: it is the same in every installation, like the identifier of the artifact, and
- a value of the persona has one kind in the whole catalog: the persona belongs to the scenario and only grows, so a value that a scenario holds must fit every entry that joins it later.

### Engage activities of a scenario

MITRE Engage tells a lure from pocket litter by intent, not by kind of file, so an artifact names no activities. Applying a deception gives its scenario the activities of the deception and adds those that follow from what the scenario holds:

- `EAC0005` (Lures) for every artifact with a slot that is bound to a honeytoken, which expects an action,
- `EAC0011` (Pocket Litter) for every artifact without a bound slot, which only supports the story,
- `EAC0022` (Artifact Diversity) for artifacts of more than one format, and
- `EAC0012` (Personas) for a persona that is not empty.

Name in `engage_activities` of a deception only what its story carries out beyond that, such as `EAC0009` (Email Manipulation) for a message.

## `artifact.json`

```json
{
  "schema_version": 1,
  "id": "ssh-config",
  "category": "network",
  "title": {"en": "...", "de": "..."},
  "summary": {"en": "...", "de": "..."},
  "slots": [
    {"key": "JumpHost", "accepts": ["dns"], "optional": false}
  ],
  "persona": [
    {"key": "Domain", "kind": "host", "label": {"en": "Internal domain", "de": "Interne Domain"}, "example": "corp.example.com"}
  ],
  "secrets": [{"key": "Password", "length": 16}],
  "file_name": "config",
  "format": "config",
  "line_endings": "lf",
  "template": "config.tmpl",
  "placing": {"en": "placing.en.md.tmpl", "de": "placing.de.md.tmpl"}
}
```

Unknown members are an error. `slots`, `persona` and `secrets` may be empty, and `placing` may be left out; every other member is required. An artifact carries no ATT&CK techniques, because it triggers nothing itself.

| Member | Rules |
|---|---|
| `schema_version` | `1`. |
| `id` | The name of the directory. |
| `category`, `title`, `summary` | As for a deception. |
| `slots` | Up to 10 places for the trigger of a honeytoken, each with a `key`, the types it `accepts` and whether it is `optional`. All types of a slot give the same value, so `dns` (a host name) cannot be combined with `web_url` or `web_image` (a URL). An optional slot may stay empty, which makes the file pocket litter; the template references it only inside `{{if}}` on the same slot, which the validation checks, and renders it empty as well. |
| `persona` | Up to 10 values that the artifact asks for, as for a deception. |
| `secrets` | Up to 10 random values of letters and digits that Nyktus generates when it renders the artifact, each with a `key` and a `length` of 8 to 64. Every artifact generates its own, so two files of a deception do not share a password. Secrets are not stored. |
| `file_name` | The name of the download: no separators, no leading dot or hyphen, no trailing dot or space. |
| `format` | `text`, `markdown`, `html` or `config`, see below. |
| `line_endings` | `lf`, or `crlf` for files that Windows tools expect with carriage returns, such as `.url` and `.rdp`. |
| `template` | The template that renders the file. |
| `placing` | Optional. A short Markdown template per language that tells the administrator where to place this artifact. It may name what the artifact is, like a guide, and may use the values of the artifact. |

Keys of slots, the persona and secrets start with an uppercase letter and contain letters and digits. Every slot, value of the persona and secret must be referenced by the template or the placing text.

## Templates

Templates are UTF-8 with line feeds; carriage returns are rejected, because editors and Git change line endings without notice, and an artifact declares its own. Templates use the syntax of Go's `text/template`, but only a small part of it: text, references to values, and `{{if}}`/`{{else}}` on a value, which is true when the value is not empty. Everything else, such as `{{range}}`, `{{with}}`, `{{template}}`, variables, pipelines and functions, is rejected. Templates are data, not code.

A template references these values:

| Value | Kind | Content |
|---|---|---|
| `{{.Honeytokens.<Key>.URL}}` | `url` | The URL of a honeytoken of the type `web_url` or `web_image`. In an artifact, `<Key>` is the key of a slot. |
| `{{.Honeytokens.<Key>.Host}}` | `host` | A host name of a honeytoken of the type `dns`. |
| `{{.Persona.<Key>}}` | its kind | A value that the administrator entered. |
| `{{.Secrets.<Key>}}` | `secret` | A random value. Artifacts only. |

The guide of a deception references its honeytokens and its persona. Secrets belong to artifacts, so a guide does not name them.

Values of the kinds `host`, `url`, `name` and `secret` consist only of characters that no supported format treats specially. Free text, of the kind `text`, may appear only in formats that a person reads.

| Format | For | Free text |
|---|---|---|
| `text` | Plain text that a person reads | Written as it is |
| `markdown` | Markdown, such as the guides | Every punctuation character escaped |
| `html` | HTML pages and bookmark files | Escaped by `html/template` for its context |
| `config` | Files that a tool interprets: SSH configurations, INI files, `.netrc`, RDP connections, shortcuts | Not allowed |

## Writing an entry

- **Nothing that reveals the artifact.** The text of an artifact template must not contain `nyktus`, `honeytoken`, `honeypot`, `canary`, `decoy`, `deception`, the identifier of the artifact or the identifier of a deception that recommends it, in any case; the validation rejects it. Applying a deception checks the rendered file again, because the persona and the zone of the DNS role reach it. Guides and placing texts are read by administrators and may name what the entry is.
- **Nothing distinctive that is the same everywhere.** The catalog is public, so whoever knows it can search for any line that every installation shares. Static text must be what real files of the kind commonly contain. Whatever makes a file fit its environment, such as domains and account names, comes from the persona, which has no default.
- **Only a passive callback.** A deception may only cause a DNS lookup or an HTTP request. It never runs code on the system that opens it.
- **Values stand inside quotes in scripts and data files.** In `.ps1`, `.js`, `.sql`, `.reg`, `.json` and `.tf` templates, every reference to a value sits inside single quotes, double quotes or square brackets; a test checks it. The kinds exclude quote characters, but a name may contain dots and hyphens, which are code outside quotes.
- **Where a honeytoken fires.** A `web_url` fires only for a request to exactly its URL, so a tool that appends a path to a base address, such as `kubectl` or a package manager, needs a `dns` honeytoken. A `dns` honeytoken fires when the name is resolved; labels in front of it, such as `dc01.<name>`, are fine.
- **A guide in both languages** that says where to place the artifacts, how to test them and what limits the deception has. Commands, file names and values are identical in both languages; only the prose is translated.
- **Secrets differ between files.** An artifact that a deception renders next to another one does not know the secrets of the other, so a password that two files name is not the same in both. Write the artifacts so that this does not matter, or put the password in one file.
