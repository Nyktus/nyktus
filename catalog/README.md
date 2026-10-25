# Deception catalog

This directory holds the deceptions of Nyktus: blueprints of scenarios, each with the honeytokens it creates, the artifacts it renders and a guide that tells the administrator how to place them. Nyktus embeds the directory when it is built and validates every deception when the server starts; a deception that does not validate keeps the server from starting. `go test ./internal/catalog/...` runs the same validation and compares every rendered artifact and guide with its golden file under `internal/catalog/testdata/golden/`, and the published catalog `docs/public/deception-catalog.json` with what the API returns. After a change, regenerate them with `go test ./internal/catalog/... -update` and review the diff.

The deceptions are licensed under CC BY-SA 4.0, with an additional permission for the files that Nyktus renders from them when it applies them, such as artifacts and guides; see [LICENSE](LICENSE). The permission does not cover other files made from the deceptions, such as the published catalog.

## Layout

Every deception is a directory under `deceptions/`, named after its identifier, such as `ssh-config`. It contains `deception.json` and the templates that it references, nothing else:

```
deceptions/
  ssh-config/
    deception.json
    config.tmpl
    guide.en.md.tmpl
    guide.de.md.tmpl
```

## `deception.json`

```json
{
  "schema_version": 1,
  "id": "ssh-config",
  "category": "network",
  "title": {"en": "...", "de": "..."},
  "summary": {"en": "...", "de": "..."},
  "techniques": ["T1021.004"],
  "engage_activities": ["EAC0005", "EAC0011"],
  "honeytokens": [
    {"key": "JumpHost", "type": "dns", "label": {"en": "Jump host", "de": "Jump-Host"}, "techniques": ["T1021.004"]}
  ],
  "persona": [
    {"key": "Domain", "kind": "host", "label": {"en": "Internal domain", "de": "Interne Domain"}, "example": "corp.example.com"}
  ],
  "secrets": [{"key": "Password", "length": 16}],
  "artifacts": [
    {"key": "config", "file_name": "config", "format": "config", "line_endings": "lf", "template": "config.tmpl"}
  ],
  "guide": {"en": "guide.en.md.tmpl", "de": "guide.de.md.tmpl"}
}
```

Unknown members are an error. `persona`, `secrets`, `artifacts` and the `techniques` of a honeytoken may be empty; every other member is required.

| Member | Rules |
|---|---|
| `schema_version` | `1`. |
| `id` | The name of the directory: lowercase letters and digits, separated by single hyphens, at most 64 characters. |
| `category` | `identity`, `network`, `data`, `endpoint` or `application`. |
| `title`, `summary` | A text in English (`en`) and German (`de`) each: one line, up to 100 and 500 characters. |
| `techniques` | 1 to 20 distinct identifiers of MITRE ATT&CK techniques that a trigger suggests, from the version that Nyktus bundles. |
| `engage_activities` | 1 to 20 distinct engagement activities of MITRE Engage that the deception carries out, such as `EAC0005` (Lures). |
| `honeytokens` | 1 to 10 honeytokens that applying the deception creates, each with a `key`, a honeytoken `type` (`web_url`, `web_image` or `dns`), a `label` in both languages, up to 20 `techniques`, which the honeytoken receives, and optionally a `severity` (`low`, `medium`, `high` or `critical`), without which the honeytoken has the default of its type. Choose `high` for a honeytoken that nobody but an intruder has a reason to use, such as credentials in a file. |
| `persona` | Up to 10 values that the administrator enters when applying the deception, each with a `key`, a `kind` (`host`, `name` or `text`), a `label` and an `example` of that kind, which the console shows. |
| `secrets` | Up to 10 random values of letters and digits that Nyktus generates, each with a `key` and a `length` of 8 to 64. |
| `artifacts` | Up to 20 files that Nyktus renders, each with a `key`, the `file_name` of the download, a `format`, the `line_endings` of the file (`lf`, or `crlf` for files that Windows tools expect with carriage returns, such as `.url` and `.rdp`) and the `template` that renders it. |
| `guide` | The templates of the guide in Markdown, one per language. |

Keys of honeytokens, the persona and secrets start with an uppercase letter and contain letters and digits; keys of artifacts are written like identifiers of deceptions.

## Templates

Templates are UTF-8 with line feeds; carriage returns are rejected, because editors and Git change line endings without notice, and an artifact declares its own. Templates use the syntax of Go's `text/template`, but only a small part of it: text, references to values, and `{{if}}`/`{{else}}` on a value, which is true when the value is not empty. Everything else, such as `{{range}}`, `{{with}}`, `{{template}}`, variables, pipelines and functions, is rejected. Templates are data, not code.

A template references these values:

| Value | Kind | Content |
|---|---|---|
| `{{.Honeytokens.<Key>.URL}}` | `url` | The URL of a honeytoken of the type `web_url` or `web_image`. |
| `{{.Honeytokens.<Key>.Host}}` | `host` | A host name of a honeytoken of the type `dns`. |
| `{{.Persona.<Key>}}` | its kind | A value that the administrator entered. |
| `{{.Secrets.<Key>}}` | `secret` | A random value. |

Values of the kinds `host`, `url`, `name` and `secret` consist only of characters that no supported format treats specially. Free text, of the kind `text`, may appear only in formats that a person reads.

| Format | For | Free text |
|---|---|---|
| `text` | Plain text that a person reads | Written as it is |
| `markdown` | Markdown, such as the guides | Every punctuation character escaped |
| `html` | HTML pages and bookmark files | Escaped by `html/template` for its context |
| `config` | Files that a tool interprets: SSH configurations, INI files, `.netrc`, RDP connections, shortcuts | Not allowed |

## Writing a deception

- **Nothing that reveals the artifact.** The text of an artifact template must not contain `nyktus`, `honeytoken`, `honeypot`, `canary`, `decoy`, `deception` or the identifier of the deception, in any case; the validation rejects it. Guides are read by administrators and may name what the deception is.
- **Nothing distinctive that is the same everywhere.** The catalog is public, so whoever knows it can search for any line that every installation shares. Static text must be what real files of the kind commonly contain. Whatever makes a file fit its environment, such as domains and account names, comes from the persona, which has no default.
- **Only a passive callback.** A deception may only cause a DNS lookup or an HTTP request. It never runs code on the system that opens it.
- **Values stand inside quotes in scripts and data files.** In `.ps1`, `.js`, `.sql`, `.reg`, `.json` and `.tf` templates, every reference to a value sits inside single quotes, double quotes or square brackets; a test checks it. The kinds exclude quote characters, but a name may contain dots and hyphens, which are code outside quotes.
- **Where a honeytoken fires.** A `web_url` fires only for a request to exactly its URL, so a tool that appends a path to a base address, such as `kubectl` or a package manager, needs a `dns` honeytoken. A `dns` honeytoken fires when the name is resolved; labels in front of it, such as `dc01.<name>`, are fine.
- **A guide in both languages** that says where to place the artifacts, how to test them and what limits the deception has. Commands, file names and values are identical in both languages; only the prose is translated.
