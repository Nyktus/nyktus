# Deception catalog

This directory holds the catalog of Nyktus. It consists of **deceptions**, and a deception is a guide for an administrator:

- the **story**: what it pretends to be and what a trigger tells,
- the **guide**: what to create and where to place it, how to test it and what limits it has,
- the **slots** that the guide asks for: honeytokens by type and honeypots by service,
- **example files**, such as a configuration file or a script, which the administrator adapts and places.

Nothing of a deception is rendered, generated or stored when it is applied. Its guide, slots and files are static text that the server reads from the catalog when it shows them, so a change of the catalog shows in every scenario that holds the deception. What applying a deception stores is the identifier, and, if the administrator asks for it, the honeytokens and honeypots of its slots, named after their labels.

Nyktus embeds the directory when it is built and validates every deception when the server starts; a deception that does not validate keeps the server from starting. `go test ./internal/catalog/...` runs the same validation and compares the published catalog `docs/public/deception-catalog.json` with what the API returns. After a change, regenerate it with `go test ./internal/catalog/... -update` and review the diff.

The deceptions are licensed under CC BY-SA 4.0, with an additional permission for the example files that Nyktus serves for download; see [LICENSE](LICENSE). The permission does not cover the guides or other works made from the deceptions, such as the published catalog.

## Layout

Every deception is a directory, named after its identifier, such as `ssh-config`. It contains its definition, its guides and, if it has example files, the directory `files`, and nothing else:

```
deceptions/
  ssh-config/
    deception.json
    guide.en.md
    guide.de.md
    files/
      config
```

Identifiers are lowercase letters and digits, separated by single hyphens, at most 64 characters.

## `deception.json`

```json
{
  "schema_version": 3,
  "id": "ssh-config",
  "category": "network",
  "title": {"en": "...", "de": "..."},
  "summary": {"en": "...", "de": "..."},
  "techniques": ["T1021.004"],
  "engage_activities": ["EAC0005"],
  "honeytokens": [
    {"label": {"en": "Jump host", "de": "Jump-Host"}, "type": "dns", "techniques": ["T1021.004"], "severity": "high"}
  ],
  "honeypots": [
    {"label": {"en": "Database", "de": "Datenbank"}, "service": "postgres"}
  ],
  "files": [
    {"name": "config", "format": "config", "file": "config"}
  ],
  "guide": {"en": "guide.en.md", "de": "guide.de.md"}
}
```

Unknown members are an error. `honeytokens`, `honeypots` and `files` may be empty, but a deception asks for at least one honeytoken or honeypot; every member is required.

| Member | Rules |
|---|---|
| `schema_version` | `3`. |
| `id` | The name of the directory. |
| `category` | `identity`, `network`, `data`, `endpoint`, `application` or `cloud`. |
| `title`, `summary` | A text in English (`en`) and German (`de`) each: one line, up to 100 and 500 characters. |
| `techniques` | 1 to 20 distinct identifiers of MITRE ATT&CK techniques that a trigger suggests, from the version that Nyktus bundles. |
| `engage_activities` | 1 to 20 distinct engagement activities of MITRE Engage that the deception carries out, see below. |
| `honeytokens` | Up to 10 slots for a honeytoken, each with a honeytoken `type` (`web_url`, `web_image` or `dns`), a `label` in both languages of up to 60 characters, which names the honeytoken when it is created, up to 20 `techniques`, which the honeytoken receives, and optionally a `severity` (`low`, `medium`, `high` or `critical`), without which the honeytoken has the default of its type. Choose `high` for a honeytoken that nobody but an intruder has a reason to use, such as credentials in a file. |
| `honeypots` | Up to 10 slots for a honeypot, each with a `service` (`ssh`, `telnet`, `postgres` or `ldap`) and a `label` as for a honeytoken. |
| `files` | Up to 20 example files, each with the `name` under which it is downloaded, a `format` and the `file` in the directory `files` that holds its content. Names are unique, also when compared in lower case, because two names that differ only in case are the same file on Windows and macOS. |
| `guide` | The Markdown file of the guide for each language, one file for each. |

The slots have no keys: the guide tells which honeytoken belongs where, and the label is what names the honeytoken that is created, so two honeytokens, and two honeypots, do not share a label in a language.

## Example files

A file is static text, shipped as it stands, with the line endings that its tool expects (`.gitattributes` keeps them): a PowerShell script has CRLF. It has fixed names and a fixed password, because the catalog does not know the environment of the administrator, who adapts them. A file that holds a honeytoken names it by a placeholder, which is visible on purpose and no host that resolves, so that a file that still holds one is not placed yet:

| Placeholder | Stands for |
|---|---|
| `Honeytoken-Domain` | The host name of a `dns` honeytoken. |
| `Honeytoken-URL` | The URL of a `web_url` or `web_image` honeytoken. |

Where a deception has several honeytokens of a kind, the placeholder names the slot as well, such as `Honeytoken-Domain-Database`, so that no two honeytokens share a word. The guide says which honeytoken belongs to which placeholder. The validation rejects, in files and in guides, a placeholder for a kind of honeytoken that the deception does not have, one that names a slot where the deception has one honeytoken of the kind, and one that does not where it has several.

| Format | For |
|---|---|
| `text` | Plain text that a person reads. Downloaded as `text/plain`. |
| `markdown` | Markdown. Downloaded as `text/markdown`. |
| `html` | HTML pages and bookmark files. Downloaded as `text/html`, as an attachment that is never rendered in the console. |
| `config` | Files that a tool interprets: SSH configurations, INI files, `.netrc`, RDP connections, shortcuts, scripts. Downloaded as `application/octet-stream`. |

A file and a guide are UTF-8 of at most 256 KiB without a NUL, a control character other than a line break or a tab, and a byte order mark.

Scripts that create accounts, such as the ones of the directory, are no files: they stand in the guide as code blocks. A script that creates a real account generates its password when it runs and keeps it nowhere.

## Engage activities

MITRE Engage tells a lure from pocket litter by intent, not by kind of file, so the deception names the activities that its files carry out. The validation does not derive them, but a test checks that a deception whose files hold no honeytoken names `EAC0011` (Pocket Litter), that one with files of more than one format names `EAC0022` (Artifact Diversity) and that one with honeytokens names `EAC0005` (Lures). Applying a deception adds its activities to those of the scenario, up to 20.

## Writing a deception

- **Nothing that reveals what a file is.** A name or a text of an example file must not contain `nyktus`, `honeytoken`, `honeypot`, `canary`, `decoy`, `deception`, a short form of a Creative Commons license or the identifier of the deception, in any case, apart from the placeholders; the validation rejects it. Guides are read by administrators and may name what the deception is.
- **Nothing distinctive that is the same everywhere.** The catalog is public, so whoever knows it can search for any line that every installation shares, such as a password. Static text must be what real files of the kind commonly contain, passwords look like the ones that real files hold, and the guide tells the administrator to adapt names and passwords to the environment before a file is placed.
- **Pocket litter says so.** A file without a placeholder is pocket litter: a deception offers it beside its lures to give the files a believable surrounding. Its text contains nothing that every installation would share, such as an IP address.
- **Only a passive callback.** A deception may only cause a DNS lookup or an HTTP request. It never runs code on the system that opens it.
- **Where a honeytoken fires.** A `web_url` fires only for a request to exactly its URL, so a tool that appends a path to a base address, such as `kubectl` or a package manager, needs a `dns` honeytoken. A `dns` honeytoken fires when the name is resolved; labels in front of it, such as `dc01.<name>`, are fine.
- **A guide in both languages** that says what to create, where to place the files, how to test them and what limits the deception has. Commands, file names and values are identical in both languages; only the prose is translated.
