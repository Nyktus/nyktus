# Artifacts

An artifact is a file that [applying a deception](catalog.md#applying-a-deception) renders for its scenario, such as an SSH configuration that names a [DNS honeytoken](dns.md) or a Windows shortcut to a URL honeytoken. You place it where an intruder looks. An artifact raises no event itself: the honeytokens it names do, when someone uses the file.

Artifacts are stored, so that you can download them again, see where you placed them, and find them when you clean up. They have a page of their own instead of a section of [scenarios](scenarios.md), because they outlive their scenario when it is deleted and they are kept, and because they have permissions of their own.

## Listing and reading artifacts

The web console lists artifacts on a page of their own and on the page of their scenario. The page of an artifact downloads the file, shows its content as text if it is text (a text, Markdown or HTML file; a configuration file is only downloaded), and lets administrators and users note where the file was placed and delete it. The console never opens an artifact: it saves the file for you, and shows an HTML file only as text, because such a file would otherwise run with the rights of your session.

- `GET /api/v1/artifacts` lists artifacts from the newest to the oldest, without their content, 50 per page by default and at most 200 (`limit`). To read the next page, pass the `next_cursor` of the response as `cursor`, with the same filter. `scenario_id=<scenario>` narrows the list to the artifacts of a scenario.
- `GET /api/v1/artifacts/<id>` returns one artifact without its content.

| Field | Content |
|---|---|
| `scenario_id` | The scenario that applying the deception created, or `null` once it was deleted and the artifact kept. |
| `deception_artifact` | The key of the file in its deception, such as `config`. |
| `file_name` | The name under which the file is downloaded. |
| `format` | `text` or `markdown` for files that a person reads, `html` for a page that a browser opens, `config` for a file that a tool reads, such as an SSH configuration, a `.netrc` or a shortcut. |
| `media_type` | The media type of the download. |
| `size` | The length of the content in bytes, at most 1 MiB. |
| `placement_notes` | Where you placed the file. |

## Downloading an artifact

```sh
curl --fail-with-body --remote-name --remote-header-name \
  https://nyktus.example.com/api/v1/artifacts/<id>/content \
  --cookie cookies.txt
```

The content comes as a file to save (`Content-Disposition: attachment` with the file name), with the media type of its format, `X-Content-Type-Options: nosniff` and `Content-Security-Policy: default-src 'none'; sandbox`: a browser saves an HTML artifact instead of showing it, and one that shows it anyway runs no script, not in the origin of the console, and loads nothing. Files that a tool reads are offered as `application/octet-stream`. Line endings are those that the file needs, such as CRLF for Windows shortcuts.

The content is what applying the deception rendered, including the passwords and other secrets that it generated. It never changes: a later release of Nyktus with a changed catalog does not render it again.

## Placement notes

```sh
curl --fail-with-body --request PATCH https://nyktus.example.com/api/v1/artifacts/<id> \
  --header 'Content-Type: application/json' \
  --data '{"placement_notes": "~/.ssh/config of the account svc_backup on jump01"}' \
  --cookie cookies.txt
```

`placement_notes` hold up to 2000 characters; line breaks and tabs are allowed, and an empty string removes them. Nothing else of an artifact can be changed: its content, name and format are what was rendered, and it leaves its scenario only when the scenario is deleted. Record every place, so that the file can be found and removed when the scenario ends.

## Deleting artifacts

`DELETE /api/v1/artifacts/<id>` deletes an artifact. [Deleting a scenario](scenarios.md#listing-changing-and-deleting) keeps its artifacts by default, so that you can still find what was placed; `artifacts=delete` deletes them with it. Deleting an artifact does not remove the file from where you placed it, and the honeytokens it names still raise events until you delete or disable them.

## Who can read artifacts

Every role reads and downloads artifacts; `admin` and `user` change and delete them. [API keys](api-keys.md) carry the scopes `artifacts:read` and `artifacts:write`. `artifacts:write` requires `artifacts:read`, and `artifacts:read` requires `honeytokens:read`, because the content of an artifact names the URLs and host names of honeytokens.

Artifacts are part of the inventory: whoever reads them knows which files are traps. Give integrations that do not place decoys keys without these scopes.

## Audit

The [audit log](audit-log.md) records downloads as `artifacts.read`, at most once per user or API key and minute, like reads of events, without naming the artifact; the [access log](logs.md) names every request. The entry is written before the content is sent; without it, nothing is sent. Reading the list or a single artifact is not recorded. Applying a deception records each artifact as `artifact.create`, a change of the placement notes as `artifact.update` with the field `placement_notes`, and a deletion as `artifact.delete`; a deleted scenario records each artifact that it detaches as `artifact.update` with the field `scenario_id`. These entries name artifacts by their identifiers only, never by file name, content or notes.
