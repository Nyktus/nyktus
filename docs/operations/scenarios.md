# Scenarios

A scenario groups the decoys that tell one story, such as the honeytokens placed on one file share or in the configuration of one admin workstation. An attacker who follows the story triggers several of them; Nyktus correlates their events into one [incident](incidents.md) with one alert, instead of one incident per honeytoken.

A honeytoken or a [honeypot](honeypots.md) belongs to at most one scenario or stands alone. Scenarios belong to the team, not to the account that created them.

## Creating a scenario

```sh
curl --fail-with-body https://nyktus.example.com/api/v1/scenarios \
  --header 'Content-Type: application/json' \
  --data '{"name": "Finance file share", "notes": "\\\\fs01\\finance, placed by IT", "engage_activities": ["EAC0005"]}' \
  --cookie cookies.txt
```

| Field | Content |
|---|---|
| `name` | 1 to 100 printable characters without leading or trailing spaces. Names need not be unique. |
| `notes` | Optional, up to 2000 characters, line breaks allowed: the story of the scenario and where its decoys are placed, for the team that triages an incident or cleans up. |
| `engage_activities` | Optional, up to 20 engagement activities of [MITRE Engage](https://engage.mitre.org) that the scenario carries out, such as `EAC0005` (Lures). Nyktus checks them against the Engage version it ships with. |

The answer contains the scenario with its `id` and `deception_id`, which is `null` for a scenario put together by hand, like `language` and `persona`.

## Scenarios of a deception

[Applying a deception](catalog.md#applying-a-deception) of the catalog creates a scenario with its honeytokens, its [artifacts](artifacts.md) and its guide. `GET /api/v1/artifacts?scenario_id=<scenario>` lists its artifacts. Its `deception_id` names the deception, `language` the language of the guide and of the names of its honeytokens, and `persona` the values that it was applied with. They cannot be changed. `GET /api/v1/scenarios/<id>/guide` returns the guide in Markdown, rendered for this scenario; a scenario put together by hand has none and answers `404`.

The scenario is a snapshot: a later change of the catalog changes neither its artifacts nor its guide.

## Adding honeytokens

A honeytoken joins a scenario through an operation of its own, not through a change of the honeytoken, because the scenario decides how its events are correlated:

```sh
curl --fail-with-body --request PUT https://nyktus.example.com/api/v1/honeytokens/<id>/scenario \
  --header 'Content-Type: application/json' \
  --data '{"scenario_id": "<scenario>"}' \
  --cookie cookies.txt
```

- Assigning a honeytoken to the scenario it belongs to changes nothing.
- A honeytoken that belongs to another scenario receives `409` with the code `honeytoken_in_scenario`. Remove it from that scenario first, so that nothing takes a honeytoken from a scenario by mistake.
- A scenario that does not exist receives `422` with the code `scenario_not_found`.
- `DELETE /api/v1/honeytokens/<id>/scenario` removes a honeytoken from its scenario. It stays and stands alone.

The `scenario_id` of a honeytoken shows its scenario, and `GET /api/v1/honeytokens?scenario_id=<scenario>` lists the honeytokens of a scenario. Changing the scenario of a honeytoken needs the permission `honeytokens:write` only: the honeytoken changes, the scenario does not.

## Adding honeypots

A [honeypot](honeypots.md) joins and leaves a scenario in the same way, through `PUT` and `DELETE /api/v1/honeypots/<id>/scenario`, with the same rules; a honeypot that belongs to another scenario receives `409` with the code `honeypot_in_scenario`. `GET /api/v1/honeypots?scenario_id=<scenario>` lists the honeypots of a scenario. Changing the scenario of a honeypot needs the permission `honeypots:write` only.

## Incidents

The events of every honeytoken of a scenario join one open [incident](incidents.md#how-events-become-incidents) of the scenario, with one alert. The incident and its alert name the scenario as their resource (`resource_type` `scenario`), and `GET /api/v1/incidents?resource_id=<scenario>` lists the incidents of a scenario.

An event belongs to the scenario its honeytoken belonged to when the event was recorded. A honeytoken that joins a scenario while it has an open incident of its own keeps that incident open until it is triaged or closes after its inactivity; its next events join the incident of the scenario. A honeytoken that leaves a scenario opens incidents of its own again. Incidents of a scenario remain when the scenario is deleted.

## Listing, changing and deleting

- `GET /api/v1/scenarios` lists scenarios from the newest to the oldest, 50 per page by default and at most 200 (`limit`). To read the next page, pass the `next_cursor` of the response as `cursor`.
- `GET /api/v1/scenarios/<id>` returns one scenario.
- `PATCH /api/v1/scenarios/<id>` changes `name`, `notes` or `engage_activities`. Members that you leave out stay unchanged; `"engage_activities": []` removes the activities.
- `DELETE /api/v1/scenarios/<id>` deletes a scenario. The parameters `honeytokens`, `honeypots` and `artifacts` choose what happens to its honeytokens, honeypots and artifacts, each on its own:
  - `keep`, the default, removes them from the scenario. They stay and stand alone; the next events of the honeytokens and honeypots open incidents of their own, and the [artifacts](artifacts.md) can still be downloaded, for example to find what was placed.
  - `delete` deletes them with the scenario. Remove their URLs, names and files from where you placed them, and stop the honeypots on their sensor, as well: a deleted honeytoken or honeypot records nothing.

  ```sh
  curl --fail-with-body --request DELETE \
    'https://nyktus.example.com/api/v1/scenarios/<id>?honeytokens=delete&honeypots=delete&artifacts=delete' \
    --cookie cookies.txt
  ```

  Events and incidents remain either way. The deletion and every honeytoken, honeypot and artifact it removes take effect together or not at all.

## Who can read scenarios

Every role reads scenarios; `admin` and `user` create, change and delete them. [API keys](api-keys.md) carry the scopes `scenarios:read` and `scenarios:write`; the second requires the first. Deleting a scenario with its honeypots needs `scenarios:write` only, as it does with its honeytokens.

Names, notes, persona and guides of scenarios are part of the inventory: they tell where decoys are placed and what they are called. Give integrations that do not manage scenarios keys without these scopes.

## Audit

The [audit log](audit-log.md) records every creation as `scenario.create`, every change as `scenario.update` with the names of the changed fields, and every deletion as `scenario.delete`. A deletion also records every honeytoken, honeypot and artifact it removes from the scenario as `honeytoken.update`, `honeypot.update` or `artifact.update` with the field `scenario_id`, or that it deletes as `honeytoken.delete`, `honeypot.delete` or `artifact.delete`. Applying a deception records every honeytoken it creates as `honeytoken.create`, the scenario as `scenario.create` and every artifact as `artifact.create`. Adding a honeytoken or a honeypot to a scenario or removing it is recorded as `honeytoken.update` or `honeypot.update` with the field `scenario_id`. Entries name scenarios, honeytokens and honeypots by their identifiers only, never by name or notes. A change that changes no value is not recorded. Reads are not recorded.
