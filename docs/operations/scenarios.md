# Scenarios

A scenario groups the decoys that tell one story, such as the honeytokens placed on one file share or in the configuration of one admin workstation. An attacker who follows the story triggers several of them; Nyktus correlates their events into one [incident](incidents.md) with one alert, instead of one incident per honeytoken.

A honeytoken belongs to at most one scenario or stands alone. Scenarios belong to the team, not to the account that created them.

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

The answer contains the scenario with its `id` and `deception_id`, which is `null` for a scenario put together by hand. Applying a deception of the [catalog](catalog.md) will set it to the deception the scenario was created from; a later change of the catalog does not change the scenario.

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

## Incidents

The events of every honeytoken of a scenario join one open [incident](incidents.md#how-events-become-incidents) of the scenario, with one alert. The incident and its alert name the scenario as their resource (`resource_type` `scenario`), and `GET /api/v1/incidents?resource_id=<scenario>` lists the incidents of a scenario.

An event belongs to the scenario its honeytoken belonged to when the event was recorded. A honeytoken that joins a scenario while it has an open incident of its own keeps that incident open until it is triaged or closes after its inactivity; its next events join the incident of the scenario. A honeytoken that leaves a scenario opens incidents of its own again. Incidents of a scenario remain when the scenario is deleted.

## Listing, changing and deleting

- `GET /api/v1/scenarios` lists scenarios from the newest to the oldest, 50 per page by default and at most 200 (`limit`). To read the next page, pass the `next_cursor` of the response as `cursor`.
- `GET /api/v1/scenarios/<id>` returns one scenario.
- `PATCH /api/v1/scenarios/<id>` changes `name`, `notes` or `engage_activities`. Members that you leave out stay unchanged; `"engage_activities": []` removes the activities.
- `DELETE /api/v1/scenarios/<id>` deletes a scenario. The parameter `honeytokens` chooses what happens to its honeytokens:
  - `keep`, the default, removes them from the scenario. They stay and stand alone, and their next events open incidents of their own.
  - `delete` deletes them with the scenario. Remove their URLs and names from where you placed them as well: a deleted honeytoken records nothing.

  ```sh
  curl --fail-with-body --request DELETE \
    'https://nyktus.example.com/api/v1/scenarios/<id>?honeytokens=delete' \
    --cookie cookies.txt
  ```

  Events and incidents remain either way. The deletion and every honeytoken it removes take effect together or not at all.

## Who can read scenarios

Every role reads scenarios; `admin` and `user` create, change and delete them. [API keys](api-keys.md) carry the scopes `scenarios:read` and `scenarios:write`; the second requires the first.

Names and notes of scenarios are part of the inventory: they tell where decoys are placed. Give integrations that do not manage scenarios keys without these scopes.

## Audit

The [audit log](audit-log.md) records every creation as `scenario.create`, every change as `scenario.update` with the names of the changed fields, and every deletion as `scenario.delete`. A deletion also records every honeytoken it removes from the scenario as `honeytoken.update` with the field `scenario_id`, or that it deletes as `honeytoken.delete`. Adding a honeytoken to a scenario or removing it is recorded as `honeytoken.update` with the field `scenario_id`. Entries name scenarios and honeytokens by their identifiers only, never by name or notes. A change that changes no value is not recorded. Reads are not recorded.
