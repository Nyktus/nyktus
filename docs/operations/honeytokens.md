# Honeytokens

A honeytoken is a URL that nobody has a reason to open. You place it where only an intruder would find it, for example as a link in a document on a file share or as an image in a mail template, and Nyktus records an event when it is requested.

> This version records the events of honeytokens, but neither shows them in the console nor raises alerts yet.

## Types

| Type | Triggered when | Typical placement |
|---|---|---|
| `web_url` | the URL is opened, for example by clicking a link | a link in a document, a wiki page, a bookmark, a configuration file, or a QR code |
| `web_image` | the URL is loaded as an image | an image embedded in a document, a mail or an HTML page, which the viewer loads when it opens it |

A QR code is a `web_url` shown as a QR code: generate the code from its `trigger_url`. A `web_url` redirects the browser after the request, so that a click leads to a page instead of an error; set the target with `redirect_url`.

## The trigger URL

Every honeytoken has a trigger value of 128 random bits, 26 characters of lowercase letters and digits. Its URL is the [address of the trigger](#choosing-the-address-of-the-trigger) followed by the value, such as `https://t.example.net/q3xwz7a2kfm4ub6tyc5nre2lpa`. The URL of a `web_image` ends with `.gif`, such as `https://t.example.net/q3xwz7a2kfm4ub6tyc5nre2lpa.gif`. The response of every request contains both as `trigger_value` and `trigger_url`. Place the `trigger_url` exactly as it is.

The value cannot be changed. If a URL has been exposed to people who should not trigger it, such as in a screenshot, create a new honeytoken, place its URL, and delete the old one.

## Creating a honeytoken

Administrators and users with the role `user` create honeytokens, with a session or with an [API key](api-keys.md) that carries the scope `honeytokens:write`:

```sh
curl --fail-with-body https://nyktus.example.com/api/v1/honeytokens \
  --header 'Content-Type: application/json' \
  --data @honeytoken.json \
  --cookie cookies.txt
```

with `honeytoken.json`:

```json
{
  "type": "web_url",
  "name": "Finance share: Q3 forecast link",
  "notes": "\\\\fs01\\finance\\2026\\Q3 forecast.docx, link on page 2",
  "redirect_url": "https://www.example.com/investors",
  "techniques": ["T1039", "T1083"]
}
```

| Field | Rules |
|---|---|
| `type` | Required. `web_url` or `web_image`. It cannot be changed later. |
| `name` | Required. 1 to 100 printable characters without leading or trailing spaces. |
| `notes` | Optional. Where and why the honeytoken is placed, up to 2000 characters; line breaks and tabs are allowed. Notes help whoever cleans up decoys or triages an incident. |
| `enabled` | Optional, `true` by default. |
| `redirect_url` | Optional, only for `web_url`. An `http` or `https` URL of up to 2048 characters with a lowercase scheme, in printable ASCII: write international host names in their `xn--` form and encode other characters with `%`. The host must be a name, not an IP address, and the URL must not contain user information such as `user@`. Without it, the trigger uses its default target. Whoever opens the URL sees the target, usually outside your network: choose a public page that fits the placement, not an intranet address, which would reveal internal host names. |
| `techniques` | Optional. Up to 20 distinct identifiers of [MITRE ATT&CK](#techniques) techniques or sub-techniques that a request of the URL suggests, such as `T1039` or `T1003.001`. |

The answer is the new honeytoken with status `201`:

```json
{
  "id": "4f1c0f0e-4f5e-4d0a-9f5e-6c1f2b3a4d5e",
  "type": "web_url",
  "name": "Finance share: Q3 forecast link",
  "notes": "\\\\fs01\\finance\\2026\\Q3 forecast.docx, link on page 2",
  "enabled": true,
  "redirect_url": "https://www.example.com/investors",
  "techniques": ["T1039", "T1083"],
  "trigger_value": "q3xwz7a2kfm4ub6tyc5nre2lpa",
  "trigger_url": "https://t.example.net/q3xwz7a2kfm4ub6tyc5nre2lpa",
  "created_at": "2026-10-12T09:30:00Z",
  "updated_at": "2026-10-12T09:30:00Z"
}
```

## Listing, changing and deleting

- `GET /api/v1/honeytokens` lists honeytokens from the newest to the oldest, 50 per page by default and at most 200 (`limit`). To read the next page, pass the `next_cursor` of the response as `cursor`, with the same filters. `type=web_url` or `type=web_image` and `enabled=true` or `enabled=false` narrow the list.
- `GET /api/v1/honeytokens/<id>` returns one honeytoken.
- `PATCH /api/v1/honeytokens/<id>` changes `name`, `notes`, `enabled`, `redirect_url` or `techniques`. Members that you leave out stay unchanged; `"redirect_url": null` removes the redirect, and `"techniques": []` removes the techniques. Disable a honeytoken instead of deleting it while you are unsure whether its URL is still placed somewhere: a disabled honeytoken records no events, but still answers as before.
- `DELETE /api/v1/honeytokens/<id>` deletes a honeytoken. Its events remain. Remove its URL from where you placed it as well: once the honeytoken is deleted, a request of the URL is answered like any unknown URL and no longer recorded.

Every role reads honeytokens; viewers cannot change them.

## What the trigger answers

The trigger answers every request without revealing whether its URL belongs to a honeytoken. Its answer depends only on the form of the URL, never on whether the value exists, whether the honeytoken is enabled or of which type it is, or whether recording the request failed:

- A URL that ends with `.gif` receives a transparent image of one pixel.
- Every other URL receives a redirect (`302`) to the `redirect_url` of its honeytoken, or to the default target `NYKTUS_TRIGGER_DEFAULT_REDIRECT` (see [Configuration](configuration.md#role-trigger)). This includes unknown values, `/`, `/robots.txt` and every other path.

The `redirect_url` is the only difference a client can see, and only someone who already knows the URL sees it. A disabled honeytoken keeps redirecting to its `redirect_url`, so that disabling it changes nothing for whoever opens it. No answer carries a header that names Nyktus, and every answer is sent with `Cache-Control: no-store`, so that a second request reaches the trigger as well.

Put a reverse proxy in front of the trigger. It answers malformed requests, which would otherwise reach the HTTP server of Nyktus, and it can limit the rate of requests. Do not let it add headers that name your organization or software to the answers of the trigger.

## Events

The trigger records an event for every `GET` and `HEAD` request of an enabled honeytoken, whichever form of the URL was requested. Other methods receive the same answer and are not recorded, and neither are requests of disabled honeytokens.

An event holds:

| Field | Content |
|---|---|
| Honeytoken | Its identifier and type, and the [techniques](#techniques) it had when it was requested. The event keeps them when you change or delete the honeytoken. |
| Time | When the trigger recorded the request. |
| Client address | The address of the client, as described in [Client addresses](configuration.md#client-addresses). |
| Method | `GET` or `HEAD`. |
| `User-Agent`, `Referer`, `Accept-Language` | The headers of the request, up to 512, 1024 and 128 bytes. Control characters and invalid characters are replaced. The client chooses these headers, so treat them as claims, not facts. The `Referer` often shows where an image was embedded. |

Nothing else is recorded: no body, no cookies, no other headers.

At most 10 events per honeytoken and minute are recorded, so that a flood of requests for one known URL cannot fill the database. The trigger counts the requests beyond the limit and logs their number once a minute as `trigger: requests not recorded` with the identifier of the honeytoken.

## Choosing the address of the trigger

`NYKTUS_TRIGGER_URL` is the public address of the trigger, and the URL of every honeytoken starts with it. Whoever finds a honeytoken sees it, and so do the systems that loaded it. Choose it with that in mind:

- **Reachable from the internet.** Stolen documents are opened on the infrastructure of the attacker, not in your network. The console, by contrast, stays internal; Nyktus refuses to start if both addresses name the same host.
- **Inconspicuous.** Use a host name that neither names Nyktus nor suggests a decoy, such as `canary` or `honeypot`, and ideally one that does not reveal your organization either. A neutral domain of its own works best.
- **Stable.** The address is part of every placed URL. Changing it later breaks the honeytokens you have already placed.

See [Configuration](configuration.md).

## Techniques

Techniques describe what an attacker is probably doing when they request the URL, for example `T1083` (File and Directory Discovery) for a link in a document on a file share. Nyktus checks the identifiers against MITRE ATT&CK Enterprise in version 19.2, which it ships with; techniques that MITRE revoked or deprecated are rejected. Look up identifiers at [attack.mitre.org](https://attack.mitre.org).

## Who can read honeytokens

Honeytokens and their notes are the most sensitive data of an installation: whoever reads them knows which URLs to avoid. Give integrations that do not manage honeytokens [API keys](api-keys.md) without the scopes `honeytokens:read` and `honeytokens:write`, and grant the role `viewer` only to people who need to see the decoys.

## Audit

The [audit log](audit-log.md) records every creation as `honeytoken.create`, every change as `honeytoken.update` with the names of the changed fields, and every deletion as `honeytoken.delete`. It names the honeytoken by its identifier only, never by its name, notes or URL. A change that changes no value is not recorded. Reads are not recorded.
