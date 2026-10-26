# Internal name that points to a honeytoken

A name in your internal DNS zone, `vault.corp.example.com`, points with a CNAME record to the DNS honeytoken `targetq3xwz7a2kfm4ub6tyc5nre.d.example.net`. Whoever looks up the alias, because it stands in a list of names, a scan finds it or they try the name, makes the internal resolver look up the honeytoken, which raises an event. There is no service behind the name, and no file to place.

## Creating the alias

1. Choose a name that invites a visit, such as `vault`, `backup01` or `adminportal`, and enter it as the persona.
2. Create a CNAME record in the internal zone `corp.example.com` from `vault` to `targetq3xwz7a2kfm4ub6tyc5nre.d.example.net.`, with the final dot. On a Windows DNS server: `Add-DnsServerResourceRecordCName -Name 'vault' -HostNameAlias 'targetq3xwz7a2kfm4ub6tyc5nre.d.example.net.' -ZoneName 'corp.example.com'`. In a BIND zone file: `vault IN CNAME targetq3xwz7a2kfm4ub6tyc5nre.d.example.net.`
3. Make sure that the internal resolvers can resolve names on the internet. Otherwise the lookup never reaches the DNS role of Nyktus.
4. Record the alias in the notes of the scenario.

## Testing

Run `nslookup vault.corp.example.com` on a computer that uses the internal DNS server. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A resolver that answers from its cache, or that cannot resolve names on the internet, prevents it.
- Whoever lists the zone, or asks for a zone transfer, sees the alias and its target without a lookup of the target. The target is a random label under the zone of your DNS role, and an intruder who reads the record can find it unusual.
- A tool of your own that resolves all names of the zone, such as an inventory or a monitoring system, raises an event as well. Exclude the alias from it.
