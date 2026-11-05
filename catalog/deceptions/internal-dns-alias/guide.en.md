## Story

Add a name to your internal DNS zone that points to a DNS honeytoken. The name `vault.corp.example.com` is a CNAME record that points to the honeytoken. Whoever looks up the alias makes the internal resolver look up the honeytoken, which raises an event. The lookup happens when the alias stands in a list of names, when a scan finds it or when someone tries the name. There is no service behind the name and no file to place.

## Setup

1. Create the DNS honeytoken "Target of the alias".
2. Choose a name that invites a visit, such as `vault`, `backup01` or `adminportal`. The steps below use `vault`.
3. Create a CNAME record in the internal zone `corp.example.com` from `vault` to `Honeytoken-Domain.`, with the final dot, and replace `Honeytoken-Domain` with the name of the honeytoken. On a Windows DNS server: `Add-DnsServerResourceRecordCName -Name 'vault' -HostNameAlias 'Honeytoken-Domain.' -ZoneName 'corp.example.com'`. In a BIND zone file: `vault IN CNAME Honeytoken-Domain.`
4. If the internal resolvers cannot resolve names on the internet, make them able to. Otherwise the lookup never reaches the DNS role of Nyktus.
5. Record the alias in the notes of the scenario.

## Testing

Run `nslookup vault.corp.example.com` on a computer that uses the internal DNS server. Within a minute, the scenario shows an incident. Close the incident after the test.

If no incident appears, run `nslookup Honeytoken-Domain`, with the name of the honeytoken, to check whether the resolver reaches the DNS role of Nyktus.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A resolver that answers from its cache, or that cannot resolve names on the internet, prevents it.
- Whoever lists the zone, or asks for a zone transfer, sees the alias and its target without a lookup of the target. The target is a random label under the zone of your DNS role, and an intruder who reads the record can find it unusual.
- A tool of your own that resolves all names of the zone, such as an inventory or a monitoring system, raises an event as well. Exclude the alias from it.
