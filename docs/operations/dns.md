# DNS honeytokens

A DNS honeytoken is a host name that nobody has a reason to resolve. Place it where a tool would look it up before it connects: as a host in an SSH configuration, a database connection string, a VPN profile, a mapped drive or a script. Whoever uses the tool resolves the name, and Nyktus records an event, even if the connection then fails, and even on a host without access to the web: a lookup reaches Nyktus through the resolvers of the network.

For this, Nyktus answers one or more zones as their authoritative name server. This is the role `dns` of the server.

## Zones

A zone is a domain that you delegate to Nyktus, such as `d.example.net`. Every DNS honeytoken has its trigger value as a name under each zone, such as `q3xwz7a2kfm4ub6tyc5nre2lpa.d.example.net`, and the console lists these names as `trigger_names`. Names with further labels in front, such as `vpn.q3xwz7a2kfm4ub6tyc5nre2lpa.d.example.net`, count as well; the event records the labels in front.

Set the zones as `NYKTUS_DNS_ZONES` for both the console, which shows the names, and the DNS role, which answers them. See [Configuration](configuration.md#role-dns).

Choose zones with the same care as the [address of the trigger](honeytokens.md#choosing-the-address-of-the-trigger): whoever finds a name sees its zone.

- **Inconspicuous.** Use a domain that neither names Nyktus nor suggests a decoy, ideally one that does not reveal your organization either, such as a neutral domain of its own.
- **Fitting the placement.** With several zones, you can choose the name that fits where you place it, for example a domain that sounds internal for a configuration file.
- **Stable.** A placed name stops being recorded once its zone is removed. To move to a new zone, add it to the list, place names under it, and remove the old zone once no name under it is placed any more.
- **Separate from the console and the trigger.** No zone may hold the host of the console or of the trigger; Nyktus refuses to start otherwise. A zone may contain neither another zone nor its own name servers.

Zones that share name servers are linked: whoever looks at one zone sees the name servers of the other. To keep zones apart, run a DNS role of its own for each, on its own address, with its own `NYKTUS_DNS_ZONES` and `NYKTUS_DNS_NAMESERVERS`, and give the console all zones.

## Delegating a zone

1. Choose host names for the name servers outside the zones, such as `ns1.example.net`, and create address records for them in their own zone, pointing at the public address of the host that runs the DNS role:

   ```
   ns1.example.net.   A     203.0.113.10
   ```

2. In the parent zone of each zone, delegate the zone to these name servers:

   ```
   d.example.net.     NS    ns1.example.net.
   ```

   Two name servers on different hosts and networks keep the zone reachable when one fails. Each runs a DNS role with the same zones.

   If the name servers lie in the parent zone itself, such as `ns1.example.net` for `d.example.net`, the parent zone needs their address records as glue. The registrar or DNS provider of the parent zone creates them together with the delegation.

3. Configure the DNS role with the zones and name servers, and start it with `--roles=dns`:

   ```sh
   NYKTUS_DNS_DATABASE_URL_FILE=/run/secrets/nyktus-dns-db \
   NYKTUS_DNS_ZONES='d.example.net' \
   NYKTUS_DNS_NAMESERVERS='ns1.example.net' \
   NYKTUS_DNS_ANSWER_IPV4='203.0.113.80' \
     nyktus serve --roles=dns
   ```

## Network

Resolvers reach the name servers on port 53 over UDP and TCP. Both are required: answers that do not fit into UDP are repeated over TCP. Allow port 53 from the internet to the host of the DNS role, and nothing else.

The DNS role listens on `127.0.0.1:8053` by default. In a container, map port 53 of the host to it, for example `--publish 53:8053/udp --publish 53:8053/tcp` with `NYKTUS_DNS_ADDR=0.0.0.0:8053`, so that the process needs no privilege to bind port 53. Do not put a resolver or a load balancer in front that rewrites the source address: the event records the address that sent the query.

## Testing

Query a name under the zone directly at the name server, then through the public DNS:

```sh
dig @ns1.example.net q3xwz7a2kfm4ub6tyc5nre2lpa.d.example.net A
dig q3xwz7a2kfm4ub6tyc5nre2lpa.d.example.net A
dig d.example.net NS
```

The first two queries are answered with the flag `aa` and `NYKTUS_DNS_ANSWER_IPV4`, or without an answer if it is not set, and each records an event if the name belongs to an enabled honeytoken. Use a honeytoken created for the test and delete it afterwards: the events of the test stay.

## What the DNS role answers

The DNS role answers every name under its zones in the same way, whether or not it holds the value of a honeytoken, whether the honeytoken is enabled or of which type it is, and whether recording the query failed:

- `A` and `AAAA` receive `NYKTUS_DNS_ANSWER_IPV4` and `NYKTUS_DNS_ANSWER_IPV6`. Without them, and for every other type, the name exists but has no records of the type. Point the addresses at a host you control, such as the reverse proxy of the trigger: a tool that connects to the name then reaches it instead of failing at once.
- `ANY` receives one record set, as RFC 8482 recommends.
- The zone itself answers `SOA` and `NS` with the configured name servers.
- Names outside the zones, queries in another class than `IN`, such as `version.bind` in the class `CHAOS`, and zone transfers are refused. The DNS role is no resolver.

The answer is sent before the query is recorded, so a slow or unreachable database neither delays nor changes it. No answer names Nyktus or its version.

Over UDP, an answer is never larger than three times the query, and each source network (`/24` for IPv4, `/56` for IPv6) may send 20 queries per second, with bursts of 50. Beyond that, every second query receives an empty, truncated answer, which makes a real resolver ask again over TCP, and the others receive nothing. Nyktus remembers a limited number of source networks; while they are all in use, for example during a flood from forged addresses, the queries of every further network are treated the same way together. This keeps the DNS role from being misused to flood a forged source address. Queries over TCP are not limited this way, but connections are limited in number and time.

## Caching

The first lookup of a name always reaches Nyktus: nobody can have cached a name that was never resolved. Resolvers then cache the answer for `NYKTUS_DNS_TTL`, one minute by default, and so do some operating systems. A repeated lookup of the same name through the same resolver within that time is answered from the cache and never reaches Nyktus. This matters for tools that look up the same name again and again, not for the first lookup. A shorter time records more repetitions but causes more queries; `0s` asks resolvers not to cache at all, which not all of them follow.

## The resolver address

An event of the DNS role records the address that sent the query. That is usually a resolver of the network or the provider of whoever looked up the name, such as a corporate resolver or a public one, not the address of their computer. It still tells from which network the lookup came. Nyktus does not store the EDNS client subnet that some resolvers send: whoever sends a query directly can fill it with any address.
