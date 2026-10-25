# Environment file with secrets of a service

The file `production.env` is the environment file of a service. It holds a database URL with the host `databaseq3xwz7a2kfm4ub6tyc5nre.d.example.net`, the database `orders`, the account `orders_app` and a random password, and two more random secrets. The host name belongs to a DNS honeytoken: a client that connects to the database resolves it, which raises an event. There is no database behind it, and the secrets exist nowhere.

## Placing the file

1. Rename the file to `.env`, or to the name your deployments use, at the place where you put it. The catalog cannot name a file with a leading dot.
2. Place it where an intruder looks for secrets of services: in a repository of a service, in a deployment directory on a server, in a backup of such a directory.
3. Do not place it where a running service reads it. The service would resolve the name on every start and raise events.
4. Record where you placed it in the placement notes of the artifact.

## Testing

Resolve the name with `nslookup databaseq3xwz7a2kfm4ub6tyc5nre.d.example.net` on a computer with access to the internet, or connect with `psql` to the URL. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The host name of the database is a random label under the zone of your DNS role. An intruder who reads the file carefully can find it unusual.
