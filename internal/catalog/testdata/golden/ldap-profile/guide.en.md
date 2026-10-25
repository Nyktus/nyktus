# Connection profile for a directory

The file `ldap.ini` configures how an application connects to its directory: the server `directoryq3xwz7a2kfm4ub6tyc5nre.d.example.net`, the bind account `svc-ldap@corp.example.com` and a random password. The server name belongs to a DNS honeytoken: whoever connects with these values resolves it, which raises an event. There is no directory behind it, so the connection fails, and the account and password exist nowhere.

## Placing the file

1. Place the file where an intruder looks for credentials of applications: beside an application on a server, in a repository of configuration, in a backup of a deployment directory.
2. Rename it if the place calls for another name, such as `directory.ini`.
3. Do not place it where a running application reads it. The application would resolve the name on every start and raise events.
4. Record where you placed it in the placement notes of the artifact.

## Testing

Resolve the name with `nslookup directoryq3xwz7a2kfm4ub6tyc5nre.d.example.net` on a computer with access to the internet. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The name of the server is a random label under the zone of your DNS role. An intruder who reads the file carefully can find it unusual.
