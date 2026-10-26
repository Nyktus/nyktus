# Documentation of directory and file shares

The documentation of a domain tells an intruder where the file servers and the domain controllers are. The files below are such documentation. The files share the honeytokens of the story, so the same host name appears in every file that names the same service. Nothing stands behind the names: the accounts, tokens and passwords exist nowhere. You decide which files you place and where; one is enough, and they need not lie together.

## Map of the DFS namespaces

The file `DFS-namespaces.txt` lists three namespaces of the domain `corp.example.com` and the file server `fileserverq3xwz7a2kfm4ub6tyc5nre.d.example.net` that serves them. The server name belongs to a DNS honeytoken: whoever opens one of the targets resolves the name, which raises an event. There is no file server behind it.

### Placing the file

1. Place the file where an intruder looks for shares: on a file server or administration server, in a folder with documentation of the IT department, in the documents of an account that exists only for this purpose.
2. Rename the namespaces if they do not fit your organization, and change `Contact` to a team that exists.
3. Record where you placed it in the placement notes of the artifact.

### Testing

Open `\\fileserverq3xwz7a2kfm4ub6tyc5nre.d.example.net\Shared` in the Windows Explorer of a computer with access to the internet, or resolve the name with `nslookup fileserverq3xwz7a2kfm4ub6tyc5nre.d.example.net`. Within a minute, the scenario shows an incident. Close the incident after the test.

## Runbook for checking replication

The file `Replication-check.txt` is a runbook of an administrator for the replication of the domain `corp.example.com`. Two of its commands name the domain controller `controllerq3xwz7a2kfm4ub6tyc5nre.d.example.net`. The name belongs to a DNS honeytoken: whoever runs one of the commands resolves it, which raises an event. There is no controller behind it.

### Placing the file

1. Place the file where an intruder looks for the structure of the domain: on a domain controller or administration server, on a file share of the IT department, in the documents of an account that exists only for this purpose.
2. Change `Contact` to a team that exists.
3. Record where you placed it in the placement notes of the artifact.

### Testing

Resolve the name with `nslookup controllerq3xwz7a2kfm4ub6tyc5nre.d.example.net` on a computer with access to the internet. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The host names are random labels under the zone of your DNS role. An intruder who reads the files carefully can find them unusual.
- `DFS-namespaces.txt`: The namespaces under `corp.example.com` are not created. An intruder who opens one of them finds nothing, and no event happens.
- `Replication-check.txt`: The controller is not part of your domain. An intruder who compares the name with the list of controllers can find it unusual.
