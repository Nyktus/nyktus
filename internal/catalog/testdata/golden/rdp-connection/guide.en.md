# Remote Desktop connection

The file `Server.rdp` is a saved connection of the Remote Desktop client of Windows to the server `serverq3xwz7a2kfm4ub6tyc5nre.d.example.net`, with the account `adm.jdoe@corp.example.com`. The server name belongs to a DNS honeytoken: before the client connects, it resolves the name, which raises an event. There is no server behind it, so the connection fails.

## Placing the file

1. Place the file where an intruder looks for access to further systems, such as the desktop or the documents of an administrative account that exists only for this purpose, a jump server, or a file share of the IT department.
2. Rename it after a server that the intruder would want to reach, such as `Backup server.rdp` or `Domain controller.rdp`. The extension `.rdp` must stay.
3. Record where you placed it in the placement notes of the artifact.

## Testing

Open the file on a Windows computer with access to the internet and click "Connect". Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The server name is a random label under the zone of your DNS role. An intruder who opens the file in a text editor can find it unusual.
