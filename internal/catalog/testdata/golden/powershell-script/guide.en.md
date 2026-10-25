# PowerShell script that maps a share

The file `Map-Share.ps1` connects the share `ops` on the server `shareq3xwz7a2kfm4ub6tyc5nre.d.example.net` with the account `CORP\svc-ops` and lists the ten newest files. The server name belongs to a DNS honeytoken: whoever runs the script, or connects to the share with the credentials, resolves the name, which raises an event. There is no server behind it, so the connection fails, and the account and password exist nowhere. The script only reads from the share and sends nothing from the computer on which it runs.

## Placing the file

1. Place the file where an intruder looks for scripts of administrators: on an administration server, on a file share of the IT department, in a folder with scripts in the profile of an account that exists only for this purpose.
2. Rename it if the place calls for another name, such as `Mount-Ops.ps1`. The extension `.ps1` must stay.
3. Do not place it where a scheduled task or a colleague runs it. Every run would resolve the name and raise an event.
4. Record where you placed it in the placement notes of the artifact.

## Testing

Run `nslookup shareq3xwz7a2kfm4ub6tyc5nre.d.example.net` on a computer with access to the internet; running the script in PowerShell has the same effect. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The server name is a random label under the zone of your DNS role. An intruder who reads the file carefully can find it unusual.
- PowerShell stores the password in the script as text, as many scripts of administrators do. An intruder who runs the script on a computer with the execution policy `Restricted` is stopped before the lookup.
