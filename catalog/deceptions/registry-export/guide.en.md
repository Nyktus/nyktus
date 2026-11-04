# Registry export with backup settings

The file `Settings.reg` is an export of the registry key `HKEY_CURRENT_USER\Software\BackupPro\Backup`. It names the backup server `Honeytoken-Domain`, the account `svc-backup` and a random password. The server name belongs to a DNS honeytoken: whoever uses the settings to reach the server resolves the name, which raises an event. There is no server behind it, and the account and password exist nowhere.

## Placing the file

1. Place the file where an intruder looks for settings of backup software: on a server that is backed up, in a folder with documentation of the IT department, in a backup of a user profile.
2. Rename it after the software if you use another one, and change `Vendor` when you apply the deception, so that the key fits.
3. Do not import the file on a computer that you use. It writes the key to the registry of the account that imports it.
4. Record where you placed it in the notes of the scenario.

## Testing

Resolve the name with `nslookup Honeytoken-Domain` on a computer with access to the internet. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The server name is a random label under the zone of your DNS role. An intruder who reads the file carefully can find it unusual.
- Importing the file creates the key but starts nothing, so an intruder who only imports it does not raise an event. The lookup happens when something connects to the server.
