# Scripts and notes of Windows administrators

Administrators of a Windows domain keep scripts and notes: a script that maps a share, a recovery sheet for the local administrator and notes on the backup of group policies. The files share the honeytokens of the story, so the same host name appears in every file that names the same service. Nothing stands behind the names: the accounts, tokens and passwords exist nowhere. You decide which files you place and where; one is enough, and they need not lie together.

## PowerShell script that maps a share

The file `Map-Share.ps1` connects the share `ops` on the server `Honeytoken-Domain-Share` with the account `CORP\svc-ops` and lists the ten newest files. The server name belongs to a DNS honeytoken: whoever runs the script, or connects to the share with the credentials, resolves the name, which raises an event. There is no server behind it, so the connection fails, and the account and password exist nowhere. The script only reads from the share and sends nothing from the computer on which it runs.

### Placing the file

1. Place the file where an intruder looks for scripts of administrators: on an administration server, on a file share of the IT department, in a folder with scripts in the profile of an account that exists only for this purpose.
2. Rename it if the place calls for another name, such as `Mount-Ops.ps1`. The extension `.ps1` must stay.
3. Do not place it where a scheduled task or a colleague runs it. Every run would resolve the name and raise an event.
4. Record where you placed it in the notes of the scenario.

### Testing

Run `nslookup Honeytoken-Domain-Share` on a computer with access to the internet; running the script in PowerShell has the same effect. Within a minute, the scenario shows an incident. Close the incident after the test.

## Recovery sheet for the local administrator

The file `Recovery.txt` is a break-glass sheet: it names the server `Honeytoken-Domain-Host`, the account `Administrator` and a random password. The server name belongs to a DNS honeytoken: whoever connects to the server over RDP or WinRM resolves the name, which raises an event. There is no server behind it, and the password exists nowhere.

### Placing the file

1. Print the sheet or save the file where emergency access is kept: in a folder of the IT department, in the documents of an account that exists only for this purpose, next to the documentation of the domain controllers.
2. Change `Contact` to a number or a team that exists.
3. Record where you placed it in the notes of the scenario.

### Testing

Resolve the name with `nslookup Honeytoken-Domain-Host` on a computer with access to the internet. Within a minute, the scenario shows an incident. Close the incident after the test.

## Notes on the backup of group policies

The file `GPO-Backup.txt` is a note of an administrator about the backups of the group policies. It names the share `\\Honeytoken-Domain-Share\GPOBackups$` and the account `CORP\svc-ops` with a random password. The server name belongs to a DNS honeytoken: whoever opens the share resolves the name, which raises an event. There is no server behind it, and the account and password exist nowhere.

### Placing the file

1. Place the file where an intruder looks for notes of administrators: on a domain controller or administration server, on a file share of the IT department, in the documents of an account that exists only for this purpose.
2. Change `Contact` to a team that exists, so that the note names someone who really works with group policies.
3. Record where you placed it in the notes of the scenario.

### Testing

Open `\\Honeytoken-Domain-Share\GPOBackups$` in the Windows Explorer of a computer with access to the internet, or resolve the name with `nslookup Honeytoken-Domain-Share`. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The host names are random labels under the zone of your DNS role. An intruder who reads the files carefully can find them unusual.
- `Map-Share.ps1`: PowerShell stores the password in the script as text, as many scripts of administrators do. An intruder who runs the script on a computer with the execution policy `Restricted` is stopped before the lookup.
- `GPO-Backup.txt`: The note has no executable content. An event happens only when someone opens the share.
