# Access to virtualization and backup

The access to the virtualization platform and to the backup repository is among the most valuable that an intruder can find, because whoever holds it can read or delete the machines and their backups. The files below hold it. The files share the honeytokens of the story, so the same host name appears in every file that names the same service. Nothing stands behind the names: the accounts, tokens and passwords exist nowhere. You decide which files you place and where; one is enough, and they need not lie together.

## PowerShell profile for vCenter

The file `Connect-VCenter.ps1` connects to the vCenter server `vcenterq3xwz7a2kfm4ub6tyc5nre.d.example.net` with the account `svc-vmops@vsphere.local` and lists the virtual machines. The name of the server belongs to a DNS honeytoken: whoever runs the script, or connects to the server with the credentials, resolves it, which raises an event. There is no server behind it, so the connection fails, and the account and password exist nowhere. The script only reads and sends nothing from the computer on which it runs.

### Placing the file

1. Place the file where an intruder looks for access to the virtualization: on an administration server, on a file share of the IT department, in a folder with scripts in the profile of an account that exists only for this purpose.
2. Do not place it where a scheduled task or a colleague runs it.
3. Record where you placed it in the placement notes of the artifact.

### Testing

Run `nslookup vcenterq3xwz7a2kfm4ub6tyc5nre.d.example.net` on a computer with access to the internet; running the script with VMware PowerCLI has the same effect. Within a minute, the scenario shows an incident. Close the incident after the test.

## Notes on the backup repository

The file `Backup-repository.txt` is a note of an administrator about the repository of the backups. It names the share `\\repositoryq3xwz7a2kfm4ub6tyc5nre.d.example.net\Repository` and the account `CORP\svc-vmops` with a random password. The server name belongs to a DNS honeytoken: whoever opens the share resolves it, which raises an event. There is no server behind it, and the account and password exist nowhere. Intruders who prepare ransomware look for exactly this.

### Placing the file

1. Place the file where an intruder looks for the backups: on the backup server, on an administration server, on a file share of the IT department.
2. Change `Contact` to a team that exists.
3. Record where you placed it in the placement notes of the artifact.

### Testing

Open `\\repositoryq3xwz7a2kfm4ub6tyc5nre.d.example.net\Repository` in the Windows Explorer of a computer with access to the internet, or resolve the name with `nslookup repositoryq3xwz7a2kfm4ub6tyc5nre.d.example.net`. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The host names are random labels under the zone of your DNS role. An intruder who reads the files carefully can find them unusual.
- `Connect-VCenter.ps1`: The script needs VMware PowerCLI. Where it is missing, running the script fails before the lookup.
