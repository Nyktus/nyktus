## Story

Place access to the virtualization platform and to the backup repository where an intruder looks for it. Whoever holds this access can read or delete the machines and their backups, so it is among the most valuable that an intruder can find. Two files hold it: a PowerShell script that connects to a vCenter server, and a note about the backup repository. Each names a server that belongs to a DNS honeytoken. Whoever uses the credentials looks up the name, which raises an event. Nothing stands behind the names, and the accounts and passwords exist nowhere. One file is enough, and the files need not lie together.

## Setup

Each placeholder in the files stands for one honeytoken:

- `Honeytoken-Domain-VCenter`: "vCenter server", in `Connect-VCenter.ps1`
- `Honeytoken-Domain-Repository`: "Repository server", in `Backup-repository.txt`

1. Create the two DNS honeytokens.
2. Replace each placeholder with the name of its honeytoken. In `Backup-repository.txt`, change the line `Contact` to a team that exists.
3. Place the files where an intruder looks for access to the virtualization or the backups: on an administration server, on the backup server, on a file share of the IT department, or in a folder with scripts in the profile of an account that exists only for this purpose.
4. Do not place `Connect-VCenter.ps1` where a scheduled task or a colleague runs it.
5. Record in the notes of the scenario where you placed the files.

## Testing

On a computer with access to the internet, run `nslookup` with the name of a honeytoken, such as `nslookup Honeytoken-Domain-VCenter`. The names are in the table "Honeytokens of this scenario". Within a minute, the scenario shows an incident. Close the incident after the test.

Opening the share in the Windows Explorer or running the script with VMware PowerCLI has the same effect.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The host names are random labels under the zone of your DNS role. An intruder who reads the files carefully can find them unusual.
- `Connect-VCenter.ps1` needs VMware PowerCLI. Where it is missing, running the script fails before the lookup. The script only reads and sends nothing from the computer on which it runs.
