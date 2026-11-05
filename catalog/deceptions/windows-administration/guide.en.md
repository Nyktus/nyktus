## Story

Place scripts and notes of Windows administrators where an intruder looks for them. Administrators of a Windows domain keep a script that maps a share, a recovery sheet for the local administrator and notes on the backup of group policies. Each file names a server that belongs to a DNS honeytoken. Whoever runs the script or uses the credentials looks up the name, which raises an event. Nothing stands behind the names, so connections fail, and the accounts and passwords exist nowhere. One file is enough, and the files need not lie together.

## Setup

Each placeholder in the files stands for one honeytoken:

- `Honeytoken-Domain-Share`: "File server", in `Map-Share.ps1` and `GPO-Backup.txt`
- `Honeytoken-Domain-Host`: "Server", in `Recovery.txt`

1. Create the two DNS honeytokens.
2. Replace each placeholder with the name of its honeytoken. In `Recovery.txt` and `GPO-Backup.txt`, change the line `Contact` to a team or number that exists, so that the note names someone who works with the subject.
3. Place the files where an intruder looks for notes and scripts of administrators: on an administration server or a domain controller, on a file share of the IT department, next to the documentation of the domain controllers, or in the profile of an account that exists only for this purpose. Print `Recovery.txt` if emergency access is kept on paper.
4. Rename `Map-Share.ps1` if the place calls for another name, such as `Mount-Ops.ps1`. The extension `.ps1` must stay.
5. Do not place `Map-Share.ps1` where a scheduled task or a colleague runs it. Every run would look up the name and raise an event.
6. Record in the notes of the scenario where you placed the files.

## Testing

On a computer with access to the internet, run `nslookup` with the name of a honeytoken, such as `nslookup Honeytoken-Domain-Share`. The names are in the table "Honeytokens of this scenario". Within a minute, the scenario shows an incident. Close the incident after the test.

Running the script in PowerShell, or opening the share `\\Honeytoken-Domain-Share\GPOBackups$` in the Windows Explorer, has the same effect.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The host names are random labels under the zone of your DNS role. An intruder who reads the files carefully can find them unusual.
- `Map-Share.ps1` holds the password as text, as many scripts of administrators do, and only reads from the share. An intruder who runs it on a computer with the execution policy `Restricted` is stopped before the lookup.
- `GPO-Backup.txt` has no executable content. An event happens only when someone opens the share.
