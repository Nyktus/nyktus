## Story

Place documentation of the directory and the file shares where an intruder looks for it. The documentation of a domain tells an intruder where the file servers and the domain controllers are. The files `DFS-namespaces.txt` and `Replication-check.txt`, and the script below, name a host that belongs to a DNS honeytoken. Whoever opens a share or runs a command looks up the name, which raises an event. Nothing stands behind the names. One file is enough, and the files need not lie together. The files `Handover.txt` and `Tickets.csv` hold no honeytoken. They give the story a believable surrounding.

- `DFS-namespaces.txt` lists three namespaces of the domain `corp.example.com` and the file server that serves them.
- `Replication-check.txt` is a runbook of an administrator for the replication of the domain. Two of its commands name a domain controller.
- The script below creates a computer object in the directory, with a DNS host name that belongs to a honeytoken. The server does not exist; the object is the bait.

## Setup

Each placeholder in the files and in the script stands for one honeytoken:

- `Honeytoken-Domain-FileServer`: "File server", in `DFS-namespaces.txt`
- `Honeytoken-Domain-Controller`: "Domain controller", in `Replication-check.txt`
- `Honeytoken-Domain-Computer`: "Computer in the directory", in the script

1. Create the three DNS honeytokens.
2. Replace each placeholder with the name of its honeytoken. Rename the namespaces in `DFS-namespaces.txt` if they do not fit your organization, and replace `Infrastructure team` in `DFS-namespaces.txt`, `Replication-check.txt` and `Handover.txt` with a team that exists.
3. Place the files where an intruder looks for the structure of the domain: on a file server, domain controller or administration server, in a folder with documentation of the IT department, or in the documents of an account that exists only for this purpose.
4. To add the computer object, run the script once yourself, in a PowerShell session with the ActiveDirectory module and an account that may create computer objects:

   ```powershell
   Import-Module ActiveDirectory
   New-ADComputer -Name 'fs-archive01' -SamAccountName 'fs-archive01$' -DNSHostName 'Honeytoken-Domain-Computer' -Enabled $true
   ```

5. The object lands in the container for new computers. Move it to the organizational unit of your servers, so that it is found among them. Keep the script where the documentation of the directory is, if you want it to be found.
6. Record in the notes of the scenario where you placed the files.

## Testing

On a computer with access to the internet, run `nslookup` with the name of a honeytoken, such as `nslookup Honeytoken-Domain-FileServer`. The names are in the table "Honeytokens of this scenario". Within a minute, the scenario shows an incident. Close the incident after the test.

Opening `\\Honeytoken-Domain-FileServer\Shared` in the Windows Explorer has the same effect. Check the computer object with `Get-ADComputer -Identity 'fs-archive01' -Properties DNSHostName`.

## Removing

Remove the computer object with `Remove-ADComputer -Identity 'fs-archive01' -Confirm:$false`. An object that stays is found by inventory scanners and keeps pointing to the name of a honeytoken.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The host names are random labels under the zone of your DNS role. An intruder who reads the files carefully can find them unusual.
- The namespaces under `corp.example.com` are not created. An intruder who opens one of them finds nothing, and no event happens.
- The controller in `Replication-check.txt` is not part of your domain. An intruder who compares the name with the list of controllers can find it unusual.
- Only a tool that resolves the DNS host name of the computer object raises an event. Which tools do, and with which method of collection, depends on the tool and its version; this has not been verified for BloodHound or PingCastle.
- Inventory and vulnerability scanners that enumerate the directory can resolve the name and raise an event. Exclude the object from them.
