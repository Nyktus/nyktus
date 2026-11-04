# Documentation of directory and file shares

The documentation of a domain tells an intruder where the file servers and the domain controllers are. The files below are such documentation. The files share the honeytokens of the story, so the same host name appears in every file that names the same service. Nothing stands behind the names: the accounts, tokens and passwords exist nowhere. You decide which files you place and where; one is enough, and they need not lie together.

## Map of the DFS namespaces

The file `DFS-namespaces.txt` lists three namespaces of the domain `corp.example.com` and the file server `Honeytoken-Domain-FileServer` that serves them. The server name belongs to a DNS honeytoken: whoever opens one of the targets resolves the name, which raises an event. There is no file server behind it.

### Placing the file

1. Place the file where an intruder looks for shares: on a file server or administration server, in a folder with documentation of the IT department, in the documents of an account that exists only for this purpose.
2. Rename the namespaces if they do not fit your organization, and change `Contact` to a team that exists.
3. Record where you placed it in the notes of the scenario.

### Testing

Open `\\Honeytoken-Domain-FileServer\Shared` in the Windows Explorer of a computer with access to the internet, or resolve the name with `nslookup Honeytoken-Domain-FileServer`. Within a minute, the scenario shows an incident. Close the incident after the test.

## Runbook for checking replication

The file `Replication-check.txt` is a runbook of an administrator for the replication of the domain `corp.example.com`. Two of its commands name the domain controller `Honeytoken-Domain-Controller`. The name belongs to a DNS honeytoken: whoever runs one of the commands resolves it, which raises an event. There is no controller behind it.

### Placing the file

1. Place the file where an intruder looks for the structure of the domain: on a domain controller or administration server, on a file share of the IT department, in the documents of an account that exists only for this purpose.
2. Change `Contact` to a team that exists.
3. Record where you placed it in the notes of the scenario.

### Testing

Resolve the name with `nslookup Honeytoken-Domain-Controller` on a computer with access to the internet. Within a minute, the scenario shows an incident. Close the incident after the test.

## Computer object in the directory

The script `New-ServerObject.ps1` creates the computer object `fs-archive01` in the directory, with the DNS host name `Honeytoken-Domain-Computer`. The host name belongs to a DNS honeytoken: a tool that connects to the computers of the domain by their DNS name resolves it, which raises an event. The server does not exist; the object is the bait, and the file creates it only when someone runs it.

The script:

```powershell
Import-Module ActiveDirectory
New-ADComputer -Name 'fs-archive01' -SamAccountName 'fs-archive01$' -DNSHostName 'Honeytoken-Domain-Computer' -Enabled $true
```

### Placing the file

1. Run the script once yourself, in a PowerShell session with the ActiveDirectory module and an account that may create computer objects.
2. The object lands in the container for new computers. Move it to the organizational unit of your servers, so that it is found among them.
3. Keep the script where the documentation of the directory is, if you want it to be found.
4. Record where you placed it in the notes of the scenario.

### Testing

Check the object with `Get-ADComputer -Identity 'fs-archive01' -Properties DNSHostName`, then resolve the host name with `nslookup Honeytoken-Domain-Computer` on a computer with access to the internet. Within a minute, the scenario shows an incident. Close the incident after the test.

## Pocket litter

The files `Handover.txt` and `Tickets.csv` hold no honeytoken and raise no event, whatever happens to them. They give the story a believable surrounding: place them in the same places as the other files of the story, beside the files that raise an event.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The host names are random labels under the zone of your DNS role. An intruder who reads the files carefully can find them unusual.
- `DFS-namespaces.txt`: The namespaces under `corp.example.com` are not created. An intruder who opens one of them finds nothing, and no event happens.
- `Replication-check.txt`: The controller is not part of your domain. An intruder who compares the name with the list of controllers can find it unusual.
- `New-ServerObject.ps1`: Only a tool that resolves the DNS host name of the object raises an event. Which tools do, and with which method of collection, depends on the tool and its version; this has not been verified for BloodHound or PingCastle.
- `New-ServerObject.ps1`: Inventory and vulnerability scanners that enumerate the directory can resolve the name and raise an event. Exclude the object from them.
