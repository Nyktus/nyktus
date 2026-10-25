# PowerShell profile for vCenter

The file `Connect-VCenter.ps1` connects to the vCenter server `vcenterq3xwz7a2kfm4ub6tyc5nre.d.example.net` with the account `svc-vmops@vsphere.local` and lists the virtual machines. The name of the server belongs to a DNS honeytoken: whoever runs the script, or connects to the server with the credentials, resolves it, which raises an event. There is no server behind it, so the connection fails, and the account and password exist nowhere. The script only reads and sends nothing from the computer on which it runs.

## Placing the file

1. Place the file where an intruder looks for access to the virtualization: on an administration server, on a file share of the IT department, in a folder with scripts in the profile of an account that exists only for this purpose.
2. Do not place it where a scheduled task or a colleague runs it.
3. Record where you placed it in the placement notes of the artifact.

## Testing

Run `nslookup vcenterq3xwz7a2kfm4ub6tyc5nre.d.example.net` on a computer with access to the internet; running the script with VMware PowerCLI has the same effect. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The name of the server is a random label under the zone of your DNS role. An intruder who reads the file carefully can find it unusual.
- The script needs VMware PowerCLI. Where it is missing, running the script fails before the lookup.
