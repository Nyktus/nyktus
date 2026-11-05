## Story

Place connections of administrators where an intruder looks for access to further systems. Four files name servers that do not exist: a Remote Desktop connection, an SSH configuration, an Ansible inventory and a WireGuard configuration. Each server name belongs to a DNS honeytoken. Whoever connects with a file looks up the name, and the lookup raises an event; the connection fails because no server stands behind the name. Two more files, `shell-history.txt` and `Tickets.csv`, hold no honeytoken. They give the story a believable surrounding.

## Setup

Each placeholder in the files stands for one honeytoken:

- `Honeytoken-Domain-Server`: "Server", in `Server.rdp`
- `Honeytoken-Domain-JumpHost`: "Jump host", in `config`
- `Honeytoken-Domain-Application`: "Application server", in `inventory.ini`
- `Honeytoken-Domain-Gateway`: "VPN gateway", in `wg0.conf`

1. Create the four DNS honeytokens.
2. Replace each placeholder with the name of its honeytoken. Adapt account names, the domain `corp.example.com` and passwords to your environment.
3. Place the files where an intruder looks for access: on the desktop of an administrator account that exists only for this purpose, on a jump server, in a repository of automation, or on a file share of the IT department. One file is enough, and the files need not lie together. Place `shell-history.txt` and `Tickets.csv` beside the others.
4. `Server.rdp`: Rename it after a server that an intruder wants to reach, such as `Backup server.rdp`. The extension `.rdp` must stay.
5. `config`: Use it as `~/.ssh/config` only where nobody works, because every `ssh` to a host under `corp.example.com` raises an event. Restrict it to its owner with `chmod 600 ~/.ssh/config`; SSH refuses configuration files that others can write to.
6. `inventory.ini`: Do not place it where you run Ansible, because a run against all hosts looks up the name. The hosts of the group `web` are names under `corp.example.com`; make sure they do not exist in your network.
7. `wg0.conf`: Do not copy it to `/etc/wireguard`, because a system service would bring the tunnel up at every start. The extension `.conf` must stay.
8. Record in the notes of the scenario where you placed the files.

## Testing

On a computer with access to the internet, run `nslookup` with the name of a honeytoken, such as `nslookup Honeytoken-Domain-Server`. The names are in the table "Honeytokens of this scenario". Within a minute, the scenario shows an incident. Close the incident after the test.

If no incident appears, check that the computer resolves names through a resolver that reaches the DNS role of Nyktus, see Limits.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The host names are random labels under the zone of your DNS role. An intruder who reads the files carefully can find them unusual.
- An intruder who only reads a file raises no event; the lookup happens when a program uses the name. WireGuard looks up the endpoint when the tunnel comes up.
