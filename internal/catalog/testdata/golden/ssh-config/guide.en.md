# SSH configuration with a jump host

The file `config` is an SSH client configuration. It sends every connection to a host under `corp.example.com`, and every connection to `jump`, through the jump host `jumphostq3xwz7a2kfm4ub6tyc5nre.d.example.net`. That name belongs to a DNS honeytoken: before SSH connects, it resolves the name, and the lookup raises an event. The connection itself fails, because the name has no SSH server behind it.

## Placing the file

1. Place the file where an intruder looks for access to further hosts, for example as `~/.ssh/config` of an account on a jump server or an administration workstation, or on a file share among scripts and notes of the IT department.
2. On a system where the file is used as `~/.ssh/config`, restrict it to its owner: `chmod 600 ~/.ssh/config`. SSH refuses configuration files that others can write to.
3. Do not place it where colleagues use it for their own work. Every legitimate `ssh` to a host under `corp.example.com` would raise an event.
4. Record where you placed it in the placement notes of the artifact, so that it can be found again and removed.

## Testing

Run `ssh -F config jump` on a computer that resolves names through the internet. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The name of the jump host is a random label under the zone of your DNS role. An intruder who reads the file carefully can find it unusual.
