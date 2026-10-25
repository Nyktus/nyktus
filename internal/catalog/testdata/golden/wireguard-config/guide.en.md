# WireGuard configuration for a tunnel

The file `wg0.conf` is the client configuration of a WireGuard tunnel to the gateway `gatewayq3xwz7a2kfm4ub6tyc5nre.d.example.net`. The keys are random values in the form of WireGuard keys. The name of the gateway belongs to a DNS honeytoken: whoever brings up the tunnel with `wg-quick up` or imports the file into a WireGuard client resolves the name, which raises an event. There is no gateway behind it, and the keys exist nowhere.

## Placing the file

1. Place the file where an intruder looks for access to the network: in the home directory of an administrator account that exists only for this purpose, in a folder with VPN profiles on a file share of the IT department, or in a backup of a workstation.
2. Rename it if the place calls for another name, such as `office.conf`. The extension `.conf` must stay.
3. Do not copy it to `/etc/wireguard`: a system service would bring the tunnel up on every start and raise events.
4. Record where you placed it in the placement notes of the artifact.

## Testing

Run `nslookup gatewayq3xwz7a2kfm4ub6tyc5nre.d.example.net` on a computer with access to the internet; `sudo wg-quick up ./wg0.conf` on a computer with WireGuard has the same effect. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The name of the gateway is a random label under the zone of your DNS role. An intruder who reads the file carefully can find it unusual.
- WireGuard resolves the endpoint when the tunnel comes up. An intruder who only reads the file does not raise an event.
