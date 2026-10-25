# Kubernetes configuration with a token

The file `config` is the configuration of `kubectl` for the cluster `prod-eu1`: the API server `apiq3xwz7a2kfm4ub6tyc5nre.d.example.net`, the account `deploy` and a random bearer token. The name of the API server belongs to a DNS honeytoken: every `kubectl` call with this configuration resolves it, which raises an event. There is no cluster behind it, so the call fails, and the token exists nowhere.

## Placing the file

1. Place the file as `~/.kube/config` in the home directory of an account on a workstation or build server, ideally an account that exists only for this purpose, and restrict it to its owner: `chmod 600 ~/.kube/config`.
2. If the account already has a configuration, add the three entries to its lists instead of replacing it, so that its other clusters keep working.
3. Do not place it where a running job reads it. The job would resolve the name on every run and raise events.
4. Record where you placed it in the placement notes of the artifact.

## Testing

Run `kubectl --kubeconfig ./config get pods` on a computer with `kubectl` and access to the internet. The command fails after the lookup. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The name of the API server is a random label under the zone of your DNS role. An intruder who reads the file carefully can find it unusual.
