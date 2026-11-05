## Story

Place the access to a container registry, a Kubernetes cluster and the state of the infrastructure where an intruder looks for it. The configuration of a workstation or build server holds this access. Each service has a host name that belongs to a DNS honeytoken. Whoever uses the access looks up the name, which raises an event. Nothing stands behind the names, so the calls fail, and the accounts, tokens and passwords exist nowhere. One file is enough, and the files need not lie together. The file `README.md` holds no honeytoken. It gives the story a believable surrounding.

## Setup

Each placeholder in the files stands for one honeytoken:

- `Honeytoken-Domain-Registry`: "Registry", in `config.json`
- `Honeytoken-Domain-Api`: "API server", in `config`
- `Honeytoken-Domain-State`: "State backend", in `backend.tf`

1. Create the three DNS honeytokens.
2. Replace each placeholder with the name of its honeytoken.
3. Place the files where an intruder looks for access to the platform, file by file.
4. `config.json`: as `~/.docker/config.json` in the home directory of an account on a build server or workstation, ideally an account that exists only for this purpose, or in a backup of such a directory.
5. `config`: as `~/.kube/config` in the home directory of such an account. Restrict it to its owner with `chmod 600 ~/.kube/config`.
6. `backend.tf`: in a repository or directory with Terraform code that an intruder would read, such as a repository of infrastructure, a folder of an administration server or a backup of such a folder.
7. `README.md`: beside the other files of the story.
8. If the account already has a `config.json`, add the entry for the registry to its `auths` object. If it already has a `~/.kube/config`, add the three entries to its lists. This keeps its other registries and clusters working.
9. Do not place the files where a running build, job or pipeline reads them, or where you run Terraform. Every run would look up the name and raise an event.
10. Record in the notes of the scenario where you placed the files.

## Testing

On a computer with access to the internet, run `nslookup` with the name of a honeytoken, such as `nslookup Honeytoken-Domain-Registry`. The names are in the table "Honeytokens of this scenario". Within a minute, the scenario shows an incident. Close the incident after the test.

The tools have the same effect and fail after the lookup: `docker pull Honeytoken-Domain-Registry/app:latest`, `kubectl --kubeconfig ./config get pods` or `terraform init` in a directory with `backend.tf`.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The host names are random labels under the zone of your DNS role. An intruder who reads the files carefully can find them unusual.
- Reading a file raises no event; using the access does.
