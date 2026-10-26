# Access to registry, cluster and infrastructure state

The configuration of a workstation or build server holds the access to the container registry, the Kubernetes cluster and the state of the infrastructure. The files below tell this story in different places. The files share the honeytokens of the story, so the same host name appears in every file that names the same service. Nothing stands behind the names: the accounts, tokens and passwords exist nowhere. You decide which files you place and where; one is enough, and they need not lie together.

## Docker configuration with registry credentials

The file `config.json` is the configuration of the Docker client. It holds the account `ci-pull` and a random password for the registry `registryq3xwz7a2kfm4ub6tyc5nre.d.example.net`. The name belongs to a DNS honeytoken: whoever pulls an image from the registry, pushes to it or signs in resolves the name, which raises an event. There is no registry behind it, and the account and password exist nowhere.

### Placing the file

1. Place the file as `~/.docker/config.json` in the home directory of an account on a build server or workstation, ideally an account that exists only for this purpose, or in a backup of such a directory.
2. If the account already has a `config.json`, add the entry for the registry to its `auths` object instead of replacing the file.
3. Do not place it where a running build reads it. The build would resolve the name on every run and raise events.
4. Record where you placed it in the placement notes of the artifact.

### Testing

Run `docker pull registryq3xwz7a2kfm4ub6tyc5nre.d.example.net/app:latest` on a computer with access to the internet. The command fails after the lookup. Within a minute, the scenario shows an incident. Close the incident after the test.

## Kubernetes configuration with a token

The file `config` is the configuration of `kubectl` for the cluster `prod-eu1`: the API server `apiq3xwz7a2kfm4ub6tyc5nre.d.example.net`, the account `ci-pull` and a random bearer token. The name of the API server belongs to a DNS honeytoken: every `kubectl` call with this configuration resolves it, which raises an event. There is no cluster behind it, so the call fails, and the token exists nowhere.

### Placing the file

1. Place the file as `~/.kube/config` in the home directory of an account on a workstation or build server, ideally an account that exists only for this purpose, and restrict it to its owner: `chmod 600 ~/.kube/config`.
2. If the account already has a configuration, add the three entries to its lists instead of replacing it, so that its other clusters keep working.
3. Do not place it where a running job reads it. The job would resolve the name on every run and raise events.
4. Record where you placed it in the placement notes of the artifact.

### Testing

Run `kubectl --kubeconfig ./config get pods` on a computer with `kubectl` and access to the internet. The command fails after the lookup. Within a minute, the scenario shows an incident. Close the incident after the test.

## Terraform backend with credentials

The file `backend.tf` configures an HTTP backend for the state of the project `platform-prod` on `stateq3xwz7a2kfm4ub6tyc5nre.d.example.net`, with the account `ci-pull` and a random password. The host name belongs to a DNS honeytoken: `terraform init`, `plan` and `apply` resolve it, which raises an event. There is no backend behind it, so the commands fail, and the account and password exist nowhere.

### Placing the file

1. Place the file in a repository or directory with Terraform code that an intruder would read: a repository of infrastructure, a folder of an administration server, a backup of such a folder.
2. Do not place it in a directory in which you or a pipeline run Terraform. Every run would resolve the name and raise an event.
3. Record where you placed it in the placement notes of the artifact.

### Testing

Run `terraform init` in a directory with the file on a computer with Terraform and access to the internet. The command fails after the lookup. Within a minute, the scenario shows an incident. Close the incident after the test.

## Pocket litter

The file `README.md` holds no honeytoken and raises no event, whatever happens to it. It gives the story a believable surrounding: place it in the same place as the other files of the story, beside the files that raise an event.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The host names are random labels under the zone of your DNS role. An intruder who reads the files carefully can find them unusual.
