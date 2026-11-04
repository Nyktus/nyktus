# Access that developers leave behind

Developers leave access to internal services in their tools: a note with an API call, the credentials of the Git server and the configuration of the package managers. The files below tell this story in different places. The files share the honeytokens of the story, so the same host name appears in every file that names the same service. Nothing stands behind the names: the accounts, tokens and passwords exist nowhere. You decide which files you place and where; one is enough, and they need not lie together.

## curl command with an API key

The file `api-call.txt` is a note with a `curl` command for the internal service `Inventory service`: it calls `https://Honeytoken-Domain-Api/v1/users` with a random bearer token. The host name belongs to a DNS honeytoken: whoever runs the command resolves it, which raises an event. There is no service behind it, so the command fails, and the token exists nowhere.

### Placing the file

1. Place the file where administrators leave commands for later: in the notes of an account on a server, in a folder with scripts or in a wiki export.
2. Change `Product` to a service that your organization has, so that the note fits its surroundings.
3. Record where you placed it in the notes of the scenario.

### Testing

Run the command on a computer with access to the internet. It fails after the lookup. Within a minute, the scenario shows an incident. Close the incident after the test.

## Git credentials and repository

The file `git-credentials` holds the account `ci-pull` and a random token for the Git server `Honeytoken-Domain-Git`, in the form that the credential helper `store` writes. The file `config` is the configuration of a repository with the remote `https://Honeytoken-Domain-Git/platform-prod.git`. The host name belongs to a DNS honeytoken: whoever clones, fetches or pushes there resolves it, which raises an event. No Git server stands behind it, and the token exists nowhere.

### Placing the file

1. Name the first file `.git-credentials` and place it in the home directory of an account on a workstation or build server. Git reads it only where `credential.helper` is set to `store`.
2. Place the second file as `.git/config` in a directory with a copy of a repository, such as a checkout on a build server or a backup of one.
3. Do not place either where somebody works with Git: every `git fetch` would resolve the name and raise an event.
4. Record where you placed it in the notes of the scenario.

### Testing

Run `git ls-remote https://Honeytoken-Domain-Git/platform-prod.git` on a computer with Git and access to the internet. The command fails after the lookup. Within a minute, the scenario shows an incident. Close the incident after the test.

## Package registries

The file `npmrc` points npm to the registry `Honeytoken-Domain-Registry` and holds a random token. The file `pip.conf` points pip to the same host, with the account `ci-pull` and a random password. The host name belongs to a DNS honeytoken: every use of npm or pip with these files resolves it, which raises an event. No registry stands behind it, and the token and the password exist nowhere.

### Placing the file

1. Name the first file `.npmrc` and place it in the home directory of an account on a workstation or build server, or in the root of a project directory.
2. Place the second file as `~/.config/pip/pip.conf` in the home directory of an account.
3. Do not place either where a build runs npm or pip: every run would resolve the name and raise an event.
4. Record where you placed it in the notes of the scenario.

### Testing

Resolve the host with `nslookup Honeytoken-Domain-Registry` on a computer with access to the internet, or run `npm install` in a directory with the file in place. Within a minute, the scenario shows an incident. Close the incident after the test.

## Pocket litter

The file `README.md` holds no honeytoken and raises no event, whatever happens to it. It gives the story a believable surrounding: place it in the same place as the other files of the story, beside the files that raise an event.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The host names are random labels under the zone of your DNS role. An intruder who reads the files carefully can find them unusual.
