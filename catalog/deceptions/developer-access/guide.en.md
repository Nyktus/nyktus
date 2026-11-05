## Story

Place access that developers leave behind where an intruder looks for it. Developers leave access to internal services in their tools: a note with an API call, the credentials of the Git server and the configuration of the package managers. Each service has a host name that belongs to a DNS honeytoken. Whoever uses the access looks up the name, which raises an event. Nothing stands behind the names, so the calls fail, and the accounts, tokens and passwords exist nowhere. One file is enough, and the files need not lie together. The file `README.md` holds no honeytoken. It gives the story a believable surrounding.

## Setup

Each placeholder in the files stands for one honeytoken:

- `Honeytoken-Domain-Api`: "API host", in `api-call.txt`
- `Honeytoken-Domain-Git`: "Git server", in `git-credentials` and `config`
- `Honeytoken-Domain-Registry`: "Package registry", in `npmrc` and `pip.conf`

1. Create the three DNS honeytokens.
2. Replace each placeholder with the name of its honeytoken. In `api-call.txt`, replace the service `Inventory service` with a service that your organization has, so that the note fits its surroundings.
3. Place the files where an intruder looks for access of developers, file by file.
4. `api-call.txt`: where administrators leave commands for later, such as the notes of an account on a server, a folder with scripts or a wiki export.
5. `git-credentials`: as `.git-credentials` in the home directory of an account on a workstation or build server. Git reads it only where `credential.helper` is set to `store`.
6. `config`: as `.git/config` in a directory with a copy of a repository, such as a checkout on a build server or a backup of one.
7. `npmrc`: as `.npmrc` in the home directory of an account on a workstation or build server, or in the root of a project directory.
8. `pip.conf`: as `~/.config/pip/pip.conf` in the home directory of an account.
9. `README.md`: beside the other files of the story.
10. Do not place `config`, `npmrc` or `pip.conf` where somebody works with Git, npm or pip, or where a build runs them. Every `git fetch`, `npm install` or `pip install` would look up the name and raise an event.
11. Record in the notes of the scenario where you placed the files.

## Testing

On a computer with access to the internet, run `nslookup` with the name of a honeytoken, such as `nslookup Honeytoken-Domain-Registry`. The names are in the table "Honeytokens of this scenario". Within a minute, the scenario shows an incident. Close the incident after the test.

The tools have the same effect and fail after the lookup: `git ls-remote https://Honeytoken-Domain-Git/platform-prod.git` with Git, or `npm install` in a directory with `.npmrc` in place.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The host names are random labels under the zone of your DNS role. An intruder who reads the files carefully can find them unusual.
- Reading a file raises no event; using the access does.
