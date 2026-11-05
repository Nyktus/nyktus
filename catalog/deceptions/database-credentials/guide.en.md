## Story

Place the configuration of an application where an intruder looks for credentials. The configuration holds how the application reaches its database and its directory. Each service has a host name that belongs to a DNS honeytoken. A client that connects with these values looks up the name, which raises an event. Nothing stands behind the names, so the connections fail, and the accounts, tokens and passwords exist nowhere. One file is enough, and the files need not lie together.

## Setup

Each placeholder in the files stands for one honeytoken:

- `Honeytoken-Domain-Database`: "Database host", in `config.ini`, `production.env`, `pgpass` and `my.cnf`
- `Honeytoken-Domain-Directory`: "Directory server", in `ldap.ini`

1. Create the two DNS honeytokens.
2. Replace each placeholder with the name of its honeytoken. Adapt the database `billing`, the account `billing_app` and the passwords to your environment.
3. Place the files where an intruder looks for credentials of applications, file by file.
4. `config.ini`, `ldap.ini`: beside an application on a server, in a repository of configuration, in a deployment directory or in a backup of one. Rename them if the place calls for another name, such as `database.ini`.
5. `production.env`: in a repository of a service, in a deployment directory on a server or in a backup of one. Rename it to `.env`, or to the name your deployments use. The catalog cannot name a file with a leading dot.
6. `pgpass`, `my.cnf`: as `.pgpass` and `.my.cnf` in the home directory of an account on an application or administration server. Choose the file that fits the database system you pretend, or place both. Restrict each file that you place to its owner, for example with `chmod 600 ~/.pgpass`, because libpq ignores a `.pgpass` that others can read.
7. Do not place the files where a running application or service reads them, or in the account of a service that connects to a real database. The application would look up the name at every start and raise events.
8. Record in the notes of the scenario where you placed the files.

## Testing

On a computer with access to the internet, run `nslookup` with the name of a honeytoken, such as `nslookup Honeytoken-Domain-Database`. The names are in the table "Honeytokens of this scenario". Within a minute, the scenario shows an incident. Close the incident after the test.

A client has the same effect and fails after the lookup, for example `psql` or `mysql` with the file in place.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The host names are random labels under the zone of your DNS role. An intruder who reads the files carefully can find them unusual.
- Reading a file raises no event; connecting with its values does.
