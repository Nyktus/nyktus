# Database credentials in configuration files

The configuration of an application holds how it reaches its database and its directory. The files below tell this story in different places. The files share the honeytokens of the story, so the same host name appears in every file that names the same service. Nothing stands behind the names: the accounts, tokens and passwords exist nowhere. You decide which files you place and where; one is enough, and they need not lie together.

## Configuration file with database credentials

The file `config.ini` configures the database connection of an application: the host `databaseq3xwz7a2kfm4ub6tyc5nre.d.example.net`, the database `billing`, the account `billing_app` and a random password. The host name belongs to a DNS honeytoken: a client that connects with these values resolves it, which raises an event. There is no database behind it, so the connection fails, and the account and password exist nowhere.

### Placing the file

1. Place the file where an intruder looks for credentials: beside an application on a server, in a repository of configuration, in a deployment directory or in a backup of one.
2. Rename it if the place calls for another name, such as `database.ini` or `settings.ini`.
3. Do not place it where a running application reads it. The application would resolve the name on every start and raise events.
4. Record where you placed it in the placement notes of the artifact.

### Testing

Resolve the host on a computer with access to the internet, for example with `nslookup databaseq3xwz7a2kfm4ub6tyc5nre.d.example.net`. Within a minute, the scenario shows an incident. Close the incident after the test.

## Environment file with secrets of a service

The file `production.env` is the environment file of a service. It holds a database URL with the host `databaseq3xwz7a2kfm4ub6tyc5nre.d.example.net`, the database `billing`, the account `billing_app` and a random password, and two more random secrets. The host name belongs to a DNS honeytoken: a client that connects to the database resolves it, which raises an event. There is no database behind it, and the secrets exist nowhere.

### Placing the file

1. Rename the file to `.env`, or to the name your deployments use, at the place where you put it. The catalog cannot name a file with a leading dot.
2. Place it where an intruder looks for secrets of services: in a repository of a service, in a deployment directory on a server, in a backup of such a directory.
3. Do not place it where a running service reads it. The service would resolve the name on every start and raise events.
4. Record where you placed it in the placement notes of the artifact.

### Testing

Resolve the name with `nslookup databaseq3xwz7a2kfm4ub6tyc5nre.d.example.net` on a computer with access to the internet, or connect with `psql` to the URL. Within a minute, the scenario shows an incident. Close the incident after the test.

## Connection profile for a directory

The file `ldap.ini` configures how an application connects to its directory: the server `directoryq3xwz7a2kfm4ub6tyc5nre.d.example.net`, the bind account `billing_app@corp.example.com` and a random password. The server name belongs to a DNS honeytoken: whoever connects with these values resolves it, which raises an event. There is no directory behind it, so the connection fails, and the account and password exist nowhere.

### Placing the file

1. Place the file where an intruder looks for credentials of applications: beside an application on a server, in a repository of configuration, in a backup of a deployment directory.
2. Rename it if the place calls for another name, such as `directory.ini`.
3. Do not place it where a running application reads it. The application would resolve the name on every start and raise events.
4. Record where you placed it in the placement notes of the artifact.

### Testing

Resolve the name with `nslookup directoryq3xwz7a2kfm4ub6tyc5nre.d.example.net` on a computer with access to the internet. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The host names are random labels under the zone of your DNS role. An intruder who reads the files carefully can find them unusual.
