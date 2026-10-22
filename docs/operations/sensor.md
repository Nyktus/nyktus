# Sensor

The sensor `nyktus-sensor` runs the [honeypots](honeypots.md) inside the network you monitor. It listens where you tell it to, answers attackers like the real service would, offers nothing behind the login, and reports every session to the [trigger](configuration.md#role-trigger). It is a separate program from the server, with a configuration file of its own and nothing to share with the server but the secrets of the honeypots: it runs on hosts that attackers can reach, and what it knows is only what it needs to report.

This version emulates the four services of the console: `telnet`, `ssh`, `postgres` and `ldap`.

## What the sensor does and does not do

- It runs as an ordinary user and needs no privilege except a port below 1024, if you choose one.
- It never executes, interprets or passes on what an attacker sends. A Telnet, SSH or PostgreSQL honeypot reads a user name and a password or a public key, counts them and refuses them, and an LDAP honeypot reads a bind and a search and answers the search with nothing. There is no shell, no file, no command, no SQL, no directory entry and no forwarded port.
- It keeps no password. It reports the length of the password and nothing else about it. Of a public key that a client offers it reports the fingerprint.
- It limits everything an attacker can use up: connections, bytes, time and logins. See [Limits](#limits).
- It reads no environment variables for its configuration, loads nothing from the internet and sends nothing anywhere except the reports to your trigger.
- It reports one event for each session of an attacker, when the session ends. The first event of an incident therefore says what the attacker did, not only that it connected.

## Installation

Build the sensor from the source of Nyktus, or install it with the Go toolchain once a release exists:

```sh
make build        # writes bin/nyktus-sensor next to bin/nyktus
go install nyktus.org/nyktus/sensor/cmd/nyktus-sensor@v0.1.0
```

The sensor is a Go module of its own whose `go.mod` names two dependencies: a YAML parser and the SSH library of the Go project, `golang.org/x/crypto`, which speaks the protocol and the cryptography so that the sensor does not. It is one static binary, and you may rename it. `nyktus-sensor version` prints its version: the release for a build from a tag, `devel` otherwise. The sensor tells the trigger this version with every heartbeat, and the console shows it as `sensor_version` of the honeypot.

Update the [server before the sensors](honeypots.md#versions): the server refuses a report of a version it does not know.

## Setting up a sensor

1. [Create the honeypot in the console.](honeypots.md#creating-a-honeypot) The response holds `secret` and `sensor_config`, the entry of the honeypot for the file of the sensor. Both are shown once.
2. Write the configuration file, with the address of your trigger and the entry:

   ```yaml
   trigger_url: https://nyktus.example.com/
   honeypots:
   - id: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d"
     service: "telnet"
     # Address and port to listen on. Ports below 1024 need CAP_NET_BIND_SERVICE.
     listen: ":23"
     secret: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
   ```

   The entry names the usual port of the service. Change `listen` where the host needs another address or port. To run several honeypots on one sensor, add one entry for each; every honeypot has its own secret.
3. Make the file accessible to the user of the sensor only: `chmod 600`. A file that holds a secret and that its group or other users can read or write is refused. The sensor runs on Linux and other Unix systems, where the file modes mean something; it does not support Windows.
4. Check it, then run it:

   ```sh
   nyktus-sensor check -config /etc/nyktus-sensor/sensor.yaml
   nyktus-sensor run -config /etc/nyktus-sensor/sensor.yaml
   ```

   After a start, the honeypot is `online` in the console within seconds, and `sensor_version` shows the version.

The sensor reads its configuration once. Change the file and restart the sensor; it does not reload on a signal.

### Secrets in files

Instead of the secret itself, an entry can name a file that holds it, so that the configuration file can be shared, kept in version control or readable by others:

```yaml
- id: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d"
  service: "telnet"
  listen: ":23"
  secret_file: /etc/nyktus-sensor/telnet.secret
```

Give an entry `secret` or `secret_file`, not both. A relative path is relative to the directory of the configuration file. The file holds the secret and an optional line break, and only its owner may access it (`chmod 600`, or `400`); the sensor checks the mode of the file it has opened, so a file that its group or others can read or write is refused. With a container or a service manager that supplies secrets as files, this is the way to pass them; mount them with a mode of `0400` for the user of the sensor (in Kubernetes `defaultMode: 0400` and `runAsUser`), not `0440` with a group.

## Configuration

The file is YAML. A key that the sensor does not know, a value of the wrong kind and a second document in the file are errors, not ignored. Text values that look like something else in YAML, such as `no` or `123`, stay the text they are.

| Key | Default | Description |
|---|---|---|
| `trigger_url` | required | The public address of your trigger, such as `https://nyktus.example.com/`: the address of [`NYKTUS_TRIGGER_URL`](configuration.md#role-console) without a path. `https` is required outside development. No user information, query or fragment. Reports go to `/`. |
| `environment` | `production` | `production` or `development`. Only `development` allows a `trigger_url` with `http`, which sends the secret in the clear. |
| `log_level` | `info` | `debug`, `info`, `warn` or `error`. |
| `honeypots` | required | One entry for each honeypot, at most 32. |

Every entry of `honeypots`:

| Key | Default | Description |
|---|---|---|
| `id` | required | The identifier of the honeypot in the console. The sensor logs it, so that a record can be tied to the honeypot. |
| `service` | required | `telnet`, `ssh`, `postgres` or `ldap`. |
| `listen` | required | `host:port` or `:port`. The host is an IP address, or empty for every address of both families. The port is written without a sign or a leading zero. `0.0.0.0` takes IPv4 addresses only and `[::]` and an empty host take both. Entries must not conflict: the same port on the same address, on an address and on a wildcard that includes it. |
| `secret` or `secret_file` | one is required | The secret of the honeypot, 43 characters, or the file that holds it. |
| `banner` | by service | What the service says first. For Telnet up to 256 bytes of printable ASCII, with line breaks and tabs; an empty value sends no banner. For SSH the identification string, see [SSH honeypots](#ssh-honeypots). PostgreSQL and LDAP say nothing before a login and take no banner. |
| `login_prompt` | `login: ` | The prompt for the user name, up to 64 bytes of printable ASCII. Telnet only. |
| `host_key_file` | required for `ssh` | The file with the private key of the server. SSH only; see [SSH honeypots](#ssh-honeypots). A relative path is relative to the directory of the configuration file. |

`nyktus-sensor check -config <file>` reads the file the way `run` does and lists every problem it finds: unknown keys, malformed values, duplicate addresses, ids and secrets, a banner that is too long, a host key that is missing, not usable or shared by two honeypots, and the modes of the files. It binds no port and does not contact the trigger.

### Telnet banners

A banner that every installation shares is one that a scanner can look for, so change it to what a device in your network would show. The default is that of a Linux server:

```yaml
banner: "\r\nUbuntu 22.04.4 LTS\r\n"
login_prompt: "login: "
```

The honeypot sends the banner exactly as written: write line breaks as `\r\n` inside double quotes. A switch of a network vendor:

```yaml
banner: "\r\nUser Access Verification\r\n\r\n"
login_prompt: "Username: "
```

The prompt for the password is always `Password: `.

## SSH honeypots

The honeypot speaks the SSH protocol with the library of the Go project, announces the version of a common OpenSSH, and refuses every login. A client can offer a password or a public key. The honeypot records the user name, the length of the password, the fingerprint of every key that the client offers, as `ssh-keygen -l` prints it (`SHA256:...`), and the version string that the client announces. Each password and each offered key is one login of the session, as in OpenSSH, where an offered key counts against `MaxAuthTries`; so is a method that the honeypot does not offer but a client tries anyway, such as keyboard-interactive, which is recorded with the user name only. A key that a client offers twice counts once. A key is only recorded and refused, so no login succeeds with it. A client that asks first whether a key would do never signs; one that signs at once has the signature checked by the library, and is refused all the same.

No login succeeds. There is therefore never a channel, a shell, a command, a forwarded port or a subsystem, and nothing is run or passed on. The sixth refused login ends the connection, as the default `MaxAuthTries` of OpenSSH does. A client that does not get as far as a login, because it fails the key exchange or leaves, is reported as a connection, with its version if it announced one.

### The host key

The honeypot needs a host key, and it has to stay the same: a key that changed with every start would tell anyone who looks that the server is a decoy, and a client that remembers the key would warn of a man in the middle. The sensor therefore creates no key. You create it once, without a passphrase, and name the file:

```sh
ssh-keygen -t ed25519 -N '' -f /etc/nyktus-sensor/ssh_host_key_7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d
chmod 600 /etc/nyktus-sensor/ssh_host_key_7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d
chown nyktus-sensor /etc/nyktus-sensor/ssh_host_key_7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d
```

The entry that the console shows names a file of its own for each honeypot, `ssh_host_key_` and the identifier of the honeypot, next to the configuration file; create the key under that name or change the name.

```yaml
- id: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d"
  service: "ssh"
  listen: ":22"
  host_key_file: "ssh_host_key_7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d"
  secret: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
```

The key is an Ed25519 key in the format that `ssh-keygen` writes. The sensor refuses a key that its group or others can read or write, as it does for a secret file, a key with a passphrase (the sensor starts unattended), a key of another type and a file larger than 8 KiB. `ssh-keygen` also writes `ssh_host_key.pub`; the sensor does not read it. Use a key of its own: never the host key of a real server, which anyone who captures the honeypot would then know. Keep the file, also in a container, where you mount it like a secret file: the rules for the mode are the same, so mount it with a mode of `0400` for the user of the sensor (in Kubernetes `defaultMode: 0400`), as the common default of `0644` or `0440` is refused. Give every SSH honeypot a key of its own: two honeypots that share one show the same host key, and anyone who looks can tie them together. The sensor refuses a configuration in which two SSH honeypots use the same key, also a copy of the file. If you replace it, clients that connected before see a changed host key.

### Version and algorithms

`banner` of an SSH honeypot is the identification string that the server sends first, without the line ending. The default is that of Ubuntu 22.04:

```yaml
banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
```

Change it to what the servers in your network announce, such as `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`. It starts with `SSH-2.0-`, then a software version of printable characters without a space or a minus, and optionally a space and a comment; it is printable ASCII of at most 253 bytes. There is no text banner before the login.

The honeypot offers the algorithms of the SSH library, not those of OpenSSH, and an Ed25519 host key only. A tool that compares the lists, such as `ssh-audit`, can tell it from the OpenSSH that it names. The library offers no algorithm that is broken or deprecated: a client that knows nothing newer than SHA-1, CBC or the 1024-bit groups, such as old embedded devices and some bots, fails the key exchange and shows up as a connection, with its version. A refused login also comes at once, where OpenSSH makes a client wait.

The library starts goroutines of its own for the key exchange and the packets of a connection, and a failure in them that panics ends the process, where the sensor catches a panic in everything else. The library is widely used and fuzzed, and the sensor cannot wrap it; run it as the [unit](#systemd) does, so that the service manager starts it again (`Restart=on-failure`) and the honeypots are `offline` in the console only for the time that takes.

## PostgreSQL honeypots

The honeypot speaks the protocol of PostgreSQL up to the login and refuses it. It reads the startup message of the client and records the user, the database that the client asked for and the name that it calls itself (`application_name`, which `psql` sets to `psql`), then asks for the password in clear text, counts its length, and answers with the error `28P01`, `password authentication failed for user "..."`, as a server does for a user that does not exist. The connection ends there, as it does on a real server, so a session holds at most one login: a brute force against the honeypot is one event for each connection, and the limit of [ten events a minute for each honeypot](honeypots.md#limits) keeps the first of them.

There is no session behind the login. The honeypot never reads a query, never runs SQL and passes nothing on. The password is counted as it is read and dropped.

The honeypot offers no encryption: it answers a request for TLS or for GSSAPI encryption with `N`, as a server does that has none, and the client goes on in clear text, as `psql` does with the default `sslmode=prefer`. A client that insists on TLS (`sslmode=require`) goes no further and is reported as a connection. A client that cancels a query, sends a protocol version that does not exist or something that is not PostgreSQL at all is reported as a connection as well, and so is a client that names no user. A real server from version 14 asks for a SCRAM password, which does not reveal its length, so a client sees a request for a clear-text password that a current server would not send: the honeypot records the length because the report needs it.

`banner` has no effect and is refused. The version of a server is part of the parameters that it sends after a successful login, which this honeypot never sends, so nothing in the dialog could carry it.

## LDAP honeypots

The honeypot speaks the part of LDAP that a scanner or a tool that maps a domain uses: bind, search and unbind. It records the name and the password length of a bind, and the base and the filter of the first search, and answers every search with an empty result.

A bind with a name or a password fails with `invalidCredentials` and is a login of the session, as many as the session keeps. A bind with neither, an anonymous bind, succeeds, so that a client that begins with one goes on to its search; it carries no credentials and is not recorded as a login. A bind with SASL is answered with `authMethodNotSupported` and not recorded. A search is answered with a result that holds no entry, whatever the base is, so also the search of the root of the directory (the RootDSE), with which most tools start. The honeypot never returns an entry and never changes anything. Any other operation, such as a request to start TLS, a change, or a request that the sensor cannot read, ends the session.

The report holds the first search only. The sensor writes the filter as text, in the form that administrators know (`(&(objectClass=user)(sAMAccountName=admin*))`), with the characters that mean something in a filter, and those that do not show, as a backslash and two hexadecimal digits. A filter with an extensible match, such as `(userAccountControl:1.2.840.113556.1.4.803:=2)`, is written as `(?)`: the search is recorded, its filter is not. Filters may nest eight levels deep, and a message may be 8 KiB long; the sensor ends a session that exceeds them, as it does for a message that it cannot read, and keeps what it recorded before.

There is no LDAPS and no StartTLS: a session on a port that you chose for LDAPS is plain LDAP, and a client that wants TLS goes no further. `banner` has no effect and is refused: the honeypot returns no RootDSE and therefore no vendor name or version.

## Limits

The limits are fixed. They bound what an attacker can use up, and they are not settings, so that a configuration cannot lift them by mistake.

| Limit | Value |
|---|---|
| Open connections of a honeypot | 128. Further connections are closed at once. |
| Open connections from one source | 8, where a source is an IPv4 address or an IPv6 network of /64. |
| Duration of a session | 2 minutes. The sensor closes the connection and reports the session. |
| Silence | 30 seconds without a byte from the client, or 10 seconds for a client that does not read. |
| Data from one client | 16 KiB for the whole connection, Telnet commands and the key exchange of SSH included. |
| Logins of a session | 6, passwords and offered SSH keys together. The sixth refusal is the last; the sensor then closes the connection. A PostgreSQL session holds one: the connection ends with the first refusal. |
| User name | The first 256 bytes are kept. |
| Password | Nothing is kept except its length. |
| Version of an SSH client | The first 128 bytes are kept. |
| Database and application of a PostgreSQL client | The first 64 bytes of each are kept. The startup message may have 10,000 bytes, as on a real server; a longer one ends the session. |
| LDAP message, base and filter | A message may have 8 KiB; a longer one, or one that is not well formed, ends the session. The first 256 bytes of the base and of the written filter are kept, and filters nest at most eight levels deep. |
| Telnet negotiation | The sensor offers `ECHO` and `SUPPRESS-GO-AHEAD` once and answers nothing the client negotiates. A negotiation of more than 128 bytes ends the session. |

The sensor keeps no table of sources beyond the connections that are open. A flood from many addresses costs memory in proportion to the connections it holds, which are at most 128.

## How reports are delivered

A session is reported once, when it ends. The report waits in a queue, which has room for 256 sessions of each honeypot, and is sent by four workers. The [trigger answers every report alike](honeypots.md#the-answer), so the sensor cannot tell whether a report was stored. It repeats a request only when the transport fails, because of a connection that is refused, a timeout, a certificate that is not accepted or a proxy in front of the trigger that cannot pass the request on (the answers 502, 503 and 504, which the trigger itself never sends), at most three times after 1, 3 and 9 seconds. Every other answer, including an error, counts as delivered. It follows no redirect and sends the secret to the address you configured and to no other.

The server takes the age of a session within five minutes. A session that is still waiting after five minutes is dropped, because its time would be wrong, and it is counted. A session is also dropped when the share of its honeypot in the queue is full, so that a flood at one honeypot does not take the places of the others, when the transport failed on every attempt and when the sensor stops before it could be sent.

The sensor sends a [heartbeat](honeypots.md#heartbeat) for each honeypot when it starts, once the honeypot listens, and every five minutes. Every honeypot has a loop of its own, and heartbeats do not use the queue, so neither a slow trigger nor an attacker who fills the queue can make a honeypot look offline.

### Stopping

On `SIGTERM` or `SIGINT` the sensor stops listening, closes the connections that are open and reports their sessions, then delivers what is queued for up to 15 seconds. What it could not deliver by then is counted in the log. A second signal ends the process at once. The exit code is 0 after a clean stop, 1 if the sensor could not start or failed, and 2 for a wrong invocation.

A sensor that cannot bind a port of its configuration does not start: it logs the honeypot and the error, closes the listeners it has opened and exits with 1. A sensor that ran fewer honeypots than you configured would look healthy and watch nothing.

## Running it

### systemd

Create a user for the sensor and give it the files. A unit that lets the sensor listen on ports below 1024 without being root:

```ini
[Unit]
Description=Nyktus sensor
After=network-online.target
Wants=network-online.target

[Service]
User=nyktus-sensor
ExecStart=/usr/local/bin/nyktus-sensor run -config /etc/nyktus-sensor/sensor.yaml
Restart=on-failure
RestartSec=5s

# Ports below 1024, and nothing else.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

The sensor writes no file. Remove `AmbientCapabilities` if every honeypot listens on a port from 1024. Use `systemctl restart nyktus-sensor` after a change of the configuration.

### Containers

Run the sensor as a user other than root, with a read-only root file system, all capabilities dropped and `no-new-privileges`, and let it listen on ports from 1024: map the port you want on the host to the port in the container, such as `-p 23:2323` with `listen: ":2323"`. The report names the port that the attacker reached *in the container*, which is `2323` here. Pass the configuration file and the secret files as mounts that only the user of the container can read.

The sensor reports the address that it sees on the connection. Some ways of publishing a port, such as the user-space proxy of Docker or a masquerading rule, replace the address of the attacker with the one of the gateway, and every event then names the gateway. Publish the ports in a way that keeps the source address, for example with host networking or a network that does not translate it, and check with a connection from another host that the event names it.

A container image comes with the releases of Nyktus.

### Placement

Put the sensor where an attacker who moves through the network looks: in the segment of the servers, of the management network or of the devices that the honeypot imitates, on a host that has no other purpose. Exclude the addresses of honeypots from your own vulnerability scanners and inventory tools, or give the honeypot a higher [severity](honeypots.md#severity) only if nothing in your network should ever reach it.

## TLS and a private authority

The sensor verifies the certificate of the trigger in every case; there is no setting to turn that off. If your trigger uses a certificate from a private authority, tell the system where to find it with the environment variable `SSL_CERT_FILE` of the sensor process, which the Go runtime reads on Linux, for example in the unit:

```ini
Environment=SSL_CERT_FILE=/etc/nyktus-sensor/ca.pem
```

The file holds the certificate of the authority in PEM format. On other systems, add the authority to the certificate store of the system. A sensor that cannot verify the certificate cannot report: the honeypot stays `offline` or `never` in the console, and the log of the sensor says that the heartbeat was not delivered.

The sensor sends no request through a proxy from the environment, because the secret would travel to it. TLS 1.2 or later is required.

## Replacing a secret

Replace the secret in the console ([Replacing the secret](honeypots.md#replacing-the-secret)), put the new `secret` into the configuration or the secret file, and restart the sensor. The old secret stops working in the console at once, so the sensor reports in vain until you restart it, and the honeypot is `never` until it reports with the new one.

## Logs

The sensor writes JSON, one record per line, to standard error, like the server. See [Logs](logs.md#sensor) for the records. They name the honeypot and counts. They never hold a secret, a user name, a password or anything else that an attacker typed.
