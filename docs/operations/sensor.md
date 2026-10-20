# Sensor

The sensor `nyktus-sensor` runs the [honeypots](honeypots.md) inside the network you monitor. It listens where you tell it to, answers attackers like the real service would, offers nothing behind the login, and reports every session to the [trigger](configuration.md#role-trigger). It is a separate program from the server, with a configuration file of its own and nothing to share with the server but the secrets of the honeypots: it runs on hosts that attackers can reach, and what it knows is only what it needs to report.

This version emulates one service, `telnet`. The other services of the console follow with later versions of the sensor; a configuration that names one is refused. The console shows the entry for the configuration file of every honeypot, also for a service that this version does not run yet: keep that entry until a sensor that emulates the service is installed.

## What the sensor does and does not do

- It runs as an ordinary user and needs no privilege except a port below 1024, if you choose one.
- It never executes, interprets or passes on what an attacker sends. A Telnet honeypot reads a user name and a password, counts them and refuses them. There is no shell, no file, no command.
- It keeps no password. It reports the length of the password and nothing else about it.
- It limits everything an attacker can use up: connections, bytes, time and logins. See [Limits](#limits).
- It reads no environment variables for its configuration, loads nothing from the internet and sends nothing anywhere except the reports to your trigger.
- It reports one event for each session of an attacker, when the session ends. The first event of an incident therefore says what the attacker did, not only that it connected.

## Installation

Build the sensor from the source of Nyktus, or install it with the Go toolchain once a release exists:

```sh
make build        # writes bin/nyktus-sensor next to bin/nyktus
go install nyktus.org/nyktus/sensor/cmd/nyktus-sensor@v0.1.0
```

The sensor is a Go module of its own whose `go.mod` names one dependency, a YAML parser. It is one static binary without other files, and you may rename it. `nyktus-sensor version` prints its version: the release for a build from a tag, `devel` otherwise. The sensor tells the trigger this version with every heartbeat, and the console shows it as `sensor_version` of the honeypot.

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
3. Make the file readable by the user of the sensor only: `chmod 600`. A file that holds a secret and that other users can read is refused.
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

Give an entry `secret` or `secret_file`, not both. A relative path is relative to the directory of the configuration file. The file holds the secret and an optional line break, and only its owner may read it (`chmod 600`); the sensor checks the mode of the file it has opened, so a file that others can read is refused. With a container or a service manager that supplies secrets as files, this is the way to pass them.

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
| `service` | required | `telnet`. |
| `listen` | required | `host:port` or `:port`. The host is an IP address, or empty for every address. Entries must not conflict: the same port on the same address, or on an address and on all addresses. |
| `secret` or `secret_file` | one is required | The secret of the honeypot, 43 characters, or the file that holds it. |
| `banner` | by service | What the service says first. Up to 256 bytes of printable ASCII, with line breaks and tabs. An empty value sends no banner. |
| `login_prompt` | `login: ` | The prompt for the user name, up to 64 bytes of printable ASCII. Telnet only. |

`nyktus-sensor check -config <file>` reads the file the way `run` does and lists every problem it finds: unknown keys, malformed values, duplicate addresses, ids and secrets, a banner that is too long, and the modes of the files. It binds no port and does not contact the trigger.

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

## Limits

The limits are fixed. They bound what an attacker can use up, and they are not settings, so that a configuration cannot lift them by mistake.

| Limit | Value |
|---|---|
| Open connections of a honeypot | 128. Further connections are closed at once. |
| Open connections from one source | 8, where a source is an IPv4 address or an IPv6 network of /64. |
| Duration of a session | 2 minutes. The sensor closes the connection and reports the session. |
| Silence | 30 seconds without a byte from the client, or 10 seconds for a client that does not read. |
| Data from one client | 16 KiB for the whole connection, Telnet commands included. |
| Logins of a session | 6. The sixth refusal is the last; the sensor then closes the connection. |
| User name | The first 256 bytes are kept. |
| Password | Nothing is kept except its length. |
| Telnet negotiation | The sensor offers `ECHO` and `SUPPRESS-GO-AHEAD` once and answers nothing the client negotiates. A negotiation of more than 128 bytes ends the session. |

The sensor keeps no table of sources beyond the connections that are open. A flood from many addresses costs memory in proportion to the connections it holds, which are at most 128.

## How reports are delivered

A session is reported once, when it ends. The report waits in a queue of 256 sessions and is sent by four workers. The [trigger answers every report alike](honeypots.md#the-answer), so the sensor cannot tell whether a report was stored. It repeats a request only when the transport fails, because of a connection that is refused, a timeout, a certificate that is not accepted or a proxy in front of the trigger that cannot pass the request on (the answers 502, 503 and 504, which the trigger itself never sends), at most three times after 1, 3 and 9 seconds. Every other answer, including an error, counts as delivered. It follows no redirect and sends the secret to the address you configured and to no other.

The server takes the age of a session within five minutes. A session that is still waiting after five minutes is dropped, because its time would be wrong, and it is counted. A session is also dropped when the queue is full, when the transport failed on every attempt and when the sensor stops before it could be sent.

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
