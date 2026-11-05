## Story

Place the history of a shell where an intruder looks for commands that administrators typed. Administrators and developers leave their commands in the history of their shell, passwords and host names included. The files tell this story for Linux and for Windows. Nothing stands behind the host names, and the accounts and passwords exist nowhere. One file is enough.

- `bash_history` is the history of a Linux shell. It holds the command that logs in to the database `billing` with the account `svc-ops` and a random password.
- `ConsoleHost_history.txt` is the PSReadLine history of PowerShell. It holds the commands that ask for the credentials of the account `CORP\svc-ops` and open a remote session to a server. It holds no password, because PowerShell does not write command lines with a password, token or secret to its history.

Each host name belongs to a DNS honeytoken. Whoever runs a command, or anything else that connects to the host, looks up the name, which raises an event.

## Setup

Each placeholder in the files stands for one honeytoken:

- `Honeytoken-Domain-Database`: "Database host", in `bash_history`
- `Honeytoken-Domain-Server`: "Server", in `ConsoleHost_history.txt`

1. Create the two DNS honeytokens.
2. Replace each placeholder with the name of its honeytoken. Adapt the names of accounts and databases to your environment.
3. For `bash_history`: name the file `.bash_history` and place it in the home directory of an account on an application server that people log in to.
4. For `ConsoleHost_history.txt`: place it in the directory `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine` of an account on a server or workstation of administrators.
5. If the account has a history already, append the lines to it instead of replacing it. A history that is new and has nothing older than the lures looks made.
6. Record in the notes of the scenario where you placed the files.

## Testing

On a computer with access to the internet, run `nslookup` with the name of a honeytoken, such as `nslookup Honeytoken-Domain-Database`. The names are in the table "Honeytokens of this scenario". Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The host names are random labels under the zone of your DNS role. An intruder who reads the files carefully can find them unusual.
- Reading the files raises no event; using the credentials or running the commands does.
