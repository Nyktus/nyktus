## Story

Place the credentials for a file transfer where an intruder looks for them. Administrators and developers keep them in the tools they use: in a `.netrc` file and in the site manager of FileZilla. Both files name the host of one DNS honeytoken, so the same host name appears in both. Whoever uses the credentials with a tool looks up the name, which raises an event. No server stands behind the name, and the account and the password exist nowhere. One file is enough.

## Setup

1. Create the DNS honeytoken "Host". Replace `Honeytoken-Domain` in the files with its name.
2. For `netrc`: save the file as `~/.netrc` in the home directory of an account on a server or workstation, ideally an account that exists only for this purpose. Restrict it to its owner with `chmod 600 ~/.netrc`, because some tools ignore a `.netrc` that others can read. If the account already has a `~/.netrc`, add the three lines to it instead of replacing it, so that its other credentials keep working.
3. For `sitemanager.xml`: place the file in the FileZilla directory of an account on a workstation, on Windows `%APPDATA%\FileZilla`. If the account has a site manager already, add the `Server` element to its `Servers` instead of replacing the file.
4. Record in the notes of the scenario where you placed the files.

## Testing

On a computer with access to the internet, run `nslookup Honeytoken-Domain`, with the name of the honeytoken. Within a minute, the scenario shows an incident. Close the incident after the test.

To test with the tool, run `curl --netrc https://Honeytoken-Domain/`, or open `sitemanager.xml` in FileZilla and connect to the site.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The host name is a random label under the zone of your DNS role. An intruder who reads the files carefully can find it unusual.
- Reading a file raises no event; connecting to the site or using the credentials does.
- `sitemanager.xml`: FileZilla itself writes the password as Base64. The file holds it as plain text, which an intruder who knows the format can find unusual.
