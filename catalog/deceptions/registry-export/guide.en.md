## Story

Place an export of backup settings where an intruder looks for saved credentials. The file `Settings.reg` names a backup server, the account `svc-backup` and a password. The server name belongs to a DNS honeytoken: whoever uses the settings to reach the server looks up the name, and the lookup raises an event. No server stands behind the name, and the account and password exist nowhere.

## Setup

1. Create the DNS honeytoken "Backup server". Replace `Honeytoken-Domain` in the file with its name.
2. Adapt the account name and the password to the naming scheme of your environment. If you use other backup software, rename the key `BackupPro` and the file to match.
3. Place the file where an intruder looks for settings of backup software: on a server that is backed up, in a folder with IT documentation, or in a backup of a user profile.
4. Do not import the file on a computer that you use. The import writes the key to the registry of the importing account.
5. Record in the notes of the scenario where you placed the file.

## Testing

On a computer with access to the internet, run `nslookup Honeytoken-Domain`, with the name of the honeytoken instead of the placeholder. The name is in the table "Honeytokens of this scenario". Within a minute, the scenario shows an incident. Close the incident after the test.

If no incident appears, check that the computer resolves names through a resolver that reaches the DNS role of Nyktus, see Limits.

## Limits

- Only a lookup that reaches the DNS role of Nyktus raises an event. A network without name resolution to the internet, or a resolver that answers from its cache, prevents it.
- The server name is a random label under the zone of your DNS role. An intruder who reads the file carefully can find it unusual.
- Importing the file creates the key but starts nothing. An intruder who only reads or imports the file raises no event; the lookup happens when a program connects to the server.
