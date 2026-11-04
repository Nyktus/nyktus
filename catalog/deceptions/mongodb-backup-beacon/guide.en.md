# MongoDB document with a connection string

The file `endpoints.js` is a script for `mongosh`. It inserts a document into the collection `endpoints` of the database `integrations` that names the service `sync-service` and holds a connection string with the account `svc-sync`, a random password and the host `Honeytoken-Domain`. The host belongs to a DNS honeytoken. Every backup of the database carries the document. An intruder who steals a backup, reads the documents and connects with the string resolves the name, which raises an event. There is no database behind it, and the account and password exist nowhere.

## Placing the file

1. Choose a database and a collection that exist and that an intruder reads when searching for connection data. A collection of integrations or services fits. Change `DatabaseName` and `CollectionName` and the name of the service to fit your data.
2. Run the script once: `mongosh "mongodb://HOST" --file endpoints.js`, with the connection string of your server. The login needs the right to insert into the collection.
3. Use one script for each database whose backups you protect.
4. Record where you placed it in the notes of the scenario.

## Testing

Resolve the name with `nslookup Honeytoken-Domain` on a computer with access to the internet, or connect with `mongosh` to the string in the document. Within a minute, the scenario shows an incident. Close the incident after the test.

## Limits

- Restoring a backup runs nothing. An event happens only when someone uses the connection string.
- The password is in the document as plain text, as in many real collections of connection data. Applications that read this collection through a driver would resolve the name too; choose a collection that none does.
- A restore in a network that cannot resolve names on the internet does not reach the DNS role. That holds for every beacon in a backup: it catches the intruder who restores your backup on a machine of their own, not one who works in an isolated laboratory.
- Whoever searches the dump for host names, or looks at the objects of the restored database, can find the name unusual.
