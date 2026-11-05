## Story

Put a document with a connection string into a MongoDB database, so that every backup of the database carries it. The file `endpoints.js` is a script for `mongosh`. It inserts a document that names the service `sync-service` and holds a connection string with the account `svc-sync`, a random password and a host name. The host name belongs to a DNS honeytoken. An intruder who steals a backup, reads the documents and connects with the string looks up the name, which raises an event. There is no database behind the name, and the account and password exist nowhere.

## Setup

1. Create the DNS honeytoken "Database host". Replace `Honeytoken-Domain` in the script with its name.
2. Choose a database and a collection that exist and that an intruder reads when searching for connection data. A collection of integrations or services fits. Replace the database `integrations`, the collection `endpoints` and the service name `sync-service` in the script to match your data.
3. Run the script once: `mongosh "mongodb://HOST" --file endpoints.js`, with the connection string of your server instead of `HOST`. The login needs the right to insert into the collection.
4. Use one script for each database whose backups you protect.
5. Record in the notes of the scenario where you placed the document.

## Testing

On a computer with access to the internet, run `nslookup Honeytoken-Domain`, with the name of the honeytoken. Within a minute, the scenario shows an incident. Close the incident after the test.

To test the whole chain, connect with `mongosh` to the string in the document.

## Limits

- Restoring a backup runs nothing. An event happens only when someone uses the connection string.
- The password is in the document as plain text, as in many real collections of connection data. An application that reads this collection through a driver would look up the name too; choose a collection that no application reads.
- A restore in a network that cannot resolve names on the internet does not reach the DNS role. That holds for every beacon in a backup: it catches the intruder who restores your backup on a machine of their own, not one who works in an isolated laboratory.
- Whoever searches the dump for host names, or looks at the objects of the restored database, can find the name unusual.
