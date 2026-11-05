## Story

Attach the trigger to your backup itself. The file `procedure.sql` creates a stored procedure in your database. When the procedure runs, it lists a directory on a share, and that first resolves the host name of the share. The host name belongs to a DNS honeytoken. Every `.bak` file that you create afterwards carries the procedure, so an intruder who steals a backup and runs the procedure on an instance of their own raises an event. The procedure reads nothing from the database and changes nothing.

## Setup

1. Create the DNS honeytoken "Share host". Replace `Honeytoken-Domain` in `procedure.sql` with its name.
2. Rename the procedure `usp_ExportCustomerData` to a name that an intruder wants to run and that fits the names of your procedures.
3. Run the file in the database whose backups you want to protect, for example with `sqlcmd -d DATABASE -i procedure.sql`. The login needs the right to create procedures.
4. Do not grant anyone the right to execute the procedure, and do not call it yourself except for the test.
5. Use one deception for each database or backup set, so that an incident tells you which data was stolen.
6. Record in the notes of the scenario which database holds the procedure.

## Testing

Back up the database, restore the backup on an instance on a computer with access to the internet, and run `EXEC [dbo].[usp_ExportCustomerData]` there as an administrator of that instance. Use the name that you chose. Within a minute, the scenario shows an incident. Close the incident after the test.

To check only the name resolution, run `nslookup Honeytoken-Domain`, with the name of the honeytoken, on a computer with access to the internet.

## Limits

- A restore of a `.bak` file runs none of the objects in it. An event happens only when someone executes the procedure. A test restore by your own database administrators on a computer with access to the internet raises an event as well, so tell them.
- `xp_dirtree` is available to administrators of an instance. An intruder who restores your backup on their own instance is one. Where the extended procedure is switched off or removed, the procedure fails before the lookup.
- A restore in a network that cannot resolve names on the internet does not reach the DNS role. That holds for every beacon in a backup: it catches the intruder who restores your backup on a machine of their own, not one who works in an isolated laboratory.
- Whoever searches the dump for host names, or looks at the objects of the restored database, can find the name unusual.
