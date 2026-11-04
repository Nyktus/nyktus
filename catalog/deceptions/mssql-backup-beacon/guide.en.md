# SQL Server procedure that travels with every backup

The deception attaches the trigger to your backup itself. The file `procedure.sql` creates a stored procedure `usp_ExportCustomerData` in your database. When it runs, it lists a directory on the share `\\Honeytoken-Domain\exports`, which first resolves the host name. The host belongs to a DNS honeytoken. Every `.bak` file that you create afterwards carries the procedure, so an intruder who steals a backup and runs the procedure on an instance of their own raises an event. The procedure reads nothing from the database and changes nothing.

## Creating the procedure

1. Change `ProcedureName` to a name that an intruder wants to run, and that fits the names of your procedures, such as `usp_ExportCustomerData`.
2. Run the file in the database whose backups you want to protect, for example with `sqlcmd -d DATABASE -i procedure.sql`. The login needs the right to create procedures.
3. Do not grant anyone the right to execute the procedure, and do not call it yourself except for the test.

## Testing

Back up the database, restore the backup on an instance on a computer with access to the internet and run `EXEC [dbo].[usp_ExportCustomerData]` there as an administrator of that instance. Within a minute, the scenario shows an incident. Close the incident after the test. Use one deception for each database or backup set, so that an incident tells you which data was stolen. Tell your database administrators: a test restore on a machine with internet access raises an event as well.

## Limits

- A restore of a `.bak` file runs none of the objects in it. An event happens only when someone executes the procedure.
- `xp_dirtree` is available to administrators of an instance. An intruder who restores your backup on their own instance is one. Where the extended procedure is switched off or removed, the procedure fails before the lookup.
- A restore in a network that cannot resolve names on the internet does not reach the DNS role. That holds for every beacon in a backup: it catches the intruder who restores your backup on a machine of their own, not one who works in an isolated laboratory.
- Whoever searches the dump for host names, or looks at the objects of the restored database, can find the name unusual.
