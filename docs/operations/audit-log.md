# Audit log

Nyktus records security-relevant actions in an audit log in its database. The console can add entries and read them, but never change or delete them.

## What an entry records

- **Action** in the form `resource.verb`, such as `user.create`, `session.create` or `session.delete`. A request denied for a missing permission names the permission it lacked, such as `audit.read`.
- **Outcome:** `success`, `failure` or `denied`.
- **Actor:** who acted and how they authenticated, such as a user with a password or a session, or the holder of the setup token. For a user, the entry keeps a copy of the address and display name at the time of the entry, so it stays readable after the account is deleted.
- **Resource** by type and identifier, never by name. Updates name the changed fields, never their values.
- **Client address** and **request ID**, which links the entry to the [log](logs.md) records of the request.

Requests without valid credentials are not recorded, so that anonymous clients cannot fill the audit log. The access log records them. A failed sign-in for an unknown address is recorded without the address.

## Reading the audit log

Administrators read the audit log through `GET /api/v1/audit-entries`. It returns entries from the newest to the oldest, 50 per page by default and at most 200 (`limit`). To read the next page, pass the `next_cursor` of the response as `cursor`. Entries recorded meanwhile do not shift the following pages.

Entries are ordered by the time they were written, not by the time their action was committed. An action that took long to complete can therefore appear behind entries you have already read. If you collect entries regularly, for example into a SIEM, read again from a few minutes before the newest entry you have and skip the identifiers you already know.

## Personal data

Entries contain addresses, display names and client addresses of users. Restrict access to the audit log, and to backups of the database, accordingly.
