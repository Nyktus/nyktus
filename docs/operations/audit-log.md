# Audit log

Nyktus records security-relevant actions in an audit log in its database. The console can add entries and read them, but never change or delete them.

## What an entry records

- **Action** in the form `resource.verb`, such as `user.create`, `session.create` or `session.delete`. A request denied for a missing permission names the permission it lacked, such as `audit.read`.
- **Outcome:** `success`, `failure` or `denied`.
- **Actor:** who acted and how they authenticated, such as a user with a password, through the [identity provider](sign-in.md#identity-provider) (`oidc`) or with a session, an [API key](api-keys.md) with its identifier, or the holder of the setup token. For a user, the entry keeps a copy of the address and display name at the time of the entry, and for a key a copy of its name, so it stays readable after the account is deleted or the key revoked.
- **Resource** by type and identifier, never by name. Updates name the changed fields, never their values.
- **Client address** and **request ID**, which links the entry to the [log](logs.md) records of the request.

Requests without valid credentials are not recorded, so that anonymous clients cannot fill the audit log. The access log records them. A failed sign-in for an unknown address is recorded without the address.

A sign-in through the identity provider is recorded once the provider has confirmed the user. The first one creates the account, recorded as `user.create` with the new account as the actor; a change of role or name that the provider reports is recorded as `user.update`, with the account as the actor, and so is the deactivation of a user who is in none of the configured groups. A rejected sign-in of an account is recorded as a failure of `session.create` with the account; one of a user without an account, for example without a matching group, as a failure without naming the user. The [log](logs.md) names the reason, the issuer and the subject. A sign-in that does not prove an identity, such as an expired or reused one, is only logged. A user of the provider who signs in there again to [confirm sensitive actions](sign-in.md#confirming-sensitive-actions) is recorded as `session.reauthenticate`, successful or not, with the account and the session.

Reads of the audit log and requests denied for a missing permission are recorded at most once per user or [API key](api-keys.md), action and minute, so that a signed-in user or a key cannot fill the audit log by repeating them. The access log records every one of them.

## Reading the audit log

Administrators read the audit log through `GET /api/v1/audit-entries`, with a session or with an [API key](api-keys.md) that carries the scope `audit:read`. Every read is recorded as `audit.read`, because the entries contain personal data. It returns entries from the newest to the oldest, 50 per page by default and at most 200 (`limit`). To read the next page, pass the `next_cursor` of the response as `cursor`. Entries recorded meanwhile do not shift the following pages.

Entries are ordered by the time they were written, not by the time their action was committed. An action that took long to complete can therefore appear behind entries you have already read. If you collect entries regularly, for example into a SIEM, read again from a few minutes before the newest entry you have and skip the identifiers you already know.

## Personal data

Entries contain addresses, display names and client addresses of users. Restrict access to the audit log, and to backups of the database, accordingly.
