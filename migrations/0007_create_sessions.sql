-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Sessions of signed-in users. The browser holds an opaque token in a cookie; the
-- database stores only its SHA-256 hash, so reading the table does not reveal a
-- usable session. A session ends after a period without requests and after an
-- absolute lifetime. Both limits are configuration of the console, which applies
-- them in its queries against the time of the database.
DO $$
BEGIN
	IF to_regrole('nyktus_console') IS NULL THEN
		RAISE EXCEPTION 'database role nyktus_console does not exist; create the server roles with deploy/postgres/roles.sql before running migrations';
	END IF;
END
$$;

CREATE TABLE public.sessions (
	-- A random identifier names a session in the audit log and lets a user end a
	-- single session, without revealing its token.
	id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	token_hash   bytea NOT NULL,
	-- Deleting a user ends all of their sessions.
	user_id      uuid NOT NULL CONSTRAINT sessions_user_id_fkey REFERENCES public.users (id) ON DELETE CASCADE,
	created_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
	last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),

	CONSTRAINT sessions_token_hash_key UNIQUE (token_hash),
	CONSTRAINT sessions_token_hash_check CHECK (octet_length(token_hash) = 32),
	CONSTRAINT sessions_last_seen_at_check CHECK (last_seen_at >= created_at)
);

-- Signing in removes the expired sessions of the user, and deleting a user
-- removes all of them.
CREATE INDEX sessions_user_id_idx ON public.sessions (user_id);

-- Default privileges set by an operator could grant more than this migration
-- intends, so everything is revoked before the grants.
REVOKE ALL ON public.sessions FROM PUBLIC, nyktus_console;

GRANT SELECT, DELETE ON public.sessions TO nyktus_console;
-- Identifiers and times come from the database. The console only records when a
-- session was last used.
GRANT INSERT (token_hash, user_id) ON public.sessions TO nyktus_console;
GRANT UPDATE (last_seen_at) ON public.sessions TO nyktus_console;

-- GRANT and REVOKE only warn when the executing role lacks the privilege, so the
-- result is verified instead of assumed, in both directions.
DO $$
BEGIN
	IF NOT has_table_privilege('nyktus_console', 'public.sessions', 'SELECT')
		OR NOT has_table_privilege('nyktus_console', 'public.sessions', 'DELETE')
		OR NOT has_column_privilege('nyktus_console', 'public.sessions', 'token_hash', 'INSERT')
		OR NOT has_column_privilege('nyktus_console', 'public.sessions', 'user_id', 'INSERT')
		OR NOT has_column_privilege('nyktus_console', 'public.sessions', 'last_seen_at', 'UPDATE') THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on public.sessions; run migrations as the owner of the schema';
	END IF;

	IF has_table_privilege('nyktus_console', 'public.sessions', 'INSERT')
		OR has_table_privilege('nyktus_console', 'public.sessions', 'UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.sessions', 'REFERENCES')
		OR EXISTS (
			SELECT FROM unnest(ARRAY['id', 'created_at', 'last_seen_at']) AS c (name)
			WHERE has_column_privilege('nyktus_console', 'public.sessions', c.name, 'INSERT')
		)
		OR EXISTS (
			SELECT FROM unnest(ARRAY['id', 'token_hash', 'user_id', 'created_at']) AS c (name)
			WHERE has_column_privilege('nyktus_console', 'public.sessions', c.name, 'UPDATE')
		) THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on public.sessions than granted; check the default privileges of the owner';
	END IF;
END
$$;
