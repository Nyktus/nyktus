-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Administrators create accounts without a password. The new user sets one
-- through an activation link, which the administrator sees once and passes on.
-- An account has at most one open link; a new link replaces the previous one.
DO $$
BEGIN
	IF to_regrole('nyktus_console') IS NULL THEN
		RAISE EXCEPTION 'database role nyktus_console does not exist; create the server roles with deploy/postgres/roles.sql before running migrations';
	END IF;
END
$$;

CREATE TABLE public.activation_tokens (
	-- Deleting an account removes its link.
	user_id    uuid CONSTRAINT activation_tokens_pkey PRIMARY KEY
		CONSTRAINT activation_tokens_user_id_fkey REFERENCES public.users (id) ON DELETE CASCADE,
	-- Only the SHA-256 hash of a token is stored, so that reading the table does
	-- not reveal a usable link.
	token_hash bytea NOT NULL,
	-- The database sets the expiry, so that the console cannot issue a link that
	-- stays valid longer.
	expires_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '72 hours',

	CONSTRAINT activation_tokens_token_hash_key UNIQUE (token_hash),
	CONSTRAINT activation_tokens_token_hash_check CHECK (octet_length(token_hash) = 32)
);

-- Default privileges set by an operator could grant more than this migration
-- intends, so everything is revoked before the grants.
REVOKE ALL ON public.activation_tokens FROM PUBLIC, nyktus_console;

-- The console issues, looks up and consumes links. It never changes one.
GRANT SELECT, DELETE ON public.activation_tokens TO nyktus_console;
GRANT INSERT (user_id, token_hash) ON public.activation_tokens TO nyktus_console;

-- GRANT and REVOKE only warn when the executing role lacks the privilege, so the
-- result is verified instead of assumed, in both directions.
DO $$
BEGIN
	IF NOT has_table_privilege('nyktus_console', 'public.activation_tokens', 'SELECT')
		OR NOT has_table_privilege('nyktus_console', 'public.activation_tokens', 'DELETE')
		OR NOT has_column_privilege('nyktus_console', 'public.activation_tokens', 'user_id', 'INSERT')
		OR NOT has_column_privilege('nyktus_console', 'public.activation_tokens', 'token_hash', 'INSERT') THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on public.activation_tokens; run migrations as the owner of the schema';
	END IF;

	IF has_table_privilege('nyktus_console', 'public.activation_tokens', 'INSERT')
		OR has_table_privilege('nyktus_console', 'public.activation_tokens', 'UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.activation_tokens', 'UPDATE, REFERENCES')
		OR has_column_privilege('nyktus_console', 'public.activation_tokens', 'expires_at', 'INSERT') THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on public.activation_tokens than granted; check the default privileges of the owner';
	END IF;
END
$$;
