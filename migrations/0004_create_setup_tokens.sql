-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- While no administrator exists, every console process that starts issues a
-- setup token and prints it. Whoever holds one can create the first
-- administrator. Tokens of other console processes stay valid until they expire,
-- so that the setup works behind a load balancer.
DO $$
BEGIN
	IF to_regrole('nyktus_console') IS NULL THEN
		RAISE EXCEPTION 'database role nyktus_console does not exist; create the server roles with deploy/postgres/roles.sql before running migrations';
	END IF;
END
$$;

CREATE TABLE public.setup_tokens (
	-- Only the SHA-256 hash of a token is stored, so that reading the table does
	-- not reveal a usable token.
	token_hash bytea NOT NULL,
	-- The database sets the expiry, so that the console cannot issue a token that
	-- stays valid longer.
	expires_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '1 hour',

	CONSTRAINT setup_tokens_pkey PRIMARY KEY (token_hash),
	CONSTRAINT setup_tokens_token_hash_check CHECK (octet_length(token_hash) = 32)
);

-- Default privileges set by an operator could grant more than this migration
-- intends, so everything is revoked before the grants.
REVOKE ALL ON public.setup_tokens FROM PUBLIC, nyktus_console;

-- The console looks tokens up, issues them and consumes them. DELETE also lets it
-- lock the table, which serializes the creation of the first administrator.
GRANT SELECT, DELETE ON public.setup_tokens TO nyktus_console;
GRANT INSERT (token_hash) ON public.setup_tokens TO nyktus_console;

-- GRANT and REVOKE only warn when the executing role lacks the privilege, so the
-- result is verified instead of assumed, in both directions.
DO $$
BEGIN
	IF NOT has_table_privilege('nyktus_console', 'public.setup_tokens', 'SELECT')
		OR NOT has_table_privilege('nyktus_console', 'public.setup_tokens', 'DELETE')
		OR NOT has_column_privilege('nyktus_console', 'public.setup_tokens', 'token_hash', 'INSERT') THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on public.setup_tokens; run migrations as the owner of the schema';
	END IF;

	IF has_table_privilege('nyktus_console', 'public.setup_tokens', 'INSERT')
		OR has_table_privilege('nyktus_console', 'public.setup_tokens', 'UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.setup_tokens', 'UPDATE, REFERENCES')
		OR has_column_privilege('nyktus_console', 'public.setup_tokens', 'expires_at', 'INSERT') THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on public.setup_tokens than granted; check the default privileges of the owner';
	END IF;
END
$$;
