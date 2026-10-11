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

-- A user who enabled a second factor signs in in two steps. The correct password
-- yields a challenge, a short-lived token in a cookie, which a code of the second
-- factor turns into a session. As with sessions, the database stores only the
-- SHA-256 hash of the token. Every change that ends the sessions of an account
-- also removes its challenges, so a challenge cannot outlive the password that
-- earned it.
CREATE TABLE public.sign_in_challenges (
	token_hash bytea PRIMARY KEY,
	user_id    uuid NOT NULL CONSTRAINT sign_in_challenges_user_id_fkey REFERENCES public.users (id) ON DELETE CASCADE,
	-- The lifetime is fixed here, so that the console cannot extend it.
	expires_at timestamptz NOT NULL DEFAULT clock_timestamp() + interval '5 minutes',

	CONSTRAINT sign_in_challenges_token_hash_check CHECK (octet_length(token_hash) = 32)
);

-- Ending the sessions of an account removes its challenges as well.
CREATE INDEX sign_in_challenges_user_id_idx ON public.sign_in_challenges (user_id);

-- The TOTP factor of an account (RFC 6238). The secret must be read back to
-- check a code, so it is encrypted by the console with a key from its
-- configuration, which never reaches the database. The first byte names that
-- key, so that keys can be replaced.
CREATE TABLE public.totp_factors (
	user_id        uuid PRIMARY KEY CONSTRAINT totp_factors_user_id_fkey REFERENCES public.users (id) ON DELETE CASCADE,
	secret         bytea NOT NULL,
	created_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
	-- NULL while the user has not yet confirmed the factor with a first code. An
	-- unconfirmed factor does not protect the sign-in.
	confirmed_at   timestamptz,
	-- The time step of the last accepted code. Only codes of later steps are
	-- accepted, so that a code cannot be used twice.
	last_used_step bigint,

	-- Key ID (1 to 255), nonce (12 bytes), the encrypted secret of 20 bytes and
	-- the authentication tag (16 bytes).
	CONSTRAINT totp_factors_secret_check CHECK (octet_length(secret) = 49 AND get_byte(secret, 0) > 0),
	CONSTRAINT totp_factors_confirmed_check CHECK (
		(confirmed_at IS NULL) = (last_used_step IS NULL) AND confirmed_at >= created_at
	),
	CONSTRAINT totp_factors_last_used_step_check CHECK (last_used_step >= 0)
);

-- Recovery codes of a TOTP factor. Each signs in once in place of a code. They
-- are random values of 80 bits, so a SHA-256 hash is enough to store them.
-- Removing the factor removes its codes.
CREATE TABLE public.recovery_codes (
	user_id   uuid NOT NULL CONSTRAINT recovery_codes_user_id_fkey REFERENCES public.totp_factors (user_id) ON DELETE CASCADE,
	code_hash bytea NOT NULL,

	CONSTRAINT recovery_codes_pkey PRIMARY KEY (user_id, code_hash),
	CONSTRAINT recovery_codes_code_hash_check CHECK (octet_length(code_hash) = 32)
);

REVOKE ALL ON public.sign_in_challenges, public.totp_factors, public.recovery_codes FROM PUBLIC, nyktus_console;

-- Challenges and recovery codes are issued, looked up and consumed, never
-- changed. Expiry times come from the database.
GRANT SELECT, DELETE ON public.sign_in_challenges TO nyktus_console;
GRANT INSERT (token_hash, user_id) ON public.sign_in_challenges TO nyktus_console;
GRANT SELECT, DELETE ON public.recovery_codes TO nyktus_console;
GRANT INSERT (user_id, code_hash) ON public.recovery_codes TO nyktus_console;
-- The console confirms a factor, records the step of each accepted code and
-- encrypts the secret again under a new key. It cannot move a factor to another
-- account or change its creation time.
GRANT SELECT, DELETE ON public.totp_factors TO nyktus_console;
GRANT INSERT (user_id, secret) ON public.totp_factors TO nyktus_console;
GRANT UPDATE (secret, confirmed_at, last_used_step) ON public.totp_factors TO nyktus_console;

DO $$
BEGIN
	-- has_table_privilege with several privileges is true if any is held, so
	-- each one is checked on its own.
	IF EXISTS (
			SELECT FROM unnest(ARRAY['public.sign_in_challenges', 'public.recovery_codes', 'public.totp_factors']) AS t (tbl),
				unnest(ARRAY['SELECT', 'DELETE']) AS p (priv)
			WHERE NOT has_table_privilege('nyktus_console', t.tbl, p.priv)
		)
		OR EXISTS (
			SELECT FROM (VALUES
				('public.sign_in_challenges', 'token_hash', 'INSERT'),
				('public.sign_in_challenges', 'user_id', 'INSERT'),
				('public.recovery_codes', 'user_id', 'INSERT'),
				('public.recovery_codes', 'code_hash', 'INSERT'),
				('public.totp_factors', 'user_id', 'INSERT'),
				('public.totp_factors', 'secret', 'INSERT'),
				('public.totp_factors', 'secret', 'UPDATE'),
				('public.totp_factors', 'confirmed_at', 'UPDATE'),
				('public.totp_factors', 'last_used_step', 'UPDATE')
			) AS p (tbl, col, priv)
			WHERE NOT has_column_privilege('nyktus_console', p.tbl, p.col, p.priv)
		) THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on the tables of the second factor; run migrations as the owner of the schema';
	END IF;

	IF has_table_privilege('nyktus_console', 'public.sign_in_challenges', 'INSERT, UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_table_privilege('nyktus_console', 'public.recovery_codes', 'INSERT, UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_table_privilege('nyktus_console', 'public.totp_factors', 'INSERT, UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.sign_in_challenges', 'UPDATE, REFERENCES')
		OR has_any_column_privilege('nyktus_console', 'public.recovery_codes', 'UPDATE, REFERENCES')
		OR has_any_column_privilege('nyktus_console', 'public.totp_factors', 'REFERENCES')
		OR EXISTS (
			SELECT FROM (VALUES
				('public.sign_in_challenges', 'expires_at', 'INSERT'),
				('public.totp_factors', 'created_at', 'INSERT'),
				('public.totp_factors', 'confirmed_at', 'INSERT'),
				('public.totp_factors', 'last_used_step', 'INSERT'),
				('public.totp_factors', 'user_id', 'UPDATE'),
				('public.totp_factors', 'created_at', 'UPDATE')
			) AS p (tbl, col, priv)
			WHERE has_column_privilege('nyktus_console', p.tbl, p.col, p.priv)
		) THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on the tables of the second factor than granted; check the default privileges of the owner';
	END IF;
END
$$;
