-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- A link that lets a user set their password serves two purposes: activating a
-- new account and resetting the password of an active one. Both are issued by an
-- administrator and passed on by hand, so they share one table, and an account
-- still has at most one open link. The purpose is stored so that each public
-- endpoint consumes only links issued for it.
DO $$
BEGIN
	IF to_regrole('nyktus_console') IS NULL THEN
		RAISE EXCEPTION 'database role nyktus_console does not exist; create the server roles with deploy/postgres/roles.sql before running migrations';
	END IF;
END
$$;

ALTER TABLE public.activation_tokens RENAME TO account_links;
ALTER TABLE public.account_links RENAME CONSTRAINT activation_tokens_pkey TO account_links_pkey;
ALTER TABLE public.account_links RENAME CONSTRAINT activation_tokens_user_id_fkey TO account_links_user_id_fkey;
ALTER TABLE public.account_links RENAME CONSTRAINT activation_tokens_token_hash_key TO account_links_token_hash_key;
ALTER TABLE public.account_links RENAME CONSTRAINT activation_tokens_token_hash_check TO account_links_token_hash_check;

-- Open links were all issued for activation. The default only fills them; the
-- console names the purpose of every new link.
ALTER TABLE public.account_links ADD COLUMN purpose text NOT NULL DEFAULT 'activation'
	CONSTRAINT account_links_purpose_check CHECK (purpose IN ('activation', 'password_reset'));
ALTER TABLE public.account_links ALTER COLUMN purpose DROP DEFAULT;
-- expires_at keeps its default of 72 hours for both purposes: both links travel
-- the same way and carry the same risk.

-- The holder of a password reset link acts as the user of the account.
ALTER TABLE public.audit_entries DROP CONSTRAINT audit_entries_actor_check;
ALTER TABLE public.audit_entries ADD CONSTRAINT audit_entries_actor_check CHECK (
	CASE actor_kind
		WHEN 'user' THEN auth_method IN ('password', 'oidc', 'session', 'api_key', 'activation_token', 'password_reset_token')
			AND actor_email IS NOT NULL AND actor_display_name IS NOT NULL
		WHEN 'setup' THEN auth_method = 'setup_token'
			AND actor_user_id IS NULL AND actor_email IS NULL AND actor_display_name IS NULL
		WHEN 'system' THEN auth_method IN ('cli', 'none')
			AND actor_user_id IS NULL AND actor_email IS NULL AND actor_display_name IS NULL
		WHEN 'anonymous' THEN auth_method IN ('password', 'oidc', 'setup_token')
			AND actor_user_id IS NULL AND actor_email IS NULL AND actor_display_name IS NULL
		ELSE false
	END
);

-- Default privileges set by an operator could grant more than this migration
-- intends, so everything is revoked before the grants.
REVOKE ALL ON public.account_links FROM PUBLIC, nyktus_console;

-- The console issues, looks up and consumes links. It never changes one.
GRANT SELECT, DELETE ON public.account_links TO nyktus_console;
GRANT INSERT (user_id, token_hash, purpose) ON public.account_links TO nyktus_console;

-- GRANT and REVOKE only warn when the executing role lacks the privilege, so the
-- result is verified instead of assumed, in both directions.
DO $$
BEGIN
	IF NOT has_table_privilege('nyktus_console', 'public.account_links', 'SELECT')
		OR NOT has_table_privilege('nyktus_console', 'public.account_links', 'DELETE')
		OR NOT has_column_privilege('nyktus_console', 'public.account_links', 'user_id', 'INSERT')
		OR NOT has_column_privilege('nyktus_console', 'public.account_links', 'token_hash', 'INSERT')
		OR NOT has_column_privilege('nyktus_console', 'public.account_links', 'purpose', 'INSERT') THEN
		RAISE EXCEPTION 'nyktus_console lacks privileges on public.account_links; run migrations as the owner of the schema';
	END IF;

	IF has_table_privilege('nyktus_console', 'public.account_links', 'INSERT')
		OR has_table_privilege('nyktus_console', 'public.account_links', 'UPDATE, TRUNCATE, REFERENCES, TRIGGER')
		OR has_any_column_privilege('nyktus_console', 'public.account_links', 'UPDATE, REFERENCES')
		OR has_column_privilege('nyktus_console', 'public.account_links', 'expires_at', 'INSERT') THEN
		RAISE EXCEPTION 'nyktus_console has more privileges on public.account_links than granted; check the default privileges of the owner';
	END IF;
END
$$;
