-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- A user who activates their account authenticates with the token of the
-- activation link, before they have a password. The entry names the account as
-- the actor and the token as the method. Requests with an invalid token are not
-- recorded, so anonymous actors never use this method.
ALTER TABLE public.audit_entries
	DROP CONSTRAINT audit_entries_actor_check,
	ADD CONSTRAINT audit_entries_actor_check CHECK (
		CASE actor_kind
			WHEN 'user' THEN auth_method IN ('password', 'oidc', 'session', 'api_key', 'activation_token')
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
