-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Administrators list accounts from the newest to the oldest, a page at a time,
-- continuing after the last account of the previous page. The identifier makes
-- the order total for accounts with the same creation time. The address is not
-- used as the position: it would end up in the query string of the next page,
-- and with it in the logs of proxies.
CREATE INDEX users_created_at_id_idx ON public.users (created_at DESC, id DESC);
