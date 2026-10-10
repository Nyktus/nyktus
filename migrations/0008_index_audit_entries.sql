-- SPDX-FileCopyrightText: The Nyktus Authors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- The console lists audit entries from the newest to the oldest, a page at a
-- time, continuing after the last entry of the previous page. The identifier
-- makes the order total for entries with the same time.
CREATE INDEX audit_entries_occurred_at_id_idx ON public.audit_entries (occurred_at DESC, id DESC);
