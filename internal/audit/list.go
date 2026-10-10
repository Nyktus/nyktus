// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
)

// StoredEntry is an entry as recorded, with what the database added.
type StoredEntry struct {
	ID         string
	OccurredAt time.Time
	Entry
	// ActorEmail and ActorDisplayName are the copies taken from the account of a
	// user actor when the entry was written. They stay after the account is
	// deleted, while Actor.UserID is then empty.
	ActorEmail       string
	ActorDisplayName string
}

// Cursor marks the position after the last entry of a page.
type Cursor struct {
	OccurredAt time.Time
	ID         string
}

// MaxPageSize is the largest page that List returns.
const MaxPageSize = 200

// ErrInvalidPageSize is returned for a page size outside [1, MaxPageSize].
var ErrInvalidPageSize = errors.New("invalid page size")

const listColumns = `
SELECT id, occurred_at, action, outcome, actor_kind, auth_method,
	coalesce(actor_user_id::text, ''), coalesce(actor_email, ''), coalesce(actor_display_name, ''),
	coalesce(api_key_id::text, ''), coalesce(resource_type, ''), coalesce(resource_id::text, ''),
	changed_fields, client_ip, coalesce(request_id, '')
FROM audit_entries`

const (
	listNewest = listColumns + `
ORDER BY occurred_at DESC, id DESC
LIMIT $1`
	listAfter = listColumns + `
WHERE (occurred_at, id) < ($1, $2::uuid)
ORDER BY occurred_at DESC, id DESC
LIMIT $3`
)

// List returns up to size entries, from the newest to the oldest, that come after
// the cursor after, or from the newest if after is nil. next is the cursor of the
// following page, or nil if there are no more entries.
//
// Paging continues after the last entry instead of skipping a number of entries,
// so that entries recorded meanwhile neither repeat nor hide entries on the next
// page. Entries are ordered by the time they were written, not by the time their
// transaction committed: an entry of a transaction that commits later than
// others can appear behind entries a reader has already passed. Entries with the
// same time are ordered by their identifier, which makes the order total but
// says nothing about which came first.
func (s *Store) List(ctx context.Context, size int, after *Cursor) (entries []StoredEntry, next *Cursor, err error) {
	if size < 1 || size > MaxPageSize {
		return nil, nil, ErrInvalidPageSize
	}
	// One more entry than requested tells whether another page follows. The
	// query without a cursor is a separate statement: a condition that is only
	// sometimes active would keep a generic plan from seeking into the index.
	var rows pgx.Rows
	if after == nil {
		rows, err = s.db.Query(ctx, listNewest, size+1)
	} else {
		rows, err = s.db.Query(ctx, listAfter, after.OccurredAt, after.ID, size+1)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("list audit entries: %w", err)
	}
	entries, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (StoredEntry, error) {
		var (
			e  StoredEntry
			ip *netip.Addr
		)
		err := row.Scan(&e.ID, &e.OccurredAt, &e.Action, &e.Outcome, &e.Actor.Kind, &e.Actor.Method,
			&e.Actor.UserID, &e.ActorEmail, &e.ActorDisplayName, &e.Actor.APIKeyID, &e.Resource.Type, &e.Resource.ID,
			&e.ChangedFields, &ip, &e.RequestID)
		if ip != nil {
			e.ClientIP = *ip
		}
		e.OccurredAt = e.OccurredAt.UTC()
		return e, err
	})
	if err != nil {
		return nil, nil, fmt.Errorf("list audit entries: %w", err)
	}
	if len(entries) > size {
		entries = entries[:size]
		last := entries[size-1]
		next = &Cursor{OccurredAt: last.OccurredAt, ID: last.ID}
	}
	return entries, next, nil
}
