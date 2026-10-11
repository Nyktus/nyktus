// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/request"
)

// Store writes audit entries to PostgreSQL.
type Store struct {
	db db.Querier
}

// NewStore returns a Store that runs its queries on q. To record an action
// atomically with its entry, pass the transaction of the action: an action then
// never happens without its entry, and a rolled-back action leaves none.
func NewStore(q db.Querier) *Store {
	if q == nil {
		panic("audit: nil querier")
	}
	return &Store{db: q}
}

// Record appends e to the audit log. The database sets the identifier and the
// time of the entry and copies the address and display name of a user actor from
// the account.
//
// The schema is the only validation. Entries are built by code, not from input,
// so a rejected entry is a programming error, and the caller's action must fail
// with it.
func (s *Store) Record(ctx context.Context, e Entry) error {
	_, err := s.db.Exec(ctx, `
INSERT INTO audit_entries (action, outcome, actor_kind, auth_method, actor_user_id, api_key_id,
	resource_type, resource_id, changed_fields, client_ip, request_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, args(e)...)
	if err != nil {
		return fmt.Errorf("record audit entry %s: %w", e.Action, err)
	}
	return nil
}

// RepeatWindow is the period in which RecordUnlessRepeated records an entry of a
// user only once.
const RepeatWindow = time.Minute

// RecordUnlessRepeated appends e unless the same user, through the same API key
// or without one, has an entry with the same action and outcome from the last
// RepeatWindow. Each key is recorded on its own, so that the requests of a
// leaked key cannot hide behind those of another key or a session. It is meant for entries that a
// signed-in user can cause at will, such as reads and denied requests, so that
// repeating them cannot fill the append-only log. The access log still records
// every request. e must have a user actor.
//
// The check runs in the database, so it holds across console processes.
// Concurrent calls can each add an entry, which is accepted.
func (s *Store) RecordUnlessRepeated(ctx context.Context, e Entry) error {
	if e.Actor.UserID == "" {
		return fmt.Errorf("record audit entry %s once per window: no user actor", e.Action)
	}
	_, err := s.db.Exec(ctx, `
INSERT INTO audit_entries (action, outcome, actor_kind, auth_method, actor_user_id, api_key_id,
	resource_type, resource_id, changed_fields, client_ip, request_id)
SELECT $1, $2, $3, $4, $5::uuid, $6::uuid, $7, $8::uuid, $9::text[], $10::inet, $11
WHERE NOT EXISTS (
	SELECT FROM audit_entries
	WHERE actor_user_id = $5::uuid AND api_key_id IS NOT DISTINCT FROM $6::uuid AND action = $1 AND outcome = $2
		AND occurred_at > clock_timestamp() - $12::interval
)`, append(args(e), RepeatWindow)...)
	if err != nil {
		return fmt.Errorf("record audit entry %s: %w", e.Action, err)
	}
	return nil
}

func args(e Entry) []any {
	fields := e.ChangedFields
	if fields == nil {
		fields = []string{}
	}
	var ip *netip.Addr
	if e.ClientIP.IsValid() {
		// Entries can carry an address from elsewhere than the request context,
		// so every address is stored in its one canonical spelling.
		addr := request.CanonicalAddr(e.ClientIP)
		ip = &addr
	}
	return []any{
		e.Action, e.Outcome, e.Actor.Kind, e.Actor.Method, nullable(e.Actor.UserID), nullable(e.Actor.APIKeyID),
		nullable(e.Resource.Type), nullable(e.Resource.ID), fields, ip, nullable(e.RequestID),
	}
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
