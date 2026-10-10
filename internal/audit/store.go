// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"context"
	"fmt"
	"net/netip"

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

	_, err := s.db.Exec(ctx, `
INSERT INTO audit_entries (action, outcome, actor_kind, auth_method, actor_user_id, api_key_id,
	resource_type, resource_id, changed_fields, client_ip, request_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		e.Action, e.Outcome, e.Actor.Kind, e.Actor.Method, nullable(e.Actor.UserID), nullable(e.Actor.APIKeyID),
		nullable(e.Resource.Type), nullable(e.Resource.ID), fields, ip, nullable(e.RequestID))
	if err != nil {
		return fmt.Errorf("record audit entry %s: %w", e.Action, err)
	}
	return nil
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
