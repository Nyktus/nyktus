// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package trigger

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"nyktus.org/nyktus/internal/platform/db"
)

// Store records requests through the database function
// record_honeytoken_request, the only privilege of the trigger's database role.
type Store struct {
	q db.Querier
}

// NewStore returns a Store that works on q.
func NewStore(q db.Querier) *Store {
	if q == nil {
		panic("trigger: nil querier")
	}
	return &Store{q: q}
}

// ErrPrivileges is returned when the database role of the trigger holds other
// privileges than its own.
var ErrPrivileges = errors.New("database role of the trigger has other privileges than nyktus_trigger")

// CheckPrivileges returns ErrPrivileges unless the connected role can record
// requests and cannot read or write any table. The trigger is reached from the
// internet, so a login with the privileges of the console, set up by mistake,
// would put the inventory within reach of whoever takes over its host; a login
// without the function would answer every request and record none.
func CheckPrivileges(ctx context.Context, q db.Querier) error {
	var canRecord bool
	var tables []string
	err := q.QueryRow(ctx, `
SELECT has_function_privilege('public.record_honeytoken_request(text, text, inet, text, text, text)', 'EXECUTE'),
	ARRAY(
		SELECT c.relname::text FROM pg_catalog.pg_class AS c
		WHERE c.relnamespace = 'public'::regnamespace
			AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
			AND (has_table_privilege(c.oid, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
				OR has_any_column_privilege(c.oid, 'SELECT, INSERT, UPDATE, REFERENCES'))
		ORDER BY c.relname
	)`).Scan(&canRecord, &tables)
	switch {
	case err != nil:
		return fmt.Errorf("check privileges of the trigger: %w", err)
	case !canRecord:
		return fmt.Errorf("%w: it cannot execute record_honeytoken_request; connect as a member of nyktus_trigger", ErrPrivileges)
	case len(tables) > 0:
		return fmt.Errorf("%w: it can access the tables %v; connect with a login that is a member of nyktus_trigger only", ErrPrivileges, tables)
	}
	return nil
}

// Record implements Recorder.
func (s *Store) Record(ctx context.Context, r Request) (Result, error) {
	var ip *netip.Addr
	if r.ClientIP.IsValid() {
		ip = &r.ClientIP
	}
	var (
		outcome      string
		honeytokenID *string
		redirectURL  *string
	)
	err := s.q.QueryRow(ctx, `
SELECT outcome, honeytoken_id, redirect_url
FROM public.record_honeytoken_request($1, $2, $3, $4, $5, $6)`,
		r.Value, r.Method, ip, r.UserAgent, r.Referer, r.AcceptLanguage,
	).Scan(&outcome, &honeytokenID, &redirectURL)
	if err != nil {
		return Result{}, fmt.Errorf("record request: %w", err)
	}

	res := Result{Outcome: Outcome(outcome)}
	switch res.Outcome {
	case OutcomeUnknown, OutcomeDisabled, OutcomeRecorded, OutcomeLimited:
	default:
		return Result{}, fmt.Errorf("record request: unexpected outcome %q", outcome)
	}
	if honeytokenID != nil {
		res.HoneytokenID = *honeytokenID
	}
	if redirectURL != nil {
		res.RedirectURL = *redirectURL
	}
	return res, nil
}
