// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dns

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"nyktus.org/nyktus/internal/platform/db"
)

// recordFunction is the database function through which the DNS role records
// queries, the only privilege of its database role.
const recordFunction = "public.record_dns_query(text, text, text, text, text, inet, interval)"

// Store records queries through the database function record_dns_query.
type Store struct {
	q db.Querier
}

// NewStore returns a Store that works on q.
func NewStore(q db.Querier) *Store {
	if q == nil {
		panic("dns: nil querier")
	}
	return &Store{q: q}
}

// CheckPrivileges returns db.ErrRolePrivileges unless the connected role can
// record queries and do nothing else, as a member of nyktus_dns.
func CheckPrivileges(ctx context.Context, q db.Querier) error {
	return db.CheckFunctionOnly(ctx, q, "nyktus_dns", recordFunction)
}

// Record implements Recorder.
func (s *Store) Record(ctx context.Context, q Query) (Result, error) {
	var ip *netip.Addr
	if q.Resolver.IsValid() {
		ip = &q.Resolver
	}
	var (
		outcome      string
		honeytokenID *string
	)
	err := s.q.QueryRow(ctx, `
SELECT outcome, honeytoken_id
FROM public.record_dns_query($1, $2, $3, $4, $5, $6, $7)`,
		q.Value, q.Zone, q.Prefix, q.QType, q.Transport, ip, delay(q.ReceivedAt),
	).Scan(&outcome, &honeytokenID)
	if err != nil {
		return Result{}, fmt.Errorf("record query: %w", err)
	}

	res := Result{Outcome: Outcome(outcome)}
	switch res.Outcome {
	case OutcomeUnknown, OutcomeDisabled, OutcomeRecorded, OutcomeLimited:
	default:
		return Result{}, fmt.Errorf("record query: unexpected outcome %q", outcome)
	}
	if honeytokenID != nil {
		res.HoneytokenID = *honeytokenID
	}
	return res, nil
}

// delay returns how long a query received at t has waited, measured with the
// monotonic clock of the process, or nil for the zero time, which the database
// records as the time of writing.
func delay(t time.Time) *time.Duration {
	if t.IsZero() {
		return nil
	}
	d := time.Since(t)
	return &d
}
