// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package trigger

import (
	"context"
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

// recordFunction is the database function through which the trigger records
// requests, the only privilege of its database role.
const recordFunction = "public.record_honeytoken_request(text, text, inet, text, text, text)"

// CheckPrivileges returns db.ErrRolePrivileges unless the connected role can
// record requests and do nothing else, as a member of nyktus_trigger.
func CheckPrivileges(ctx context.Context, q db.Querier) error {
	return db.CheckFunctionOnly(ctx, q, "nyktus_trigger", recordFunction)
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
