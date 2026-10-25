// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package trigger

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/platform/db"
)

// Store records requests and reports through the database functions
// record_honeytoken_request, record_honeypot_session and
// record_honeypot_heartbeat, the only privileges of the trigger's database
// role.
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

// recordFunctions are the database functions through which the trigger
// records requests and reports, the only privileges of its database role.
var recordFunctions = []string{
	"public.record_honeytoken_request(text, text, inet, text, text, text, text)",
	"public.record_honeypot_session(bytea, uuid, interval, integer, inet, integer, text, text, text, text, text, text, jsonb)",
	"public.record_honeypot_heartbeat(bytea, text)",
}

// CheckPrivileges returns db.ErrRolePrivileges unless the connected role can
// record requests and reports and do nothing else, as a member of
// nyktus_trigger.
func CheckPrivileges(ctx context.Context, q db.Querier) error {
	return db.CheckScope(ctx, q, db.Scope{GroupRole: "nyktus_trigger", Functions: recordFunctions})
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
FROM public.record_honeytoken_request($1, $2, $3, $4, $5, $6, $7)`,
		r.Value, r.Method, ip, r.UserAgent, r.Referer, r.AcceptLanguage, r.Body,
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

// attemptJSON is an attempt as the database function reads it. A password has
// no member: only its length leaves the trigger.
type attemptJSON struct {
	Username       string  `json:"username"`
	PasswordLength *int    `json:"password_length"`
	KeyFingerprint *string `json:"key_fingerprint"`
}

// RecordSession implements Reporter.
func (s *Store) RecordSession(ctx context.Context, secretHash []byte, session Session) (ReportResult, error) {
	attempts := make([]attemptJSON, len(session.Attempts))
	for i, a := range session.Attempts {
		attempts[i] = attemptJSON{Username: a.Username, PasswordLength: a.PasswordLength, KeyFingerprint: nilIfEmpty(a.KeyFingerprint)}
	}
	var baseDN, filter *string
	if session.Query != nil {
		baseDN, filter = &session.Query.BaseDN, &session.Query.Filter
	}
	row := s.q.QueryRow(ctx, `
SELECT outcome, honeypot_id, service
FROM public.record_honeypot_session($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		secretHash, session.ID, session.Age, session.Duration.Milliseconds(), session.ClientIP, session.Port,
		string(session.EventType()), nilIfEmpty(session.ClientVersion), nilIfEmpty(session.Database),
		nilIfEmpty(session.ApplicationName), baseDN, filter, attempts)
	return scanReport(row, "record session")
}

// RecordHeartbeat implements Reporter.
func (s *Store) RecordHeartbeat(ctx context.Context, secretHash []byte, h Heartbeat) (ReportResult, error) {
	row := s.q.QueryRow(ctx, `
SELECT outcome, honeypot_id, service
FROM public.record_honeypot_heartbeat($1, $2)`, secretHash, nilIfEmpty(h.SensorVersion))
	return scanReport(row, "record heartbeat")
}

func scanReport(row pgx.Row, operation string) (ReportResult, error) {
	var outcome string
	var honeypotID, service *string
	if err := row.Scan(&outcome, &honeypotID, &service); err != nil {
		return ReportResult{}, fmt.Errorf("%s: %w", operation, err)
	}
	res := ReportResult{Outcome: ReportOutcome(outcome)}
	switch res.Outcome {
	case ReportUnknown, ReportDisabled, ReportRecorded, ReportLimited, ReportDuplicate, ReportInvalid:
	default:
		return ReportResult{}, fmt.Errorf("%s: unexpected outcome %q", operation, outcome)
	}
	if honeypotID != nil {
		res.HoneypotID = *honeypotID
	}
	if service != nil {
		res.Service = *service
	}
	return res, nil
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
