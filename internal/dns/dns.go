// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dns answers the zones delegated to Nyktus as an authoritative name
// server and records the queries of DNS honeytokens as events.
//
// Whoever sends a query may be the attacker, or a resolver that asks on their
// behalf, so the answer must not tell them anything: it depends only on the
// form of the query, never on whether a name holds the trigger value of a
// honeytoken, whether that honeytoken is enabled, or whether recording the
// query failed. The answer is written before the query is recorded, because
// nothing in it depends on the result.
//
// The DNS role never reads the inventory. It depends on Recorder, which
// resolves one trigger value and records the query in one step.
package dns

import (
	"context"
	"net/netip"
)

// Query is what the DNS role records about a query of a name that holds a
// trigger value.
type Query struct {
	Value string
	// Zone is the zone under which the name was queried, in lower case without
	// a trailing dot.
	Zone string
	// Prefix holds the labels in front of the value, such as "vpn" for
	// "vpn.<value>.<zone>", or is empty. Whoever sends the query chooses them;
	// every character other than a letter, a digit, '-' or '_' is replaced
	// with '?'.
	Prefix string
	// QType is the type of the query, such as "A" or "TYPE65280".
	QType string
	// Transport is "udp" or "tcp".
	Transport string
	// Resolver is the address that sent the query, usually a resolver that
	// asks on behalf of its clients, or the zero Addr if it is unknown.
	Resolver netip.Addr
}

// Outcome says what became of a query.
type Outcome string

// Outcomes of a query of a trigger value.
const (
	// OutcomeUnknown means that the value belongs to no honeytoken.
	OutcomeUnknown Outcome = "unknown"
	// OutcomeDisabled means that the honeytoken is disabled, so the query was
	// not recorded.
	OutcomeDisabled Outcome = "disabled"
	// OutcomeRecorded means that the query was recorded as an event, together
	// with the job that processes it.
	OutcomeRecorded Outcome = "recorded"
	// OutcomeLimited means that the honeytoken reached its limit of events per
	// minute, so the query was not recorded.
	OutcomeLimited Outcome = "limited"
)

// Result is what the DNS role learns about a queried value: enough to log it,
// nothing more.
type Result struct {
	Outcome Outcome
	// HoneytokenID identifies the honeytoken of the value, unless the value is
	// unknown.
	HoneytokenID string
}

// Recorder resolves a trigger value and records its query in one step, so that
// the DNS role can neither look up a value without leaving an event nor learn
// more about a honeytoken than its log needs.
type Recorder interface {
	Record(ctx context.Context, q Query) (Result, error)
}
