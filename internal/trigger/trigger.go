// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trigger answers the requests of honeytokens from the internet and
// records them as events.
//
// Whoever requests a URL of the trigger may be the attacker, so the response
// must not tell them anything: it depends only on the form of the request, never
// on whether the value belongs to a honeytoken, whether that honeytoken is
// enabled, or whether recording the request failed. The only exception is the
// redirect target that the operator configured for a honeytoken.
//
// The trigger never reads the inventory. It depends on Recorder, which resolves
// one trigger value and records the request in one step.
package trigger

import (
	"context"
	"net/netip"
)

// Request is what the trigger records about a request of a trigger value.
type Request struct {
	Value  string
	Method string
	// ClientIP is the address of the client, or the zero Addr if it is unknown.
	ClientIP netip.Addr
	// Headers of the request. Whoever sends the request chooses them, so they
	// are untrusted: they describe what the client claims to be.
	UserAgent      string
	Referer        string
	AcceptLanguage string
}

// Outcome says what became of a request.
type Outcome string

// Outcomes of a request of a trigger value.
const (
	// OutcomeUnknown means that the value belongs to no honeytoken.
	OutcomeUnknown Outcome = "unknown"
	// OutcomeDisabled means that the honeytoken is disabled, so the request was
	// not recorded.
	OutcomeDisabled Outcome = "disabled"
	// OutcomeRecorded means that the request was recorded as an event, together
	// with the job that processes it.
	OutcomeRecorded Outcome = "recorded"
	// OutcomeLimited means that the honeytoken reached its limit of events per
	// minute, so the request was not recorded.
	OutcomeLimited Outcome = "limited"
)

// Result is what the trigger learns about a requested value: enough to answer
// the request and to log it, nothing more.
type Result struct {
	Outcome Outcome
	// HoneytokenID identifies the honeytoken of the value, unless the value is
	// unknown.
	HoneytokenID string
	// RedirectURL is the redirect target configured for the honeytoken, or empty
	// for the default target.
	RedirectURL string
}

// Recorder resolves a trigger value and records its request in one step, so
// that the trigger can neither look up a value without leaving an event nor
// learn more about a honeytoken than its answer needs.
type Recorder interface {
	Record(ctx context.Context, r Request) (Result, error)
}
