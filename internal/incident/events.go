// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package incident

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"nyktus.org/nyktus/internal/platform/db"
)

// ErrEventNotFound means that no event has the identifier.
var ErrEventNotFound = errors.New("event not found")

// Channels on which an event arrives.
const (
	ChannelHTTP = "http"
	ChannelDNS  = "dns"
)

// Event is a recorded request or query of a honeytoken. It contains personal
// data: the address of the client or resolver and, over HTTP, headers that the
// client chose.
type Event struct {
	ID           string
	ResourceType string
	ResourceID   string
	// ScenarioID is the scenario that the resource belonged to when it was
	// requested, or nil if it stood alone.
	ScenarioID *string
	// HoneytokenType and Techniques are those of the honeytoken when it was
	// requested.
	HoneytokenType string
	Techniques     []string
	// IncidentID is the incident of the event, or nil until the worker has
	// processed it.
	IncidentID *string
	OccurredAt time.Time
	RecordedAt time.Time
	Channel    string
	// ClientIP is the address of the client, or of the resolver for DNS, or
	// the zero Addr if it is unknown.
	ClientIP netip.Addr
	// The request of an event of the channel http.
	Method, UserAgent, Referer, AcceptLanguage string
	// The query of an event of the channel dns.
	DNSZone, DNSPrefix, DNSQType, DNSTransport string
}

const eventColumns = `id, resource_type, resource_id, scenario_id, honeytoken_type, techniques, incident_id, occurred_at, recorded_at,
	channel, client_ip, coalesce(method, ''), user_agent, referer, accept_language, coalesce(dns_zone, ''),
	coalesce(dns_prefix, ''), coalesce(dns_qtype, ''), coalesce(dns_transport, '')`

func scanEvent(row pgx.Row) (Event, error) {
	var (
		e              Event
		honeytokenType *string
		clientIP       *netip.Addr
	)
	err := row.Scan(&e.ID, &e.ResourceType, &e.ResourceID, &e.ScenarioID, &honeytokenType, &e.Techniques, &e.IncidentID,
		&e.OccurredAt, &e.RecordedAt, &e.Channel, &clientIP, &e.Method, &e.UserAgent, &e.Referer, &e.AcceptLanguage,
		&e.DNSZone, &e.DNSPrefix, &e.DNSQType, &e.DNSTransport)
	if honeytokenType != nil {
		e.HoneytokenType = *honeytokenType
	}
	if clientIP != nil {
		e.ClientIP = *clientIP
	}
	return e, err
}

// EventFilter narrows a list of events. An empty field does not narrow it.
type EventFilter struct {
	// IncidentID lists only the events of one incident.
	IncidentID string
}

// The filter and the cursor are conditions of statements of their own, so
// that a generic plan can seek into the index that serves them.
const (
	eventsOrder = `
ORDER BY recorded_at DESC, id DESC`
	listEventsNewest = `SELECT ` + eventColumns + ` FROM public.events` + eventsOrder + `
LIMIT $1`
	listEventsAfter = `SELECT ` + eventColumns + ` FROM public.events
WHERE (recorded_at, id) < ($1, $2::uuid)` + eventsOrder + `
LIMIT $3`
	listIncidentEventsNewest = `SELECT ` + eventColumns + ` FROM public.events
WHERE incident_id = $1` + eventsOrder + `
LIMIT $2`
	listIncidentEventsAfter = `SELECT ` + eventColumns + ` FROM public.events
WHERE incident_id = $1 AND (recorded_at, id) < ($2, $3::uuid)` + eventsOrder + `
LIMIT $4`
)

// ListEvents returns up to size events that match f, from the most recently
// recorded to the oldest, that come after the cursor after, or from the most
// recent if after is nil. next is the cursor of the following page, or nil if there are
// no more events.
func ListEvents(ctx context.Context, q db.Querier, f EventFilter, size int, after *Cursor) (list []Event, next *Cursor, err error) {
	if size < 1 || size > MaxPageSize {
		return nil, nil, ErrInvalidPageSize
	}
	// One more event than requested tells whether another page follows.
	var rows pgx.Rows
	switch {
	case f.IncidentID != "" && after == nil:
		rows, err = q.Query(ctx, listIncidentEventsNewest, f.IncidentID, size+1)
	case f.IncidentID != "":
		rows, err = q.Query(ctx, listIncidentEventsAfter, f.IncidentID, after.Time, after.ID, size+1)
	case after == nil:
		rows, err = q.Query(ctx, listEventsNewest, size+1)
	default:
		rows, err = q.Query(ctx, listEventsAfter, after.Time, after.ID, size+1)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("list events: %w", err)
	}
	list, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Event, error) { return scanEvent(row) })
	if err != nil {
		return nil, nil, fmt.Errorf("list events: %w", err)
	}
	if len(list) > size {
		list = list[:size]
		last := list[size-1]
		next = &Cursor{Time: last.RecordedAt, ID: last.ID}
	}
	return list, next, nil
}

// GetEvent returns the event id. It returns ErrEventNotFound if there is none.
func GetEvent(ctx context.Context, q db.Querier, id string) (Event, error) {
	e, err := scanEvent(q.QueryRow(ctx, `SELECT `+eventColumns+` FROM public.events WHERE id = $1`, id))
	if db.NotFound(err) {
		return Event{}, ErrEventNotFound
	}
	if err != nil {
		return Event{}, fmt.Errorf("get event %s: %w", id, err)
	}
	return e, nil
}
