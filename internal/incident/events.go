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
	"nyktus.org/nyktus/internal/severity"
)

// ErrEventNotFound means that no event has the identifier.
var ErrEventNotFound = errors.New("event not found")

// Channels on which an event arrives.
const (
	ChannelHTTP   = "http"
	ChannelDNS    = "dns"
	ChannelSensor = "sensor"
)

// Event is a recorded request or query of a honeytoken, or a session of a
// honeypot. It contains personal data: the address of the client, resolver or
// attacker and, over HTTP, headers that the client chose, and for a session the
// user names and the other values that the attacker typed.
type Event struct {
	ID           string
	ResourceType string
	ResourceID   string
	// ScenarioID is the scenario that the resource belonged to when it was
	// requested, or nil if it stood alone.
	ScenarioID *string
	// HoneytokenType and Techniques are those of the honeytoken when it was
	// requested; the techniques of a session are those of the honeypot and of
	// its kind of event.
	HoneytokenType string
	Techniques     []string
	// Severity is the severity of the resource when it was requested.
	Severity severity.Level
	// IncidentID is the incident of the event, or nil until the worker has
	// processed it.
	IncidentID *string
	OccurredAt time.Time
	RecordedAt time.Time
	Channel    string
	// ClientIP is the address of the client, or of the resolver for DNS, or
	// the zero Addr if it is unknown.
	ClientIP netip.Addr
	// The request of an event of the channel http. Body is the start of the body
	// of a POST request, and empty for every other method.
	Method, UserAgent, Referer, AcceptLanguage, Body string
	// The query of an event of the channel dns.
	DNSZone, DNSPrefix, DNSQType, DNSTransport string
	// Sensor is the session of an event of the channel sensor, or nil.
	Sensor *Session
}

// Session is what a sensor reported about a session of an attacker with a
// honeypot. Everything but the service and the kind of event is chosen by the
// attacker or the sensor and is untrusted. It never holds a password, only the
// length of one.
type Session struct {
	// Service is the service of the honeypot when the session ended.
	Service string
	// EventType is the highest stage that the session reached.
	EventType string
	// Port is the port of the honeypot that the attacker reached.
	Port int
	// DurationMS is how long the session lasted.
	DurationMS int
	// What the client said about itself, or nil.
	ClientVersion, Database, ApplicationName *string
	// Query is the first search of a directory client, or nil.
	Query    *SessionQuery
	Attempts []Attempt
}

// SessionQuery is the first search of a session.
type SessionQuery struct {
	BaseDN, Filter string
}

// Attempt is one login or bind of a session.
type Attempt struct {
	Username string
	// PasswordLength is the length of the password that was sent, or nil if
	// none was.
	PasswordLength *int
	// KeyFingerprint is the fingerprint of the public key that was offered,
	// or nil.
	KeyFingerprint *string
}

const eventColumns = `id, resource_type, resource_id, scenario_id, honeytoken_type, techniques, severity, incident_id,
	occurred_at, recorded_at, channel, client_ip, coalesce(method, ''), user_agent, referer, accept_language, body, coalesce(dns_zone, ''),
	coalesce(dns_prefix, ''), coalesce(dns_qtype, ''), coalesce(dns_transport, ''),
	sensor_service, sensor_event_type, sensor_port, sensor_duration_ms, sensor_client_version, sensor_database,
	sensor_application_name, sensor_base_dn, sensor_filter`

func scanEvent(row pgx.Row) (Event, error) {
	var (
		e              Event
		honeytokenType *string
		clientIP       *netip.Addr
		service, kind  *string
		port, duration *int
		client, dbname *string
		appName        *string
		baseDN, filter *string
	)
	err := row.Scan(&e.ID, &e.ResourceType, &e.ResourceID, &e.ScenarioID, &honeytokenType, &e.Techniques, &e.Severity, &e.IncidentID,
		&e.OccurredAt, &e.RecordedAt, &e.Channel, &clientIP, &e.Method, &e.UserAgent, &e.Referer, &e.AcceptLanguage, &e.Body,
		&e.DNSZone, &e.DNSPrefix, &e.DNSQType, &e.DNSTransport,
		&service, &kind, &port, &duration, &client, &dbname, &appName, &baseDN, &filter)
	if honeytokenType != nil {
		e.HoneytokenType = *honeytokenType
	}
	if clientIP != nil {
		e.ClientIP = *clientIP
	}
	if e.Channel == ChannelSensor && err == nil {
		e.Sensor = &Session{
			Service: *service, EventType: *kind, Port: *port, DurationMS: *duration,
			ClientVersion: client, Database: dbname, ApplicationName: appName, Attempts: []Attempt{},
		}
		if baseDN != nil && filter != nil {
			e.Sensor.Query = &SessionQuery{BaseDN: *baseDN, Filter: *filter}
		}
	}
	return e, err
}

// loadAttempts reads the attempts of the sessions among events, which the
// event rows leave out, in the order in which they were made.
func loadAttempts(ctx context.Context, q db.Querier, events []Event) error {
	bySession := map[string]*Session{}
	ids := make([]string, 0, len(events))
	for _, e := range events {
		if e.Sensor != nil {
			bySession[e.ID] = e.Sensor
			ids = append(ids, e.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := q.Query(ctx, `
SELECT event_id, username, password_length, key_fingerprint
FROM public.event_attempts WHERE event_id = ANY($1::uuid[]) ORDER BY event_id, ordinal`, ids)
	if err != nil {
		return fmt.Errorf("load attempts: %w", err)
	}
	var (
		id string
		a  Attempt
	)
	_, err = pgx.ForEachRow(rows, []any{&id, &a.Username, &a.PasswordLength, &a.KeyFingerprint}, func() error {
		s := bySession[id]
		s.Attempts = append(s.Attempts, a)
		return nil
	})
	if err != nil {
		return fmt.Errorf("load attempts: %w", err)
	}
	return nil
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
	if err := loadAttempts(ctx, q, list); err != nil {
		return nil, nil, fmt.Errorf("list events: %w", err)
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
	events := []Event{e}
	if err := loadAttempts(ctx, q, events); err != nil {
		return Event{}, fmt.Errorf("get event %s: %w", id, err)
	}
	return events[0], nil
}
