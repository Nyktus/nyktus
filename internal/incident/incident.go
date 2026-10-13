// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package incident correlates events into incidents.
//
// Every event belongs to exactly one incident: the open incident of its
// resource, or a new one, which raises the single alert of the incident. A
// closed incident is never opened again; the next event of its resource opens
// a new one. The worker assigns events through Store; triage happens on the
// incidents.
package incident

import (
	"fmt"
	"slices"

	"nyktus.org/nyktus/internal/honeytoken"
)

// Status is where an incident stands in triage. It only moves forward, in the
// order of Statuses.
type Status string

// Statuses of an incident.
const (
	// StatusOpen is an incident that nobody has looked at yet.
	StatusOpen Status = "open"
	// StatusAcknowledged is an incident that someone is looking into. It still
	// collects the events of its resource.
	StatusAcknowledged Status = "acknowledged"
	// StatusClosed is an incident whose triage is finished. It collects no
	// more events.
	StatusClosed Status = "closed"
)

// Statuses lists every status in the order in which an incident moves through
// them.
var Statuses = []Status{StatusOpen, StatusAcknowledged, StatusClosed}

// Severity says how urgently an analyst should look at an incident.
type Severity string

// Severities of events and incidents.
const (
	// SeverityInfo is only an analyst's judgment of an incident that turned out
	// to be irrelevant. No event suggests it.
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Severities lists every severity from the lowest to the highest.
var Severities = []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// higher returns the higher of a and b.
func higher(a, b Severity) Severity {
	if slices.Index(Severities, b) > slices.Index(Severities, a) {
		return b
	}
	return a
}

// honeytokenSeverity is the severity that an event of a honeytoken suggests,
// by its type. Without knowing what the honeytoken pretends to be, it only
// reflects how much harmless traffic triggers it.
var honeytokenSeverity = map[honeytoken.Type]Severity{
	// Opening a URL is deliberate, but whatever it pretends to lead to is
	// unknown.
	honeytoken.TypeWebURL: SeverityMedium,
	// Mail gateways, previews and scanners load images without a human
	// opening anything.
	honeytoken.TypeWebImage: SeverityLow,
	// Resolving a name is deliberate, as for a URL.
	honeytoken.TypeDNS: SeverityMedium,
}

// eventSeverity returns the severity that an event of a resource suggests.
// honeytokenType is the type of the honeytoken that the event froze.
func eventSeverity(resourceType string, honeytokenType *string) (Severity, error) {
	if resourceType != honeytoken.ResourceType || honeytokenType == nil {
		return "", fmt.Errorf("no severity for events of resource type %q", resourceType)
	}
	s, ok := honeytokenSeverity[honeytoken.Type(*honeytokenType)]
	if !ok {
		return "", fmt.Errorf("no severity for honeytokens of type %q", *honeytokenType)
	}
	return s, nil
}

// union returns a followed by the elements of b that a lacks. It never returns
// nil, which would be written as NULL.
func union(a, b []string) []string {
	out := append([]string{}, a...)
	for _, s := range b {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
