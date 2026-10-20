// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package incident correlates events into incidents.
//
// Every event belongs to exactly one incident: the open incident of its
// scenario, or of its resource if it stood alone, or a new one, which raises
// the single alert of the incident. A closed incident is never opened again;
// the next event opens a new one. The worker assigns events through Store. The console reads
// incidents and events and triages incidents through the functions of this
// package; HTTP lives in incidentapi.
package incident

import (
	"slices"

	"nyktus.org/nyktus/internal/honeypot"
	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/scenario"
)

// ResourceTypes lists what an incident can correlate: the events of a
// scenario, or of a honeytoken or honeypot that stood alone.
var ResourceTypes = []string{honeytoken.ResourceType, honeypot.ResourceType, scenario.ResourceType}

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
