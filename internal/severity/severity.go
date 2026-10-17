// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package severity defines how urgently someone should look at what a decoy
// raised: the severity of honeytokens, which their events keep, and of the
// incidents that correlate those events.
package severity

import "slices"

// Level is a severity.
type Level string

// Levels of severity.
const (
	// Info is only an analyst's judgment of an incident that turned out to be
	// irrelevant. No decoy and no event suggests it.
	Info     Level = "info"
	Low      Level = "low"
	Medium   Level = "medium"
	High     Level = "high"
	Critical Level = "critical"
)

// Levels lists every level from the lowest to the highest.
var Levels = []Level{Info, Low, Medium, High, Critical}

// Suggested lists the levels that a decoy and its events can suggest, from
// the lowest to the highest: every level but Info.
var Suggested = []Level{Low, Medium, High, Critical}

// Valid reports whether l is a known level.
func (l Level) Valid() bool {
	return slices.Contains(Levels, l)
}

// IsSuggested reports whether a decoy can suggest l, as Suggested lists.
func (l Level) IsSuggested() bool {
	return slices.Contains(Suggested, l)
}

// Higher returns the higher of a and b.
func Higher(a, b Level) Level {
	if slices.Index(Levels, b) > slices.Index(Levels, a) {
		return b
	}
	return a
}
