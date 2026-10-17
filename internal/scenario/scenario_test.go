// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenario_test

import (
	"errors"
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/scenario"
)

// The validation holds the limits of the schema on its own, so that a row the
// schema would reject never reaches the database and its log.
func TestValidate_HoldsTheLimitsOfTheSchema(t *testing.T) {
	t.Parallel()

	ids := engageIDs(t)
	for _, tt := range []struct {
		name string
		err  error
		want error
	}{
		{"longest name", scenario.ValidateName(strings.Repeat("\u00e4", scenario.MaxNameLength)), nil},
		{"long name", scenario.ValidateName(strings.Repeat("x", scenario.MaxNameLength+1)), scenario.ErrInvalidName},
		{"empty name", scenario.ValidateName(""), scenario.ErrInvalidName},
		{"longest notes", scenario.ValidateNotes(strings.Repeat("x", scenario.MaxNotesLength)), nil},
		{"long notes", scenario.ValidateNotes(strings.Repeat("x", scenario.MaxNotesLength+1)), scenario.ErrInvalidNotes},
		{"no activities", scenario.ValidateEngageActivities(nil), nil},
		{"most activities", scenario.ValidateEngageActivities(ids[:scenario.MaxEngageActivities]), nil},
		{"too many activities", scenario.ValidateEngageActivities(ids[:scenario.MaxEngageActivities+1]), scenario.ErrInvalidEngageActivities},
		{"unknown activity", scenario.ValidateEngageActivities([]string{"EAC9999"}), scenario.ErrInvalidEngageActivities},
		{"repeated activity", scenario.ValidateEngageActivities([]string{ids[0], ids[0]}), scenario.ErrInvalidEngageActivities},
	} {
		if !errors.Is(tt.err, tt.want) || (tt.want == nil && tt.err != nil) {
			t.Errorf("%s: error = %v, want %v", tt.name, tt.err, tt.want)
		}
	}
}
