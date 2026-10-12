// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package attack

import (
	"slices"
	"testing"

	"nyktus.org/nyktus/internal/platform/schematest"
)

// The database checks the form of technique identifiers on its own. Every
// identifier of the list must pass that check, and malformed ones must not.
func TestSchema_AcceptsEveryTechniqueOfTheList(t *testing.T) {
	t.Parallel()

	_, consoleURL := schematest.Console(t)
	pool := schematest.Open(t, consoleURL)

	ids := make([]string, 0, len(techniques))
	for id := range techniques {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var valid bool
	if err := pool.QueryRow(t.Context(), `SELECT public.attack_technique_ids_valid($1)`, ids).Scan(&valid); err != nil || !valid {
		t.Errorf("attack_technique_ids_valid(all %d techniques) = %v, %v; want true", len(ids), valid, err)
	}

	for _, invalid := range [][]string{
		{"T1003", "T1003"},
		{"t1003"},
		{"T1003.1"},
		{"T10031"},
		{"T1003 "},
		{"TA0006"},
		{"T1003", ""},
	} {
		if err := pool.QueryRow(t.Context(), `SELECT public.attack_technique_ids_valid($1)`, invalid).Scan(&valid); err != nil || valid {
			t.Errorf("attack_technique_ids_valid(%q) = %v, %v; want false", invalid, valid, err)
		}
	}
	for _, query := range []string{
		`SELECT public.attack_technique_ids_valid(ARRAY['T1003', NULL])`,
		`SELECT public.attack_technique_ids_valid('{{T1003},{T1005}}')`,
	} {
		if err := pool.QueryRow(t.Context(), query).Scan(&valid); err != nil || valid {
			t.Errorf("%s = %v, %v; want false", query, valid, err)
		}
	}
}
