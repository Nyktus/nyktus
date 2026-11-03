// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/schematest"
)

// The migration checks the grants of the console on honeytokens in both
// directions: a grant that went missing, among them the scenario that a
// honeytoken joins when it is created, and one that an operator widened both
// stop it.
func TestApply_VerifiesThePrivilegesOfTheConsoleOnHoneytokens(t *testing.T) {
	t.Parallel()

	const grant = "GRANT INSERT (type, name, notes, enabled, redirect_url, techniques, severity, trigger_value, scenario_id) ON public.honeytokens TO nyktus_console;"
	tests := []struct {
		name, replacement, want string
	}{
		{
			name:        "missing scenario",
			replacement: "GRANT INSERT (type, name, notes, enabled, redirect_url, techniques, severity, trigger_value) ON public.honeytokens TO nyktus_console;",
			want:        "nyktus_console lacks privileges on public.honeytokens",
		},
		{
			name:        "missing trigger value",
			replacement: "GRANT INSERT (type, name, notes, enabled, redirect_url, techniques, severity, scenario_id) ON public.honeytokens TO nyktus_console;",
			want:        "nyktus_console lacks privileges on public.honeytokens",
		},
		{
			name:        "wider insert",
			replacement: grant + " GRANT INSERT (id) ON public.honeytokens TO nyktus_console;",
			want:        "nyktus_console has more privileges on public.honeytokens than granted",
		},
		{
			name:        "wider update",
			replacement: grant + " GRANT UPDATE (trigger_value) ON public.honeytokens TO nyktus_console;",
			want:        "nyktus_console has more privileges on public.honeytokens than granted",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			all := load(t)
			found := false
			for i := range all {
				if strings.Contains(all[i].SQL, grant) {
					all[i].SQL = strings.Replace(all[i].SQL, grant, tt.replacement, 1)
					found = true
				}
			}
			if !found {
				t.Fatalf("the migrations do not contain %q", grant)
			}
			dbURL := dbtest.New(t)
			schematest.GroupRoles(t)
			if err := apply(t, dbURL, all); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Apply() error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}
