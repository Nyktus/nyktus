// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/schematest"
)

// The migration checks the grants of the console on honeypots in both
// directions: a grant that went missing and one that an operator widened both
// stop it.
func TestApply_VerifiesThePrivilegesOfTheConsoleOnHoneypots(t *testing.T) {
	t.Parallel()

	const grant = "GRANT INSERT (service, name, notes, enabled, techniques, severity, secret_hash) ON public.honeypots TO nyktus_console;"
	tests := []struct {
		name, replacement, want string
	}{
		{
			name:        "missing",
			replacement: "GRANT INSERT (service, name, notes, enabled, techniques, severity) ON public.honeypots TO nyktus_console;",
			want:        "nyktus_console lacks privileges on public.honeypots",
		},
		{
			name:        "wider insert",
			replacement: grant + " GRANT INSERT (last_seen_at) ON public.honeypots TO nyktus_console;",
			want:        "nyktus_console has more privileges on public.honeypots than granted",
		},
		{
			name:        "wider update",
			replacement: grant + " GRANT UPDATE (service) ON public.honeypots TO nyktus_console;",
			want:        "nyktus_console has more privileges on public.honeypots than granted",
		},
		{
			name:        "report written by the console",
			replacement: grant + " GRANT UPDATE (last_seen_at) ON public.honeypots TO nyktus_console;",
			want:        "nyktus_console has more privileges on public.honeypots than granted",
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
