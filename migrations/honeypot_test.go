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

	const grant = "GRANT INSERT (service, name, notes, enabled, techniques, severity, secret_hash, secret_sealed, scenario_id) ON public.honeypots TO nyktus_console;"
	tests := []struct {
		name, replacement, want string
	}{
		{
			name:        "missing",
			replacement: "GRANT INSERT (service, name, notes, enabled, techniques, severity, secret_hash, scenario_id) ON public.honeypots TO nyktus_console;",
			want:        "nyktus_console lacks privileges on public.honeypots",
		},
		{
			name:        "missing without scenario",
			replacement: "GRANT INSERT (service, name, notes, enabled, techniques, severity, secret_hash, secret_sealed) ON public.honeypots TO nyktus_console;",
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
			name:        "trigger function executable by the console",
			replacement: grant + " GRANT EXECUTE ON FUNCTION public.honeypots_clear_report() TO nyktus_console;",
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

// The migration checks the grants of the trigger and of the console for the
// reports of sensors in both directions as well: a grant that went missing and
// one that an operator widened both stop it.
func TestApply_VerifiesThePrivilegesForReportsOfSensors(t *testing.T) {
	t.Parallel()

	const (
		heartbeatGrant = "GRANT EXECUTE ON FUNCTION public.record_honeypot_heartbeat(bytea, text) TO nyktus_trigger;"
		eventsGrant    = "GRANT SELECT ON public.events, public.event_attempts, public.event_tool_calls, public.incidents TO nyktus_console;"
		statusGrant    = "GRANT EXECUTE ON FUNCTION public.honeypot_status(timestamptz) TO nyktus_console;"
	)
	tests := []struct {
		name, anchor, replacement, want string
	}{
		{
			name: "heartbeat function missing for the trigger", anchor: heartbeatGrant, replacement: "",
			want: "nyktus_trigger lacks privileges on public.record_honeypot_heartbeat(bytea, text)",
		},
		{
			name: "status function executable by the trigger", anchor: heartbeatGrant,
			replacement: heartbeatGrant + " GRANT EXECUTE ON FUNCTION public.honeypot_status(timestamptz) TO nyktus_trigger;",
			want:        "nyktus_trigger has more privileges than granted",
		},
		{
			name: "attempts readable by the trigger", anchor: heartbeatGrant,
			replacement: heartbeatGrant + " GRANT SELECT ON public.event_attempts TO nyktus_trigger;",
			want:        "nyktus_trigger has more privileges than granted",
		},
		{
			name: "honeypots readable by the trigger", anchor: heartbeatGrant,
			replacement: heartbeatGrant + " GRANT SELECT (secret_hash) ON public.honeypots TO nyktus_trigger;",
			want:        "nyktus_trigger has more privileges than granted",
		},
		{
			name: "attempts unreadable by the console", anchor: eventsGrant,
			replacement: "GRANT SELECT ON public.events, public.event_tool_calls, public.incidents TO nyktus_console;",
			want:        "nyktus_console lacks privileges on events or incidents",
		},
		{
			name: "tool calls unreadable by the console", anchor: eventsGrant,
			replacement: "GRANT SELECT ON public.events, public.event_attempts, public.incidents TO nyktus_console;",
			want:        "nyktus_console lacks privileges on events or incidents",
		},
		{
			name: "tool calls writable by the console", anchor: eventsGrant,
			replacement: eventsGrant + " GRANT INSERT ON public.event_tool_calls TO nyktus_console;",
			want:        "nyktus_console has more privileges on events or incidents than granted",
		},
		{
			name: "attempts writable by the console", anchor: eventsGrant,
			replacement: eventsGrant + " GRANT INSERT ON public.event_attempts TO nyktus_console;",
			want:        "nyktus_console has more privileges on events or incidents than granted",
		},
		{
			name: "session function executable by the console", anchor: eventsGrant,
			replacement: eventsGrant + " GRANT EXECUTE ON FUNCTION public.record_honeypot_heartbeat(bytea, text) TO nyktus_console;",
			want:        "nyktus_console has more privileges on events or incidents than granted",
		},
		{
			name: "status function missing for the console", anchor: statusGrant, replacement: "",
			want: "nyktus_console lacks privileges on public.honeypot_status()",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			all := load(t)
			found := false
			for i := range all {
				if strings.Contains(all[i].SQL, tt.anchor) {
					all[i].SQL = strings.Replace(all[i].SQL, tt.anchor, tt.replacement, 1)
					found = true
				}
			}
			if !found {
				t.Fatalf("the migrations do not contain %q", tt.anchor)
			}
			dbURL := dbtest.New(t)
			schematest.GroupRoles(t)
			if err := apply(t, dbURL, all); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Apply() error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}
