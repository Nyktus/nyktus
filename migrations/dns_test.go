// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/schematest"
)

const recordQuery = "SELECT * FROM public.record_dns_query(repeat('a', 26), 'd.example.com', '', 'A', 'udp', NULL, interval '0')"

func TestDNSRole_PassesLeastPrivilegeCheck(t *testing.T) {
	t.Parallel()

	_, dnsURL := schematest.DNS(t)
	if err := db.CheckLeastPrivilege(t.Context(), schematest.Open(t, dnsURL)); err != nil {
		t.Errorf("CheckLeastPrivilege() error = %v, want nil", err)
	}
}

// The DNS role answers queries from the internet. Whoever controls it must not
// be able to read the inventory, so its role cannot read, or write to, any table
// directly; it records queries through one function.
func TestDNSRole_CannotSelectFromAnyTable(t *testing.T) {
	t.Parallel()

	ownerURL, dnsURL := schematest.DNS(t)
	tables := relations(t, ownerURL)
	if len(tables) < 10 {
		t.Fatalf("found %d tables, want the whole schema", len(tables))
	}

	pool := schematest.Open(t, dnsURL)
	for _, table := range tables {
		ident := pgx.Identifier{"public", table}.Sanitize()
		for _, statement := range []string{
			"SELECT count(*) FROM " + ident,
			"DELETE FROM " + ident,
			"TRUNCATE " + ident,
		} {
			expectDenied(t, pool, statement)
		}
	}
	if _, err := pool.Exec(t.Context(), recordQuery); err != nil {
		t.Errorf("%s: error = %v, want nil", recordQuery, err)
	}
}

// Each internet-facing role records through its own function only: the DNS
// role cannot record requests of the trigger, nor the trigger queries of the
// DNS role, nor either of them call the helper of the limit.
func TestDNSRole_HasOnlyGrantedPrivileges(t *testing.T) {
	t.Parallel()

	ownerURL, dnsURL := schematest.DNS(t)
	pool := schematest.Open(t, dnsURL)
	for _, statement := range []string{
		"CREATE TABLE extra (id int)",
		"INSERT INTO events (resource_type, resource_id, honeytoken_type, channel, dns_zone, dns_prefix, dns_qtype, dns_transport, resource_name) VALUES ('honeytoken', gen_random_uuid(), 'dns', 'dns', 'd.example.com', '', 'A', 'udp', 'Name')",
		"INSERT INTO event_jobs (event_id) VALUES (gen_random_uuid())",
		"UPDATE honeytokens SET enabled = true",
		recordRequest,
		"SELECT public.event_limit_reached(gen_random_uuid())",
		"SELECT public.untrusted_text_valid('a', 1)",
		"SELECT public.attack_technique_ids_valid('{T1078}')",
	} {
		expectDenied(t, pool, statement)
	}

	_, triggerURL := dbtest.Role(t, ownerURL, "trigger", "IN ROLE "+pgx.Identifier{schematest.TriggerRole}.Sanitize())
	triggerPool := schematest.Open(t, triggerURL)
	expectDenied(t, triggerPool, recordQuery)
	expectDenied(t, triggerPool, "SELECT public.event_limit_reached(gen_random_uuid())")
}

func TestDNSRole_HasNoPrivilegesBeyondItsFunction(t *testing.T) {
	t.Parallel()

	if held := rolePrivileges(t, schematest.New(t), schematest.DNSRole, dnsFunctions...); len(held) > 0 {
		t.Errorf("nyktus_dns holds %v, want nothing beyond EXECUTE on record_dns_query", held)
	}
}

// Default privileges that an operator set for the owner also apply when they
// name the DNS role's group role. The migration must remove them, including on
// the table of the migration runner, which exists before the migration runs.
func TestApply_IgnoresDefaultPrivilegesOfTheDNSRole(t *testing.T) {
	t.Parallel()

	dbURL := dbtest.New(t)
	schematest.GroupRoles(t)
	dns := pgx.Identifier{schematest.DNSRole}.Sanitize()
	dbtest.Exec(t, dbURL,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "+dns,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO "+dns,
	)
	if err := apply(t, dbURL, load(t)); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if held := rolePrivileges(t, dbURL, schematest.DNSRole, dnsFunctions...); len(held) > 0 {
		t.Errorf("nyktus_dns holds %v, want nothing beyond EXECUTE on record_dns_query", held)
	}
}

// The schema is the last line of defense: the columns of a channel are set
// exactly for its events, and the DNS columns hold only what the DNS role
// produces.
func TestSchema_ChecksEventsOfChannels(t *testing.T) {
	t.Parallel()

	pool := schematest.Open(t, schematest.New(t))
	const insert = `INSERT INTO events (resource_type, resource_id, honeytoken_type, severity, occurred_at, recorded_at, channel, method,
	user_agent, dns_zone, dns_prefix, dns_qtype, dns_transport, resource_name) VALUES ('honeytoken', gen_random_uuid(), 'dns', 'medium', now() - $8::interval, now(), $1, $2, $3, $4, $5, $6, $7, 'Name')`
	httpRow := []any{"http", "GET", "", nil, nil, nil, nil, "0s"}
	dnsRow := []any{"dns", nil, "", "d.example.com", "vpn", "A", "udp", "5m"}
	with := func(row []any, i int, v any) []any {
		args := append([]any(nil), row...)
		args[i] = v
		return args
	}
	for _, tt := range []struct {
		name       string
		args       []any
		constraint string
	}{
		{"unknown channel", with(httpRow, 0, "smtp"), "events_channel_check"},
		{"HTTP without method", with(httpRow, 1, nil), "events_http_check"},
		{"DNS with method", with(dnsRow, 1, "GET"), "events_http_check"},
		{"DNS with user agent", with(dnsRow, 2, "curl"), "events_http_check"},
		{"HTTP with zone", with(httpRow, 3, "d.example.com"), "events_dns_check"},
		{"DNS without zone", with(dnsRow, 3, nil), "events_dns_check"},
		{"DNS without prefix", with(dnsRow, 4, nil), "events_dns_check"},
		{"DNS without type", with(dnsRow, 5, nil), "events_dns_check"},
		{"DNS without transport", with(dnsRow, 6, nil), "events_dns_check"},
		{"zone in upper case", with(dnsRow, 3, "D.example.com"), "events_dns_zone_check"},
		{"zone with trailing dot", with(dnsRow, 3, "d.example.com."), "events_dns_zone_check"},
		{"single-label zone", with(dnsRow, 3, "example"), "events_dns_zone_check"},
		{"long zone", with(dnsRow, 3, strings.Repeat("a", 200)+".com"), "events_dns_zone_check"},
		{"prefix with a control character", with(dnsRow, 4, "a\x01b"), "events_dns_prefix_check"},
		{"prefix with a space", with(dnsRow, 4, "a b"), "events_dns_prefix_check"},
		{"prefix with an empty label", with(dnsRow, 4, "a..b"), "events_dns_prefix_check"},
		{"prefix with a trailing dot", with(dnsRow, 4, "a."), "events_dns_prefix_check"},
		{"prefix in upper case", with(dnsRow, 4, "VPN"), "events_dns_prefix_check"},
		{"long prefix", with(dnsRow, 4, strings.Repeat("a", 201)), "events_dns_prefix_check"},
		{"type in lower case", with(dnsRow, 5, "a"), "events_dns_qtype_check"},
		{"long type", with(dnsRow, 5, strings.Repeat("A", 17)), "events_dns_qtype_check"},
		{"unknown transport", with(dnsRow, 6, "quic"), "events_dns_transport_check"},
		{"occurred after it was recorded", with(dnsRow, 7, "-1s"), "events_occurred_at_check"},
		{"occurred more than five minutes before", with(dnsRow, 7, "5m 1s"), "events_occurred_at_check"},
	} {
		_, err := pool.Exec(t.Context(), insert, tt.args...)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != tt.constraint {
			t.Errorf("%s: error = %v, want a violation of %s", tt.name, err, tt.constraint)
		}
	}
	for name, row := range map[string][]any{"HTTP": httpRow, "DNS": dnsRow, "DNS without prefix labels": with(dnsRow, 4, "")} {
		if _, err := pool.Exec(t.Context(), insert, row...); err != nil {
			t.Errorf("valid %s row: %v", name, err)
		}
	}
}

// The names that an event copies from the inventory follow the rules of the
// inventory, and a scenario has a name exactly when the event has a scenario.
func TestSchema_ChecksTheNamesOfEvents(t *testing.T) {
	t.Parallel()

	pool := schematest.Open(t, schematest.New(t))
	const insert = `INSERT INTO events (resource_type, resource_id, honeytoken_type, severity, occurred_at, recorded_at, channel, method,
	resource_name, scenario_id, scenario_name) VALUES ('honeytoken', gen_random_uuid(), 'web_url', 'medium', now(), now(), 'http', 'GET', $1, $2, $3)`
	scenario := "00000000-0000-4000-8000-000000000001"
	for _, tt := range []struct {
		name       string
		args       []any
		constraint string
	}{
		{"empty name", []any{"", nil, nil}, "events_resource_name_check"},
		{"long name", []any{strings.Repeat("a", 101), nil, nil}, "events_resource_name_check"},
		{"name with padding", []any{" a", nil, nil}, "events_resource_name_check"},
		{"control character in name", []any{"a\x07", nil, nil}, "events_resource_name_check"},
		{"scenario without a name", []any{"Name", scenario, nil}, "events_scenario_name_check"},
		{"name of a scenario that is none", []any{"Name", nil, "Scenario"}, "events_scenario_name_check"},
		{"empty scenario name", []any{"Name", scenario, ""}, "events_scenario_name_check"},
		{"long scenario name", []any{"Name", scenario, strings.Repeat("a", 101)}, "events_scenario_name_check"},
		{"scenario name with padding", []any{"Name", scenario, "a "}, "events_scenario_name_check"},
		{"control character in scenario name", []any{"Name", scenario, "a\x07"}, "events_scenario_name_check"},
	} {
		_, err := pool.Exec(t.Context(), insert, tt.args...)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != tt.constraint {
			t.Errorf("%s: error = %v, want a violation of %s", tt.name, err, tt.constraint)
		}
	}
	for name, args := range map[string][]any{
		"alone":                  {"Name", nil, nil},
		"in a scenario":          {"Name", scenario, "Scenario"},
		"names of the longest":   {strings.Repeat("a", 100), scenario, strings.Repeat("b", 100)},
		"name with inner spaces": {"a b", nil, nil},
	} {
		if _, err := pool.Exec(t.Context(), insert, args...); err != nil {
			t.Errorf("valid event %s: %v", name, err)
		}
	}
}
