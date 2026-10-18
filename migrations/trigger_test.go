// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/platform/db"
	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/schematest"
)

const recordRequest = "SELECT * FROM public.record_honeytoken_request(repeat('a', 26), 'GET', NULL, '', '', '')"

func TestTriggerRole_PassesLeastPrivilegeCheck(t *testing.T) {
	t.Parallel()

	_, triggerURL := schematest.Trigger(t)
	if err := db.CheckLeastPrivilege(t.Context(), schematest.Open(t, triggerURL)); err != nil {
		t.Errorf("CheckLeastPrivilege() error = %v, want nil", err)
	}
}

// The trigger answers requests from the internet. Whoever controls it must not
// be able to read the inventory, so its role cannot read, or write to, any table
// directly; it records requests through one function.
func TestTriggerRole_CannotSelectFromAnyTable(t *testing.T) {
	t.Parallel()

	ownerURL, triggerURL := schematest.Trigger(t)
	tables := relations(t, ownerURL)
	if len(tables) < 10 {
		t.Fatalf("found %d tables, want the whole schema", len(tables))
	}

	pool := schematest.Open(t, triggerURL)
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
	if _, err := pool.Exec(t.Context(), recordRequest); err != nil {
		t.Errorf("%s: error = %v, want nil", recordRequest, err)
	}
}

func TestTriggerRole_HasOnlyGrantedPrivileges(t *testing.T) {
	t.Parallel()

	_, triggerURL := schematest.Trigger(t)
	pool := schematest.Open(t, triggerURL)

	for _, statement := range []string{
		"CREATE TABLE extra (id int)",
		"INSERT INTO events (resource_type, resource_id, honeytoken_type, method) VALUES ('honeytoken', gen_random_uuid(), 'web_url', 'GET')",
		"INSERT INTO event_jobs (event_id) VALUES (gen_random_uuid())",
		"UPDATE events SET method = 'GET'",
		"UPDATE honeytokens SET enabled = true",
		"INSERT INTO honeytokens (type, name, trigger_value) VALUES ('web_url', 'h', repeat('b', 26))",
		"SELECT public.attack_technique_ids_valid('{T1078}')",
		"SELECT public.audit_field_names_valid('{name}')",
		"SELECT public.api_key_scopes_valid('{audit:read}')",
		"SELECT public.set_updated_at()",
	} {
		expectDenied(t, pool, statement)
	}
}

// relations returns the tables, views and sequences of the schema, including the
// table of the migration runner.
func relations(t *testing.T, ownerURL string) []string {
	t.Helper()
	rows, err := schematest.Open(t, ownerURL).Query(t.Context(), `
SELECT relname FROM pg_class
WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r', 'p', 'v', 'm', 'f')
ORDER BY relname`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	return names
}

func expectDenied(t *testing.T, pool *pgxpool.Pool, statement string) {
	t.Helper()
	_, err := pool.Exec(t.Context(), statement)
	var pgErr *pgconn.PgError
	// 42501 is insufficient_privilege.
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Errorf("%s: error = %v, want insufficient_privilege", statement, err)
	}
}

// Functions that the internet-facing roles may execute, one each.
const (
	triggerFunction = "public.record_honeytoken_request(text, text, inet, text, text, text)"
	dnsFunction     = "public.record_dns_query(text, text, text, text, text, inet, interval)"
)

// rolePrivileges reports every privilege of a group role on the objects of the
// schema, except EXECUTE on function, the one it is granted.
func rolePrivileges(t *testing.T, dbURL, role, function string) []string {
	t.Helper()
	rows, err := schematest.Open(t, dbURL).Query(t.Context(), `
SELECT c.relname || ': ' || p.privilege
FROM pg_class AS c
CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p (privilege)
WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
	AND (has_table_privilege($1, c.oid, p.privilege)
		OR (p.privilege IN ('SELECT', 'INSERT', 'UPDATE', 'REFERENCES') AND has_any_column_privilege($1, c.oid, p.privilege)))
UNION ALL
SELECT f.oid::regprocedure::text || ': EXECUTE'
FROM pg_proc AS f
WHERE f.pronamespace = 'public'::regnamespace
	AND f.oid <> $2::regprocedure
	AND has_function_privilege($1, f.oid, 'EXECUTE')
UNION ALL
SELECT 'schema public: CREATE' WHERE has_schema_privilege($1, 'public', 'CREATE')`, role, function)
	if err != nil {
		t.Fatalf("query privileges: %v", err)
	}
	held, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("query privileges: %v", err)
	}
	return held
}

func TestTriggerRole_HasNoPrivilegesBeyondItsFunction(t *testing.T) {
	t.Parallel()

	if held := rolePrivileges(t, schematest.New(t), schematest.TriggerRole, triggerFunction); len(held) > 0 {
		t.Errorf("nyktus_trigger holds %v, want nothing beyond EXECUTE on record_honeytoken_request", held)
	}
}

// The schema is the last line of defense for the headers of an event: a
// compromised trigger cannot store what hides or reorders text, even though
// the trigger replaces it. Code points are built at run time, so that no
// invisible character sits in the source.
func TestSchema_ChecksHeadersOfEvents(t *testing.T) {
	t.Parallel()

	pool := schematest.Open(t, schematest.New(t))
	const insert = `INSERT INTO events (resource_type, resource_id, honeytoken_type, severity, occurred_at, recorded_at, channel, method,
	user_agent, referer, accept_language) VALUES ('honeytoken', gen_random_uuid(), 'web_url', 'medium', now(), now(), 'http', 'GET', $1, $2, $3)`
	headers := func(i int, v string) []any {
		args := []any{"", "", ""}
		args[i] = v
		return args
	}
	columns := []struct{ name, constraint string }{
		{"user agent", "events_user_agent_check"},
		{"referer", "events_referer_check"},
		{"accept language", "events_accept_language_check"},
	}
	refused := []struct {
		name string
		cp   rune
	}{
		{"control character", 0x01},
		{"delete", 0x7f},
		{"C1 control character", 0x85},
		{"soft hyphen", 0xad},
		{"arabic letter mark", 0x61c},
		{"mongolian vowel separator", 0x180e},
		{"zero width space", 0x200b},
		{"right-to-left mark", 0x200f},
		{"line separator", 0x2028},
		{"paragraph separator", 0x2029},
		{"right-to-left override", 0x202e},
		{"word joiner", 0x2060},
		{"isolate", 0x2066},
		{"deprecated format character", 0x206f},
		{"byte order mark", 0xfeff},
		{"interlinear annotation", 0xfff9},
		{"tag character", 0xe0041},
	}
	for i, col := range columns {
		for _, r := range refused {
			_, err := pool.Exec(t.Context(), insert, headers(i, "a"+string(r.cp)+"b")...)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != col.constraint {
				t.Errorf("%s with %s: error = %v, want a violation of %s", col.name, r.name, err, col.constraint)
			}
		}
		// What people write in other scripts and emoji must pass, as must the
		// characters next to the refused ranges.
		for _, ok := range []string{"Mozilla/5.0", string([]rune{0x4e2d, 0x6587, 0x1f600}), string([]rune{0x7e, 0xa0, 0xae, 0x61b, 0x61d, 0x180d, 0x180f, 0x200a, 0x2027, 0x202f, 0x205f, 0x2070, 0xfefc, 0xfffc, 0xfffd, 0xe0100})} {
			if _, err := pool.Exec(t.Context(), insert, headers(i, ok)...); err != nil {
				t.Errorf("%s %q: %v", col.name, ok, err)
			}
		}
	}
}

// Default privileges that an operator set for the owner also apply when they
// name the trigger's group role. The migration must remove them, including on the
// table of the migration runner, which exists before the migration runs.
func TestApply_IgnoresDefaultPrivilegesOfTheTrigger(t *testing.T) {
	t.Parallel()

	dbURL := dbtest.New(t)
	schematest.GroupRoles(t)
	trigger := pgx.Identifier{schematest.TriggerRole}.Sanitize()
	dbtest.Exec(t, dbURL,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "+trigger,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO "+trigger,
	)
	if err := apply(t, dbURL, load(t)); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if held := rolePrivileges(t, dbURL, schematest.TriggerRole, triggerFunction); len(held) > 0 {
		t.Errorf("nyktus_trigger holds %v, want nothing beyond EXECUTE on record_honeytoken_request", held)
	}
}
