// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeypot_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/honeypot"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/severity"
)

type testDB struct {
	owner, console *pgxpool.Pool
}

func newTestDB(t *testing.T) testDB {
	t.Helper()
	ownerURL, consoleURL := schematest.Console(t)
	return testDB{owner: schematest.Open(t, ownerURL), console: schematest.Open(t, consoleURL)}
}

// createUser inserts an active account to act as the actor of audit entries.
func createUser(t *testing.T, d testDB) audit.Actor {
	t.Helper()
	var id string
	err := d.owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status, password_hash)
VALUES ('user@example.com', 'Test User', 'user', 'active', '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA')
RETURNING id`).Scan(&id)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return audit.Actor{Kind: audit.ActorUser, Method: audit.AuthSession, UserID: id}
}

func ptr[T any](v T) *T { return &v }

func create(t *testing.T, d testDB, spec honeypot.Spec) honeypot.Created {
	t.Helper()
	c, err := honeypot.NewStore(d.console).Create(t.Context(), spec)
	if err != nil {
		t.Fatalf("Create(%+v) error = %v", spec, err)
	}
	return c
}

// secretHash returns the stored hash of the secret of the honeypot id.
func secretHash(t *testing.T, d testDB, id string) []byte {
	t.Helper()
	var hash []byte
	if err := d.owner.QueryRow(t.Context(), `SELECT secret_hash FROM honeypots WHERE id = $1`, id).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	return hash
}

// findBySecret returns the honeypot that the hash of secret belongs to, or ""
// if none does, as the trigger will look a sensor up.
func findBySecret(t *testing.T, d testDB, secret honeypot.Secret) string {
	t.Helper()
	sum := sha256.Sum256([]byte(secret))
	var id string
	err := d.owner.QueryRow(t.Context(), `SELECT id FROM honeypots WHERE secret_hash = $1`, sum[:]).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestStore_CreateAndGet(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	s := honeypot.NewStore(d.console)

	spec := honeypot.Spec{
		Service: honeypot.ServiceSSH, Name: "Jump host", Notes: "VLAN 20\nowner: IT", Enabled: true,
		Techniques: []string{"T1021.004", "T1078"},
	}
	c := create(t, d, spec)
	h := c.Honeypot
	if h.ID == "" || h.Service != spec.Service || h.Name != spec.Name || h.Notes != spec.Notes || !h.Enabled ||
		!slices.Equal(h.Techniques, spec.Techniques) || h.Severity != severity.Medium || h.ScenarioID != nil {
		t.Errorf("Create() = %+v, want the fields of %+v", h, spec)
	}
	if h.Status != honeypot.StatusNever || h.LastSeenAt != nil || h.SensorVersion != nil || !h.CreatedAt.Equal(h.UpdatedAt) {
		t.Errorf("Create() = %+v; want status never, no report and equal times", h)
	}
	if len(c.Secret) != 43 {
		t.Errorf("Create() secret has %d characters, want 43", len(c.Secret))
	}

	got, err := s.Get(t.Context(), h.ID)
	if err != nil || got.ID != h.ID || got.Name != h.Name || got.Status != honeypot.StatusNever {
		t.Errorf("Get() = %+v, %v; want %+v", got, err, h)
	}

	minimal := create(t, d, honeypot.Spec{Service: honeypot.ServiceLDAP, Name: "DC"})
	if minimal.Techniques == nil || len(minimal.Techniques) != 0 || minimal.Enabled || minimal.Notes != "" {
		t.Errorf("Create(minimal) = %+v, want no techniques, disabled, no notes", minimal.Honeypot)
	}
	if minimal.Secret == c.Secret {
		t.Error("two honeypots have the same secret")
	}

	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid", ""} {
		if _, err := s.Get(t.Context(), id); !errors.Is(err, honeypot.ErrNotFound) {
			t.Errorf("Get(%q) error = %v, want ErrNotFound", id, err)
		}
	}
}

// The database keeps only the SHA-256 hash of a secret: no column holds the
// secret in clear text, and whoever reads the table cannot present it.
func TestStore_Create_StoresOnlyTheHashOfTheSecret(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	c := create(t, d, honeypot.Spec{Service: honeypot.ServiceTelnet, Name: "t"})

	sum := sha256.Sum256([]byte(c.Secret))
	if got := secretHash(t, d, c.ID); !slices.Equal(got, sum[:]) {
		t.Errorf("stored hash = %x, want the SHA-256 of the secret", got)
	}
	var row string
	if err := d.owner.QueryRow(t.Context(), `SELECT row_to_json(h)::text FROM honeypots AS h WHERE id = $1`, c.ID).Scan(&row); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(row, string(c.Secret)) {
		t.Errorf("the row %s holds the secret in clear text", row)
	}
	if findBySecret(t, d, c.Secret) != c.ID {
		t.Error("the secret does not find its honeypot")
	}
}

// The store validates before it writes, so that a rejected row never reaches
// the log of the database, and techniques are checked against the bundled
// list, which the schema cannot do.
func TestStore_Create_ValidatesBeforeWriting(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	s := honeypot.NewStore(d.console)

	for _, tt := range []struct {
		spec honeypot.Spec
		err  error
	}{
		{honeypot.Spec{Service: "smtp", Name: "a"}, honeypot.ErrInvalidService},
		{honeypot.Spec{Service: honeypot.ServiceSSH, Name: " a"}, honeypot.ErrInvalidName},
		{honeypot.Spec{Service: honeypot.ServiceSSH, Name: "a", Notes: "\x00"}, honeypot.ErrInvalidNotes},
		{honeypot.Spec{Service: honeypot.ServiceSSH, Name: "a", Techniques: []string{"T9999"}}, honeypot.ErrInvalidTechniques},
		{honeypot.Spec{Service: honeypot.ServiceSSH, Name: "a", Severity: ptr(severity.Info)}, honeypot.ErrInvalidSeverity},
	} {
		if _, err := s.Create(t.Context(), tt.spec); !errors.Is(err, tt.err) {
			t.Errorf("Create(%+v) error = %v, want %v", tt.spec, err, tt.err)
		}
	}
	var n int
	if err := d.owner.QueryRow(t.Context(), `SELECT count(*) FROM honeypots`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d honeypots stored, %v; want none", n, err)
	}
}

// Every service that the code knows must pass the check of the schema, with
// its default severity, and so must every severity that the code accepts. The
// test writes what the code produces, so that a value added to one place
// only fails.
func TestStore_Create_StoresEveryServiceAndSeverity(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)

	for _, s := range honeypot.Services {
		c := create(t, d, honeypot.Spec{Service: s, Name: string(s)})
		if c.Service != s || c.Severity != s.DefaultSeverity() {
			t.Errorf("Create(%s) = service %s, severity %s; want the default severity %s", s, c.Service, c.Severity, s.DefaultSeverity())
		}
	}
	for _, l := range severity.Suggested {
		if c := create(t, d, honeypot.Spec{Service: honeypot.ServiceSSH, Name: string(l), Severity: &l}); c.Severity != l {
			t.Errorf("Create(severity %s) severity = %s", l, c.Severity)
		}
	}
}

// setLastSeen moves the creation of the honeypot id a day back and records a
// report age ago, as a sensor would have, measured by the clock of the
// database.
func setLastSeen(t *testing.T, d testDB, id string, age time.Duration) {
	t.Helper()
	_, err := d.owner.Exec(t.Context(), `
UPDATE honeypots SET created_at = clock_timestamp() - interval '1 day',
	last_seen_at = clock_timestamp() - make_interval(secs => $2), sensor_version = '0.1.0'
WHERE id = $1`, id, age.Seconds())
	if err != nil {
		t.Fatal(err)
	}
}

// A honeypot is online while its last report is younger than OfflineAfter and
// offline afterwards, measured by the clock of the database; one without a
// report has never been seen.
func TestStore_DerivesTheStatusFromTheLastReport(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	s := honeypot.NewStore(d.console)

	for _, tt := range []struct {
		name string
		age  *time.Duration
		want honeypot.Status
	}{
		{"no report", nil, honeypot.StatusNever},
		{"just now", ptr(time.Duration(0)), honeypot.StatusOnline},
		{"shortly before the bound", ptr(honeypot.OfflineAfter - 5*time.Second), honeypot.StatusOnline},
		{"at the bound", ptr(honeypot.OfflineAfter), honeypot.StatusOffline},
		{"long ago", ptr(12 * time.Hour), honeypot.StatusOffline},
	} {
		c := create(t, d, honeypot.Spec{Service: honeypot.ServiceSSH, Name: "p"})
		if tt.age != nil {
			setLastSeen(t, d, c.ID, *tt.age)
		}
		got, err := s.Get(t.Context(), c.ID)
		if err != nil || got.Status != tt.want {
			t.Errorf("%s: Get() status = %q, %v; want %q", tt.name, got.Status, err, tt.want)
		}
		if (got.LastSeenAt != nil) != (tt.age != nil) || (got.SensorVersion != nil) != (tt.age != nil) {
			t.Errorf("%s: Get() = %+v; want the report exactly if there is one", tt.name, got)
		}
		page, _, err := s.List(t.Context(), honeypot.Filter{}, honeypot.MaxPageSize, nil)
		i := slices.IndexFunc(page, func(h honeypot.Honeypot) bool { return h.ID == c.ID })
		if err != nil || i < 0 || page[i].Status != tt.want {
			t.Errorf("%s: List() = %+v, %v; want it with status %q", tt.name, page, err, tt.want)
		}
	}
}

// A new secret replaces the old one at once: only the new one finds the
// honeypot, and what the last sensor reported with the old one is cleared.
func TestStore_ReplaceSecret_InvalidatesTheOldSecret(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	s := honeypot.NewStore(d.console)
	c := create(t, d, honeypot.Spec{Service: honeypot.ServicePostgres, Name: "db", Enabled: true})
	other := create(t, d, honeypot.Spec{Service: honeypot.ServicePostgres, Name: "other"})
	setLastSeen(t, d, c.ID, time.Minute)
	setLastSeen(t, d, other.ID, time.Minute)
	before, err := s.Get(t.Context(), c.ID)
	if err != nil || before.Status != honeypot.StatusOnline {
		t.Fatalf("Get() = %+v, %v; want it online", before, err)
	}

	replaced, err := s.ReplaceSecret(t.Context(), c.ID)
	if err != nil {
		t.Fatalf("ReplaceSecret() error = %v", err)
	}
	if replaced.Secret == c.Secret || len(replaced.Secret) != 43 {
		t.Errorf("ReplaceSecret() secret = %q, want a new one", string(replaced.Secret))
	}
	if replaced.Status != honeypot.StatusNever || replaced.LastSeenAt != nil || replaced.SensorVersion != nil ||
		!replaced.UpdatedAt.After(before.UpdatedAt) || replaced.Name != "db" || !replaced.Enabled {
		t.Errorf("ReplaceSecret() = %+v; want status never without a report, a later update and the other fields kept", replaced.Honeypot)
	}
	if id := findBySecret(t, d, c.Secret); id != "" {
		t.Errorf("the old secret still finds %q", id)
	}
	if id := findBySecret(t, d, replaced.Secret); id != c.ID {
		t.Errorf("the new secret finds %q, want %q", id, c.ID)
	}
	if got, err := s.Get(t.Context(), other.ID); err != nil || got.Status != honeypot.StatusOnline || findBySecret(t, d, other.Secret) != other.ID {
		t.Errorf("another honeypot = %+v, %v; want it unchanged", got, err)
	}

	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if _, err := s.ReplaceSecret(t.Context(), id); !errors.Is(err, honeypot.ErrNotFound) {
			t.Errorf("ReplaceSecret(%q) error = %v, want ErrNotFound", id, err)
		}
	}
}

func TestStore_List_PagesFromTheNewestAndFilters(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	s := honeypot.NewStore(d.console)

	var all []string
	for i, sv := range []honeypot.Service{
		honeypot.ServiceSSH, honeypot.ServiceLDAP, honeypot.ServiceSSH, honeypot.ServiceLDAP, honeypot.ServiceSSH,
	} {
		c := create(t, d, honeypot.Spec{Service: sv, Name: "p", Enabled: i%2 == 0})
		all = append([]string{c.ID}, all...)
	}

	ids := func(f honeypot.Filter, size int) []string {
		t.Helper()
		var (
			got   []string
			after *honeypot.Cursor
		)
		for {
			page, next, err := s.List(t.Context(), f, size, after)
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}
			if len(page) > size {
				t.Fatalf("List() returned %d, want at most %d", len(page), size)
			}
			for _, h := range page {
				got = append(got, h.ID)
			}
			if next == nil {
				return got
			}
			after = next
		}
	}
	filter := func(keep func(i int) bool) []string {
		var want []string
		for i, id := range all {
			// all is newest first; the honeypot at position i was created as
			// number len(all)-1-i.
			if keep(len(all) - 1 - i) {
				want = append(want, id)
			}
		}
		return want
	}

	if got := ids(honeypot.Filter{}, 2); !slices.Equal(got, all) {
		t.Errorf("List() = %v, want %v", got, all)
	}
	if got := ids(honeypot.Filter{}, honeypot.MaxPageSize); !slices.Equal(got, all) {
		t.Errorf("List(max) = %v, want %v", got, all)
	}
	ldap := honeypot.ServiceLDAP
	if got, want := ids(honeypot.Filter{Service: &ldap}, 1), filter(func(i int) bool { return i%2 == 1 }); !slices.Equal(got, want) {
		t.Errorf("List(service ldap) = %v, want %v", got, want)
	}
	if got, want := ids(honeypot.Filter{Enabled: ptr(true)}, 2), filter(func(i int) bool { return i%2 == 0 }); !slices.Equal(got, want) {
		t.Errorf("List(enabled) = %v, want %v", got, want)
	}
	ssh := honeypot.ServiceSSH
	if got := ids(honeypot.Filter{Service: &ssh, Enabled: ptr(false)}, 2); len(got) != 0 {
		t.Errorf("List(disabled SSH) = %v, want none", got)
	}

	for _, size := range []int{0, -1, honeypot.MaxPageSize + 1} {
		if _, _, err := s.List(t.Context(), honeypot.Filter{}, size, nil); !errors.Is(err, honeypot.ErrInvalidPageSize) {
			t.Errorf("List(size %d) error = %v, want ErrInvalidPageSize", size, err)
		}
	}
}

func update(ctx context.Context, d testDB, id string, c honeypot.Change) (honeypot.Honeypot, []string, error) {
	var (
		h       honeypot.Honeypot
		changed []string
	)
	err := pgx.BeginFunc(ctx, d.console, func(tx pgx.Tx) error {
		var err error
		h, changed, err = honeypot.NewStore(tx).Update(ctx, id, c)
		return err
	})
	return h, changed, err
}

func TestStore_Update(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)

	c := create(t, d, honeypot.Spec{Service: honeypot.ServiceSSH, Name: "a", Enabled: true, Techniques: []string{"T1078"}})
	hash := secretHash(t, d, c.ID)

	got, changed, err := update(t.Context(), d, c.ID, honeypot.Change{
		Name: ptr("b"), Notes: ptr("n"), Enabled: ptr(false), Techniques: []string{"T1078", "T1021.004"},
		SetTechniques: true, Severity: ptr(severity.Critical),
	})
	want := []string{
		honeypot.FieldName, honeypot.FieldNotes, honeypot.FieldEnabled, honeypot.FieldTechniques, honeypot.FieldSeverity,
	}
	if err != nil || !slices.Equal(changed, want) || got.Name != "b" || got.Notes != "n" || got.Enabled ||
		!slices.Equal(got.Techniques, []string{"T1078", "T1021.004"}) || got.Severity != severity.Critical {
		t.Fatalf("Update() = %+v, %v, %v; want every field changed", got, changed, err)
	}
	if !got.UpdatedAt.After(got.CreatedAt) || got.Service != c.Service || !slices.Equal(secretHash(t, d, c.ID), hash) {
		t.Errorf("Update() = %+v; want a later update time and the same service and secret", got)
	}

	// The same values change nothing and leave the time of the last change.
	again, changed, err := update(t.Context(), d, c.ID, honeypot.Change{
		Name: ptr("b"), Enabled: ptr(false), Techniques: []string{"T1078", "T1021.004"}, SetTechniques: true,
		Severity: ptr(severity.Critical),
	})
	if err != nil || len(changed) != 0 || !again.UpdatedAt.Equal(got.UpdatedAt) {
		t.Errorf("Update(same values) = %v, %v, updated %v; want no change", changed, err, again.UpdatedAt)
	}

	// An empty list removes the techniques.
	got, changed, err = update(t.Context(), d, c.ID, honeypot.Change{SetTechniques: true})
	if err != nil || !slices.Equal(changed, []string{honeypot.FieldTechniques}) || got.Techniques == nil || len(got.Techniques) != 0 {
		t.Errorf("Update(remove techniques) = %+v, %v, %v", got, changed, err)
	}

	for _, ch := range []honeypot.Change{
		{Name: ptr("")},
		{Notes: ptr("\x00")},
		{Techniques: []string{"T9999"}, SetTechniques: true},
		{Severity: ptr(severity.Info)},
	} {
		if _, _, err := update(t.Context(), d, c.ID, ch); err == nil {
			t.Errorf("Update(%+v) error = nil, want a validation error", ch)
		}
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if _, _, err := update(t.Context(), d, id, honeypot.Change{Name: ptr("x")}); !errors.Is(err, honeypot.ErrNotFound) {
			t.Errorf("Update(%q) error = %v, want ErrNotFound", id, err)
		}
	}
}

// Update compares the request with the current values under the lock of the
// honeypot, so that a concurrent change cannot slip in between and the audit
// log names the fields that actually changed.
func TestStore_Update_LocksTheHoneypot(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	c := create(t, d, honeypot.Spec{Service: honeypot.ServiceSSH, Name: "a"})

	for name, ch := range map[string]honeypot.Change{
		"change":    {Name: ptr("b")},
		"no change": {Name: ptr("a")},
	} {
		tx, err := d.console.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := honeypot.NewStore(tx).Update(t.Context(), c.ID, ch); err != nil {
			t.Fatalf("%s: Update() error = %v", name, err)
		}
		_, err = d.owner.Exec(t.Context(), `SELECT FROM honeypots WHERE id = $1 FOR UPDATE NOWAIT`, c.ID)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
			t.Errorf("%s: probe error = %v, want lock_not_available", name, err)
		}
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStore_Delete(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	s := honeypot.NewStore(d.console)
	c := create(t, d, honeypot.Spec{Service: honeypot.ServiceSSH, Name: "a"})

	if err := s.Delete(t.Context(), c.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := s.Get(t.Context(), c.ID); !errors.Is(err, honeypot.ErrNotFound) {
		t.Errorf("Get(deleted) error = %v, want ErrNotFound", err)
	}
	if id := findBySecret(t, d, c.Secret); id != "" {
		t.Errorf("the secret of a deleted honeypot finds %q", id)
	}
	for _, id := range []string{c.ID, "not-a-uuid"} {
		if err := s.Delete(t.Context(), id); !errors.Is(err, honeypot.ErrNotFound) {
			t.Errorf("Delete(%q) error = %v, want ErrNotFound", id, err)
		}
	}
}

type entry struct {
	Action        string
	ResourceType  string
	ResourceID    string
	ChangedFields []string
	ActorUserID   string
}

func entries(t *testing.T, d testDB) []entry {
	t.Helper()
	rows, err := d.owner.Query(t.Context(), `
SELECT action, resource_type, resource_id::text, changed_fields, actor_user_id::text
FROM audit_entries ORDER BY occurred_at, id`)
	if err != nil {
		t.Fatal(err)
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[entry])
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func sameEntries(a, b []entry) bool {
	return slices.EqualFunc(a, b, func(a, b entry) bool {
		return a.Action == b.Action && a.ResourceType == b.ResourceType && a.ResourceID == b.ResourceID &&
			slices.Equal(a.ChangedFields, b.ChangedFields) && a.ActorUserID == b.ActorUserID
	})
}

// Writes are recorded with the resource and the names of the changed fields,
// never with names or values, so that the audit log does not copy the
// inventory. A new secret is recorded as the field secret, never its value.
func TestCreateUpdateDelete_RecordEveryWrite(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	ctx := t.Context()

	c, err := honeypot.Create(ctx, d.console, actor, honeypot.Spec{Service: honeypot.ServiceSSH, Name: "a", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := honeypot.Update(ctx, d.console, actor, c.ID, honeypot.Change{Name: ptr("b"), Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if _, err := honeypot.Update(ctx, d.console, actor, c.ID, honeypot.Change{Name: ptr("b")}); err != nil {
		t.Fatal(err)
	}
	replaced, err := honeypot.ReplaceSecret(ctx, d.console, actor, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := honeypot.Delete(ctx, d.console, actor, c.ID); err != nil {
		t.Fatal(err)
	}

	want := []entry{
		{"honeypot.create", "honeypot", c.ID, []string{}, actor.UserID},
		{"honeypot.update", "honeypot", c.ID, []string{"name", "enabled"}, actor.UserID},
		{"honeypot.update", "honeypot", c.ID, []string{"secret"}, actor.UserID},
		{"honeypot.delete", "honeypot", c.ID, []string{}, actor.UserID},
	}
	if got := entries(t, d); !sameEntries(got, want) {
		t.Errorf("audit entries = %+v, want %+v", got, want)
	}
	var dump string
	if err := d.owner.QueryRow(ctx, `SELECT coalesce(string_agg(row_to_json(a)::text, ''), '') FROM audit_entries AS a`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{string(c.Secret), string(replaced.Secret)} {
		if strings.Contains(dump, leak) {
			t.Error("the audit log holds a secret")
		}
	}
}

// A failed audit entry fails the action, so that no write goes unrecorded: a
// secret that was not recorded as replaced stays the valid one.
func TestCreateUpdateDelete_FailWithoutTheirAuditEntry(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	c := create(t, d, honeypot.Spec{Service: honeypot.ServiceSSH, Name: "a"})
	// An actor without an account fails the check of the audit log.
	ghost := audit.Actor{Kind: audit.ActorUser, Method: audit.AuthSession, UserID: "00000000-0000-4000-8000-000000000000"}
	ctx := t.Context()

	if _, err := honeypot.Create(ctx, d.console, ghost, honeypot.Spec{Service: honeypot.ServiceSSH, Name: "b"}); err == nil {
		t.Error("Create() without audit entry succeeded")
	}
	if _, err := honeypot.Update(ctx, d.console, ghost, c.ID, honeypot.Change{Name: ptr("c")}); err == nil {
		t.Error("Update() without audit entry succeeded")
	}
	if _, err := honeypot.ReplaceSecret(ctx, d.console, ghost, c.ID); err == nil {
		t.Error("ReplaceSecret() without audit entry succeeded")
	}
	if err := honeypot.Delete(ctx, d.console, ghost, c.ID); err == nil {
		t.Error("Delete() without audit entry succeeded")
	}
	got, err := honeypot.NewStore(d.console).Get(ctx, c.ID)
	if err != nil || got.Name != "a" {
		t.Errorf("Get() = %+v, %v; want the unchanged honeypot", got, err)
	}
	if findBySecret(t, d, c.Secret) != c.ID {
		t.Error("the secret changed without its audit entry")
	}
	var n int
	if err := d.owner.QueryRow(ctx, `SELECT count(*) FROM honeypots`).Scan(&n); err != nil || n != 1 {
		t.Errorf("%d honeypots, %v; want 1", n, err)
	}
}

// The schema is the last line of defense: each rule rejects a row that the
// application never writes, under the name that the store maps or that tests
// assert on.
func TestSchema_ChecksHoneypots(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)

	const insert = `INSERT INTO honeypots (service, name, notes, techniques, severity, secret_hash, sensor_version, last_seen_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	hash := sha256.Sum256([]byte("a"))
	valid := []any{"ssh", "a", "", []string{}, "medium", hash[:], nil, nil}
	with := func(i int, v any) []any {
		args := slices.Clone(valid)
		args[i] = v
		return args
	}
	long := make([]string, 21)
	for i := range long {
		long[i] = "T1" + string(rune('0'+i/10)) + string(rune('0'+i%10)) + "0"
	}
	for _, tt := range []struct {
		name       string
		args       []any
		constraint string
	}{
		{"unknown service", with(0, "smtp"), "honeypots_service_check"},
		{"empty name", with(1, ""), "honeypots_name_check"},
		{"long name", with(1, strings.Repeat("x", 101)), "honeypots_name_check"},
		{"name with spaces around", with(1, " a"), "honeypots_name_check"},
		{"name with line break", with(1, "a\nb"), "honeypots_name_check"},
		{"long notes", with(2, strings.Repeat("x", 2001)), "honeypots_notes_check"},
		{"notes with escape", with(2, "a\x1bb"), "honeypots_notes_check"},
		{"malformed technique", with(3, []string{"T1"}), "honeypots_techniques_check"},
		{"repeated technique", with(3, []string{"T1078", "T1078"}), "honeypots_techniques_check"},
		{"too many techniques", with(3, long), "honeypots_techniques_check"},
		{"severity info", with(4, "info"), "honeypots_severity_check"},
		{"unknown severity", with(4, "urgent"), "honeypots_severity_check"},
		{"short hash", with(5, hash[:31]), "honeypots_secret_hash_check"},
		{"secret instead of a hash", with(5, []byte("c2VjcmV0LXZhbHVlLXRoYXQtbXVzdC1uZXZlci1sZWFr")), "honeypots_secret_hash_check"},
		{"empty sensor version", with(6, ""), "honeypots_sensor_version_check"},
		{"long sensor version", with(6, strings.Repeat("1", 33)), "honeypots_sensor_version_check"},
		{"sensor version with a space", with(6, "0.1 beta"), "honeypots_sensor_version_check"},
		{"sensor version with a line break", with(6, "0.1\n"), "honeypots_sensor_version_check"},
		{"report before creation", with(7, time.Now().Add(-time.Hour)), "honeypots_last_seen_at_check"},
	} {
		_, err := d.owner.Exec(t.Context(), insert, tt.args...)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != tt.constraint {
			t.Errorf("%s: error = %v, want a violation of %s", tt.name, err, tt.constraint)
		}
	}

	if _, err := d.owner.Exec(t.Context(), insert, with(6, "0.1.0-rc.1+abc")...); err != nil {
		t.Fatalf("valid row: %v", err)
	}
	_, err := d.owner.Exec(t.Context(), insert, with(1, "b")...)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" || pgErr.ConstraintName != "honeypots_secret_hash_key" {
		t.Errorf("repeated hash: error = %v, want a violation of honeypots_secret_hash_key", err)
	}
	_, err = d.owner.Exec(t.Context(), `UPDATE honeypots SET updated_at = created_at - interval '1 second'`)
	if !errors.As(err, &pgErr) || pgErr.ConstraintName != "honeypots_updated_at_check" {
		t.Errorf("update before creation: error = %v, want a violation of honeypots_updated_at_check", err)
	}

	// The time of the last change of a new row is its creation time.
	var equal bool
	if err := d.owner.QueryRow(t.Context(), `SELECT created_at = updated_at FROM honeypots`).Scan(&equal); err != nil || !equal {
		t.Errorf("created_at = updated_at: %v, %v; want true", equal, err)
	}
}

// createScenario inserts a scenario as the owner; the scenario package
// creates them through the console.
func createScenario(t *testing.T, d testDB) string {
	t.Helper()
	var id string
	if err := d.owner.QueryRow(t.Context(), `INSERT INTO scenarios (name) VALUES ('s') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func setScenario(ctx context.Context, d testDB, id, scenarioID string) (honeypot.Honeypot, bool, error) {
	var (
		h       honeypot.Honeypot
		changed bool
	)
	err := pgx.BeginFunc(ctx, d.console, func(tx pgx.Tx) error {
		var err error
		h, changed, err = honeypot.NewStore(tx).SetScenario(ctx, id, scenarioID)
		return err
	})
	return h, changed, err
}

// A honeypot joins a scenario, stays when it is assigned again, leaves it,
// and joins another one only after it left the first.
func TestStore_SetScenario(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	first, second := createScenario(t, d), createScenario(t, d)
	h := create(t, d, honeypot.Spec{Service: honeypot.ServiceSSH, Name: "a"}).Honeypot

	got, changed, err := setScenario(t.Context(), d, h.ID, first)
	if err != nil || !changed || got.ScenarioID == nil || *got.ScenarioID != first || !got.UpdatedAt.After(h.UpdatedAt) {
		t.Fatalf("SetScenario(first) = %+v, %v, %v; want it in the first scenario", got, changed, err)
	}
	if again, changed, err := setScenario(t.Context(), d, h.ID, first); err != nil || changed || !again.UpdatedAt.Equal(got.UpdatedAt) {
		t.Errorf("SetScenario(first again) = %+v, %v, %v; want no change", again, changed, err)
	}
	if _, _, err := setScenario(t.Context(), d, h.ID, second); !errors.Is(err, honeypot.ErrInOtherScenario) {
		t.Errorf("SetScenario(second) error = %v, want ErrInOtherScenario", err)
	}
	if got, err := honeypot.NewStore(d.console).Get(t.Context(), h.ID); err != nil || got.ScenarioID == nil || *got.ScenarioID != first {
		t.Errorf("Get() = %+v, %v; want it still in the first scenario", got, err)
	}

	got, changed, err = setScenario(t.Context(), d, h.ID, "")
	if err != nil || !changed || got.ScenarioID != nil {
		t.Errorf("SetScenario(detach) = %+v, %v, %v; want it alone", got, changed, err)
	}
	if _, changed, err := setScenario(t.Context(), d, h.ID, ""); err != nil || changed {
		t.Errorf("SetScenario(detach again) = %v, %v; want no change", changed, err)
	}
	if got, changed, err := setScenario(t.Context(), d, h.ID, second); err != nil || !changed || *got.ScenarioID != second {
		t.Errorf("SetScenario(second after leaving) = %+v, %v, %v", got, changed, err)
	}

	const missing = "00000000-0000-4000-8000-000000000000"
	for _, tt := range []struct {
		name, id, scenarioID string
		err                  error
	}{
		{"unknown scenario", h.ID, missing, honeypot.ErrScenarioNotFound},
		{"malformed scenario", h.ID, "not-a-uuid", honeypot.ErrScenarioNotFound},
		{"unknown honeypot", missing, first, honeypot.ErrNotFound},
		{"unknown honeypot and scenario", missing, missing, honeypot.ErrNotFound},
		{"malformed honeypot", "not-a-uuid", first, honeypot.ErrNotFound},
		{"unknown honeypot detached", missing, "", honeypot.ErrNotFound},
	} {
		if _, _, err := setScenario(t.Context(), d, tt.id, tt.scenarioID); !errors.Is(err, tt.err) {
			t.Errorf("%s: SetScenario() error = %v, want %v", tt.name, err, tt.err)
		}
	}
}

// waitForLockWait returns once a session of the test database waits for a
// lock.
func waitForLockWait(t *testing.T, d testDB) {
	t.Helper()
	for {
		var waiting bool
		err := d.owner.QueryRow(t.Context(), `
SELECT EXISTS (
	SELECT FROM pg_stat_activity
	WHERE datname = current_database() AND wait_event_type = 'Lock'
)`).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		if t.Context().Err() != nil {
			t.Fatal("no session waits for a lock")
		}
	}
}

// The assignment locks the scenario before the honeypot, as the deletion of a
// scenario does: while the scenario is held, the honeypot stays free.
func TestStore_SetScenario_LocksTheScenarioFirst(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc := createScenario(t, d)
	h := create(t, d, honeypot.Spec{Service: honeypot.ServiceSSH, Name: "a"})

	holder, err := d.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := holder.Exec(t.Context(), `SELECT FROM scenarios WHERE id = $1 FOR UPDATE`, sc); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := setScenario(t.Context(), d, h.ID, sc)
		done <- err
	}()
	waitForLockWait(t, d)

	if _, err := d.owner.Exec(t.Context(), `SELECT FROM honeypots WHERE id = $1 FOR UPDATE NOWAIT`, h.ID); err != nil {
		t.Errorf("probe of the honeypot: error = %v, want it free while the scenario is held", err)
	}
	if err := holder.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Errorf("SetScenario() error = %v", err)
	}
}

// The assignment keeps the scenario from being deleted until it ends: the
// scenario is held with a lock that conflicts with its deletion.
func TestStore_SetScenario_HoldsTheScenario(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc := createScenario(t, d)
	h := create(t, d, honeypot.Spec{Service: honeypot.ServiceSSH, Name: "a"})

	tx, err := d.console.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
	if _, _, err := honeypot.NewStore(tx).SetScenario(t.Context(), h.ID, sc); err != nil {
		t.Fatal(err)
	}
	_, err = d.owner.Exec(t.Context(), `SELECT FROM scenarios WHERE id = $1 FOR UPDATE NOWAIT`, sc)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("probe of the scenario: error = %v, want lock_not_available", err)
	}
	_, err = d.owner.Exec(t.Context(), `SELECT FROM honeypots WHERE id = $1 FOR KEY SHARE NOWAIT`, h.ID)
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("probe of the honeypot: error = %v, want lock_not_available", err)
	}
}

// An assignment that waits for a scenario that is deleted meanwhile finds no
// scenario, instead of joining one that is gone.
func TestStore_SetScenario_ToAScenarioDeletedMeanwhile(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc := createScenario(t, d)
	h := create(t, d, honeypot.Spec{Service: honeypot.ServiceSSH, Name: "a"})

	deleter, err := d.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = deleter.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := deleter.Exec(t.Context(), `SELECT FROM scenarios WHERE id = $1 FOR UPDATE`, sc); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := setScenario(t.Context(), d, h.ID, sc)
		done <- err
	}()
	waitForLockWait(t, d)
	if _, err := deleter.Exec(t.Context(), `DELETE FROM scenarios WHERE id = $1`, sc); err != nil {
		t.Fatal(err)
	}
	if err := deleter.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, honeypot.ErrScenarioNotFound) {
		t.Errorf("SetScenario() error = %v, want ErrScenarioNotFound", err)
	}
	if got, err := honeypot.NewStore(d.console).Get(t.Context(), h.ID); err != nil || got.ScenarioID != nil {
		t.Errorf("Get() = %+v, %v; want it alone", got, err)
	}
}

// The assignment is recorded as a change of the scenario of the honeypot; one
// that changes nothing is not, and a failed entry fails it.
func TestSetScenario_RecordsTheChange(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	sc := createScenario(t, d)
	h := create(t, d, honeypot.Spec{Service: honeypot.ServiceSSH, Name: "a"})
	ctx := t.Context()

	ghost := audit.Actor{Kind: audit.ActorUser, Method: audit.AuthSession, UserID: "00000000-0000-4000-8000-000000000000"}
	if _, err := honeypot.SetScenario(ctx, d.console, ghost, h.ID, sc); err == nil {
		t.Error("SetScenario() without audit entry succeeded")
	}
	if got, err := honeypot.NewStore(d.console).Get(ctx, h.ID); err != nil || got.ScenarioID != nil {
		t.Errorf("Get() = %+v, %v; want it alone after the failed assignment", got, err)
	}

	for _, scenarioID := range []string{sc, sc, "", ""} {
		if _, err := honeypot.SetScenario(ctx, d.console, actor, h.ID, scenarioID); err != nil {
			t.Fatal(err)
		}
	}
	want := []entry{
		{"honeypot.update", "honeypot", h.ID, []string{"scenario_id"}, actor.UserID},
		{"honeypot.update", "honeypot", h.ID, []string{"scenario_id"}, actor.UserID},
	}
	if got := entries(t, d); !sameEntries(got, want) {
		t.Errorf("audit entries = %+v, want %+v", got, want)
	}
}

// The list of a scenario holds its honeypots and no others, a page at a time,
// and the filters of service and state still apply.
func TestStore_List_FiltersByScenario(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	s := honeypot.NewStore(d.console)
	sc, other := createScenario(t, d), createScenario(t, d)

	var want []string
	for i := range 5 {
		h := create(t, d, honeypot.Spec{Service: honeypot.ServiceSSH, Name: "p", Enabled: i%2 == 0})
		target := sc
		if i == 2 {
			target = other
		}
		if _, _, err := setScenario(t.Context(), d, h.ID, target); err != nil {
			t.Fatal(err)
		}
		if target == sc {
			want = append([]string{h.ID}, want...)
		}
	}
	create(t, d, honeypot.Spec{Service: honeypot.ServiceSSH, Name: "alone"})

	var (
		got   []string
		after *honeypot.Cursor
	)
	for {
		page, next, err := s.List(t.Context(), honeypot.Filter{ScenarioID: sc}, 1, after)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range page {
			if h.ScenarioID == nil || *h.ScenarioID != sc {
				t.Errorf("List() returned %+v of another scenario", h)
			}
			got = append(got, h.ID)
		}
		if next == nil {
			break
		}
		after = next
	}
	if !slices.Equal(got, want) {
		t.Errorf("List(scenario) = %v, want %v", got, want)
	}
	page, _, err := s.List(t.Context(), honeypot.Filter{ScenarioID: sc, Enabled: ptr(false)}, honeypot.MaxPageSize, nil)
	if err != nil || len(page) != 2 || page[0].Enabled || page[1].Enabled {
		t.Errorf("List(scenario, disabled) = %+v, %v; want the two disabled honeypots", page, err)
	}
}
