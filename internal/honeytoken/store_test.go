// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeytoken_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/platform/schematest"
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

func create(t *testing.T, d testDB, spec honeytoken.Spec) honeytoken.Honeytoken {
	t.Helper()
	h, err := honeytoken.NewStore(d.console).Create(t.Context(), spec)
	if err != nil {
		t.Fatalf("Create(%+v) error = %v", spec, err)
	}
	return h
}

func TestStore_CreateAndGet(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	s := honeytoken.NewStore(d.console)

	spec := honeytoken.Spec{
		Type: honeytoken.TypeWebURL, Name: "Finance share link", Notes: "\\\\fs01\\finance\\Q3.docx\nowner: IT",
		Enabled: true, RedirectURL: ptr("https://intranet.example.com/finance"), Techniques: []string{"T1083", "T1005"},
	}
	h := create(t, d, spec)
	if h.ID == "" || h.Type != spec.Type || h.Name != spec.Name || h.Notes != spec.Notes || !h.Enabled ||
		h.RedirectURL == nil || *h.RedirectURL != *spec.RedirectURL || !slices.Equal(h.Techniques, spec.Techniques) {
		t.Errorf("Create() = %+v, want the fields of %+v", h, spec)
	}
	if len(h.TriggerValue) != 26 || !h.CreatedAt.Equal(h.UpdatedAt) {
		t.Errorf("Create() trigger value %q, times %v, %v; want 26 characters and equal times", h.TriggerValue, h.CreatedAt, h.UpdatedAt)
	}

	got, err := s.Get(t.Context(), h.ID)
	if err != nil || got.ID != h.ID || got.TriggerValue != h.TriggerValue || got.Name != h.Name {
		t.Errorf("Get() = %+v, %v; want %+v", got, err, h)
	}

	image := create(t, d, honeytoken.Spec{Type: honeytoken.TypeWebImage, Name: "Pixel"})
	if image.RedirectURL != nil || image.Techniques == nil || len(image.Techniques) != 0 || image.Enabled || image.Notes != "" {
		t.Errorf("Create(minimal) = %+v, want no redirect, no techniques, disabled, no notes", image)
	}
	if image.TriggerValue == h.TriggerValue {
		t.Error("two honeytokens have the same trigger value")
	}

	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid", ""} {
		if _, err := s.Get(t.Context(), id); !errors.Is(err, honeytoken.ErrNotFound) {
			t.Errorf("Get(%q) error = %v, want ErrNotFound", id, err)
		}
	}
}

// The store validates before it writes, so that a rejected row never reaches
// the log of the database, and techniques are checked against the bundled
// list, which the schema cannot do.
func TestStore_Create_ValidatesBeforeWriting(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	s := honeytoken.NewStore(d.console)

	for _, tt := range []struct {
		spec honeytoken.Spec
		err  error
	}{
		{honeytoken.Spec{Type: "txt", Name: "a"}, honeytoken.ErrInvalidType},
		{honeytoken.Spec{Type: honeytoken.TypeWebURL, Name: " a"}, honeytoken.ErrInvalidName},
		{honeytoken.Spec{Type: honeytoken.TypeWebURL, Name: "a", Notes: "\x00"}, honeytoken.ErrInvalidNotes},
		{honeytoken.Spec{Type: honeytoken.TypeWebURL, Name: "a", RedirectURL: ptr("https://127.0.0.1")}, honeytoken.ErrInvalidRedirectURL},
		{honeytoken.Spec{Type: honeytoken.TypeWebImage, Name: "a", RedirectURL: ptr("https://example.com")}, honeytoken.ErrRedirectNotAllowed},
		{honeytoken.Spec{Type: honeytoken.TypeWebURL, Name: "a", Techniques: []string{"T9999"}}, honeytoken.ErrInvalidTechniques},
	} {
		if _, err := s.Create(t.Context(), tt.spec); !errors.Is(err, tt.err) {
			t.Errorf("Create(%+v) error = %v, want %v", tt.spec, err, tt.err)
		}
	}
	var n int
	if err := d.owner.QueryRow(t.Context(), `SELECT count(*) FROM honeytokens`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d honeytokens stored, %v; want none", n, err)
	}
}

// Every type that the code knows must pass the check of the schema. The test
// writes what the code produces, so that a type added to one place only fails.
func TestStore_Create_StoresEveryType(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)

	for _, typ := range honeytoken.Types {
		if h := create(t, d, honeytoken.Spec{Type: typ, Name: string(typ)}); h.Type != typ {
			t.Errorf("Create(%s) type = %s", typ, h.Type)
		}
	}
}

func TestStore_List_PagesFromTheNewestAndFilters(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	s := honeytoken.NewStore(d.console)

	var all []string
	for i, typ := range []honeytoken.Type{
		honeytoken.TypeWebURL, honeytoken.TypeWebImage, honeytoken.TypeWebURL, honeytoken.TypeWebImage, honeytoken.TypeWebURL,
	} {
		h := create(t, d, honeytoken.Spec{Type: typ, Name: "h", Enabled: i%2 == 0})
		all = append([]string{h.ID}, all...)
	}

	ids := func(f honeytoken.Filter, size int) []string {
		t.Helper()
		var (
			got   []string
			after *honeytoken.Cursor
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
			// all is newest first; the honeytoken at position i was created
			// as number len(all)-1-i.
			if keep(len(all) - 1 - i) {
				want = append(want, id)
			}
		}
		return want
	}

	if got := ids(honeytoken.Filter{}, 2); !slices.Equal(got, all) {
		t.Errorf("List() = %v, want %v", got, all)
	}
	if got := ids(honeytoken.Filter{}, honeytoken.MaxPageSize); !slices.Equal(got, all) {
		t.Errorf("List(max) = %v, want %v", got, all)
	}
	image := honeytoken.TypeWebImage
	if got, want := ids(honeytoken.Filter{Type: &image}, 1), filter(func(i int) bool { return i%2 == 1 }); !slices.Equal(got, want) {
		t.Errorf("List(type web_image) = %v, want %v", got, want)
	}
	if got, want := ids(honeytoken.Filter{Enabled: ptr(true)}, 2), filter(func(i int) bool { return i%2 == 0 }); !slices.Equal(got, want) {
		t.Errorf("List(enabled) = %v, want %v", got, want)
	}
	url := honeytoken.TypeWebURL
	if got := ids(honeytoken.Filter{Type: &url, Enabled: ptr(false)}, 2); len(got) != 0 {
		t.Errorf("List(disabled URLs) = %v, want none", got)
	}

	for _, size := range []int{0, -1, honeytoken.MaxPageSize + 1} {
		if _, _, err := s.List(t.Context(), honeytoken.Filter{}, size, nil); !errors.Is(err, honeytoken.ErrInvalidPageSize) {
			t.Errorf("List(size %d) error = %v, want ErrInvalidPageSize", size, err)
		}
	}
}

func update(ctx context.Context, d testDB, id string, c honeytoken.Change) (honeytoken.Honeytoken, []string, error) {
	var (
		h       honeytoken.Honeytoken
		changed []string
	)
	err := pgx.BeginFunc(ctx, d.console, func(tx pgx.Tx) error {
		var err error
		h, changed, err = honeytoken.NewStore(tx).Update(ctx, id, c)
		return err
	})
	return h, changed, err
}

func TestStore_Update(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)

	h := create(t, d, honeytoken.Spec{Type: honeytoken.TypeWebURL, Name: "a", Enabled: true, Techniques: []string{"T1078"}})

	got, changed, err := update(t.Context(), d, h.ID, honeytoken.Change{
		Name: ptr("b"), Notes: ptr("n"), Enabled: ptr(false), RedirectURL: ptr("https://example.com"),
		Techniques: []string{"T1078", "T1003.001"}, SetTechniques: true,
	})
	want := []string{honeytoken.FieldName, honeytoken.FieldNotes, honeytoken.FieldEnabled, honeytoken.FieldRedirectURL, honeytoken.FieldTechniques}
	if err != nil || !slices.Equal(changed, want) || got.Name != "b" || got.Notes != "n" || got.Enabled ||
		got.RedirectURL == nil || *got.RedirectURL != "https://example.com" || !slices.Equal(got.Techniques, []string{"T1078", "T1003.001"}) {
		t.Fatalf("Update() = %+v, %v, %v; want every field changed", got, changed, err)
	}
	if !got.UpdatedAt.After(got.CreatedAt) || got.TriggerValue != h.TriggerValue || got.Type != h.Type {
		t.Errorf("Update() = %+v; want a later update time and the same type and trigger value", got)
	}

	// The same values change nothing and leave the time of the last change.
	again, changed, err := update(t.Context(), d, h.ID, honeytoken.Change{
		Name: ptr("b"), Enabled: ptr(false), RedirectURL: ptr("https://example.com"),
		Techniques: []string{"T1078", "T1003.001"}, SetTechniques: true,
	})
	if err != nil || len(changed) != 0 || !again.UpdatedAt.Equal(got.UpdatedAt) {
		t.Errorf("Update(same values) = %v, %v, updated %v; want no change", changed, err, again.UpdatedAt)
	}

	// An empty string removes the redirect, an empty list the techniques.
	got, changed, err = update(t.Context(), d, h.ID, honeytoken.Change{RedirectURL: ptr(""), SetTechniques: true})
	if err != nil || !slices.Equal(changed, []string{honeytoken.FieldRedirectURL, honeytoken.FieldTechniques}) ||
		got.RedirectURL != nil || got.Techniques == nil || len(got.Techniques) != 0 {
		t.Errorf("Update(remove) = %+v, %v, %v", got, changed, err)
	}
	if _, changed, err := update(t.Context(), d, h.ID, honeytoken.Change{RedirectURL: ptr("")}); err != nil || len(changed) != 0 {
		t.Errorf("Update(remove again) = %v, %v; want no change", changed, err)
	}

	image := create(t, d, honeytoken.Spec{Type: honeytoken.TypeWebImage, Name: "i"})
	if _, _, err := update(t.Context(), d, image.ID, honeytoken.Change{RedirectURL: ptr("https://example.com")}); !errors.Is(err, honeytoken.ErrRedirectNotAllowed) {
		t.Errorf("Update(redirect of an image) error = %v, want ErrRedirectNotAllowed", err)
	}
	if _, changed, err := update(t.Context(), d, image.ID, honeytoken.Change{RedirectURL: ptr("")}); err != nil || len(changed) != 0 {
		t.Errorf("Update(remove redirect of an image) = %v, %v; want no change", changed, err)
	}

	for _, c := range []honeytoken.Change{
		{Name: ptr("")},
		{Notes: ptr("\x00")},
		{RedirectURL: ptr("javascript:alert(1)")},
		{Techniques: []string{"T9999"}, SetTechniques: true},
	} {
		if _, _, err := update(t.Context(), d, h.ID, c); err == nil {
			t.Errorf("Update(%+v) error = nil, want a validation error", c)
		}
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if _, _, err := update(t.Context(), d, id, honeytoken.Change{Name: ptr("x")}); !errors.Is(err, honeytoken.ErrNotFound) {
			t.Errorf("Update(%q) error = %v, want ErrNotFound", id, err)
		}
	}
}

// Update compares the request with the current values under the lock of the
// honeytoken, so that a concurrent change cannot slip in between and the audit
// log names the fields that actually changed.
func TestStore_Update_LocksTheHoneytoken(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	h := create(t, d, honeytoken.Spec{Type: honeytoken.TypeWebURL, Name: "a"})

	for name, c := range map[string]honeytoken.Change{
		"change":    {Name: ptr("b")},
		"no change": {Name: ptr("a")},
	} {
		tx, err := d.console.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := honeytoken.NewStore(tx).Update(t.Context(), h.ID, c); err != nil {
			t.Fatalf("%s: Update() error = %v", name, err)
		}
		_, err = d.owner.Exec(t.Context(), `SELECT FROM honeytokens WHERE id = $1 FOR UPDATE NOWAIT`, h.ID)
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
	s := honeytoken.NewStore(d.console)
	h := create(t, d, honeytoken.Spec{Type: honeytoken.TypeWebURL, Name: "a"})

	if err := s.Delete(t.Context(), h.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := s.Get(t.Context(), h.ID); !errors.Is(err, honeytoken.ErrNotFound) {
		t.Errorf("Get(deleted) error = %v, want ErrNotFound", err)
	}
	for _, id := range []string{h.ID, "not-a-uuid"} {
		if err := s.Delete(t.Context(), id); !errors.Is(err, honeytoken.ErrNotFound) {
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

// Writes are recorded with the resource and the names of the changed fields,
// never with names or values, so that the audit log does not copy the
// inventory.
func TestCreateUpdateDelete_RecordEveryWrite(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	ctx := t.Context()

	h, err := honeytoken.Create(ctx, d.console, actor, honeytoken.Spec{Type: honeytoken.TypeWebURL, Name: "a", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := honeytoken.Update(ctx, d.console, actor, h.ID, honeytoken.Change{Name: ptr("b"), Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	if _, err := honeytoken.Update(ctx, d.console, actor, h.ID, honeytoken.Change{Name: ptr("b")}); err != nil {
		t.Fatal(err)
	}
	if err := honeytoken.Delete(ctx, d.console, actor, h.ID); err != nil {
		t.Fatal(err)
	}

	want := []entry{
		{"honeytoken.create", "honeytoken", h.ID, []string{}, actor.UserID},
		{"honeytoken.update", "honeytoken", h.ID, []string{"name", "enabled"}, actor.UserID},
		{"honeytoken.delete", "honeytoken", h.ID, []string{}, actor.UserID},
	}
	got := entries(t, d)
	if !slices.EqualFunc(got, want, func(a, b entry) bool {
		return a.Action == b.Action && a.ResourceType == b.ResourceType && a.ResourceID == b.ResourceID &&
			slices.Equal(a.ChangedFields, b.ChangedFields) && a.ActorUserID == b.ActorUserID
	}) {
		t.Errorf("audit entries = %+v, want %+v", got, want)
	}
}

// A failed audit entry fails the action, so that no write goes unrecorded.
func TestCreateUpdateDelete_FailWithoutTheirAuditEntry(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	h := create(t, d, honeytoken.Spec{Type: honeytoken.TypeWebURL, Name: "a"})
	// An actor without an account fails the check of the audit log.
	ghost := audit.Actor{Kind: audit.ActorUser, Method: audit.AuthSession, UserID: "00000000-0000-4000-8000-000000000000"}
	ctx := t.Context()

	if _, err := honeytoken.Create(ctx, d.console, ghost, honeytoken.Spec{Type: honeytoken.TypeWebURL, Name: "b"}); err == nil {
		t.Error("Create() without audit entry succeeded")
	}
	if _, err := honeytoken.Update(ctx, d.console, ghost, h.ID, honeytoken.Change{Name: ptr("c")}); err == nil {
		t.Error("Update() without audit entry succeeded")
	}
	if err := honeytoken.Delete(ctx, d.console, ghost, h.ID); err == nil {
		t.Error("Delete() without audit entry succeeded")
	}
	got, err := honeytoken.NewStore(d.console).Get(ctx, h.ID)
	if err != nil || got.Name != "a" {
		t.Errorf("Get() = %+v, %v; want the unchanged honeytoken", got, err)
	}
	var n int
	if err := d.owner.QueryRow(ctx, `SELECT count(*) FROM honeytokens`).Scan(&n); err != nil || n != 1 {
		t.Errorf("%d honeytokens, %v; want 1", n, err)
	}
}

// The schema is the last line of defense: each rule rejects a row that the
// application never writes, under the name that the store maps.
func TestSchema_ChecksHoneytokens(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)

	const insert = `INSERT INTO honeytokens (type, name, notes, redirect_url, techniques, trigger_value) VALUES ($1, $2, $3, $4, $5, $6)`
	valid := []any{"web_url", "a", "", nil, []string{}, "aaaaaaaaaaaaaaaaaaaaaaaaaa"}
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
		{"unknown type", with(0, "txt"), "honeytokens_type_check"},
		{"empty name", with(1, ""), "honeytokens_name_check"},
		{"long name", with(1, string(slices.Repeat([]byte("x"), 101))), "honeytokens_name_check"},
		{"name with spaces around", with(1, " a"), "honeytokens_name_check"},
		{"name with line break", with(1, "a\nb"), "honeytokens_name_check"},
		{"long notes", with(2, string(slices.Repeat([]byte("x"), 2001))), "honeytokens_notes_check"},
		{"notes with escape", with(2, "a\x1bb"), "honeytokens_notes_check"},
		{"redirect of an image", append([]any{"web_image"}, with(3, "https://example.com")[1:]...), "honeytokens_redirect_url_check"},
		{"redirect of a DNS name", append([]any{"dns"}, with(3, "https://example.com")[1:]...), "honeytokens_redirect_url_check"},
		{"redirect to another scheme", with(3, "javascript:alert(1)"), "honeytokens_redirect_url_check"},
		{"redirect with a space", with(3, "https://example.com/a b"), "honeytokens_redirect_url_check"},
		{"long redirect", with(3, "https://"+string(slices.Repeat([]byte("a"), 2041))), "honeytokens_redirect_url_check"},
		{"malformed technique", with(4, []string{"T1"}), "honeytokens_techniques_check"},
		{"repeated technique", with(4, []string{"T1078", "T1078"}), "honeytokens_techniques_check"},
		{"too many techniques", with(4, long), "honeytokens_techniques_check"},
		{"short trigger value", with(5, "aaaa"), "honeytokens_trigger_value_check"},
		{"trigger value in upper case", with(5, "AAAAAAAAAAAAAAAAAAAAAAAAAA"), "honeytokens_trigger_value_check"},
		{"trigger value with 0", with(5, "aaaaaaaaaaaaaaaaaaaaaaaaa0"), "honeytokens_trigger_value_check"},
	} {
		_, err := d.owner.Exec(t.Context(), insert, tt.args...)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != tt.constraint {
			t.Errorf("%s: error = %v, want a violation of %s", tt.name, err, tt.constraint)
		}
	}

	if _, err := d.owner.Exec(t.Context(), insert, valid...); err != nil {
		t.Fatalf("valid row: %v", err)
	}
	_, err := d.owner.Exec(t.Context(), insert, with(1, "b")...)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" || pgErr.ConstraintName != "honeytokens_trigger_value_key" {
		t.Errorf("repeated trigger value: error = %v, want a violation of honeytokens_trigger_value_key", err)
	}
	_, err = d.owner.Exec(t.Context(), `UPDATE honeytokens SET updated_at = created_at - interval '1 second'`)
	if !errors.As(err, &pgErr) || pgErr.ConstraintName != "honeytokens_updated_at_check" {
		t.Errorf("update before creation: error = %v, want a violation of honeytokens_updated_at_check", err)
	}

	// The time of the last change of a new row is its creation time.
	var equal bool
	if err := d.owner.QueryRow(t.Context(), `SELECT created_at = updated_at FROM honeytokens`).Scan(&equal); err != nil || !equal {
		t.Errorf("created_at = updated_at: %v, %v; want true", equal, err)
	}
}
