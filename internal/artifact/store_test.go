// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package artifact_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/artifact"
	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/catalog"
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

// createScenario inserts a scenario of a deception as the owner; the
// scenario package creates them through the console.
func createScenario(t *testing.T, d testDB) string {
	t.Helper()
	var id string
	err := d.owner.QueryRow(t.Context(), `
INSERT INTO scenarios (name, deception_id, language, persona, guide) VALUES ('s', 'ssh-config', 'en', '{}', 'g')
RETURNING id`).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func spec(scenarioID string) artifact.Spec {
	return artifact.Spec{
		ScenarioID: scenarioID, DeceptionArtifact: "config", FileName: "config", Format: catalog.FormatConfig,
		Content: []byte("Host a\n"),
	}
}

func TestStore_Create(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc := createScenario(t, d)

	a, err := artifact.NewStore(d.console).Create(t.Context(), spec(sc))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if a.ID == "" || a.ScenarioID == nil || *a.ScenarioID != sc || a.DeceptionArtifact != "config" ||
		a.FileName != "config" || a.Format != catalog.FormatConfig || a.Size != len("Host a\n") ||
		a.PlacementNotes != "" || !a.CreatedAt.Equal(a.UpdatedAt) {
		t.Errorf("Create() = %+v", a)
	}
}

// Every format of the catalog has a media type and passes the check of the
// schema, so that every artifact that the catalog renders can be stored and
// downloaded. The test writes what the code produces.
func TestFormats_MatchTheSchemaAndHaveAMediaType(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc := createScenario(t, d)

	for _, f := range catalog.Formats {
		s := spec(sc)
		s.Format = f
		if _, err := artifact.NewStore(d.console).Create(t.Context(), s); err != nil {
			t.Errorf("Create(format %s) error = %v", f, err)
		}
		if mt := artifact.MediaType(f); mt == "application/octet-stream" && f != catalog.FormatConfig {
			t.Errorf("MediaType(%s) = %s, want a media type of its own", f, mt)
		}
	}
	// Only files that a tool reads are offered as bytes, never as a type
	// that a browser renders.
	if mt := artifact.MediaType(catalog.FormatConfig); mt != "application/octet-stream" {
		t.Errorf("MediaType(config) = %s", mt)
	}
	if mt := artifact.MediaType("yaml"); mt != "application/octet-stream" {
		t.Errorf("MediaType(unknown) = %s, want application/octet-stream", mt)
	}
}

// The schema is the last line of defense: each rule rejects a row that the
// application never writes, under its name.
func TestSchema_ChecksArtifacts(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc := createScenario(t, d)

	const insert = `INSERT INTO artifacts (scenario_id, deception_artifact, file_name, format, content, placement_notes)
VALUES ($1, $2, $3, $4, $5, $6)`
	valid := []any{sc, "config", "config", "config", []byte("x"), ""}
	with := func(i int, v any) []any {
		args := slices.Clone(valid)
		args[i] = v
		return args
	}
	for _, tt := range []struct {
		name       string
		args       []any
		constraint string
	}{
		{"without scenario", with(0, nil), "artifacts_scenario_id_check"},
		{"malformed key", with(1, "Config"), "artifacts_deception_artifact_check"},
		{"long key", with(1, strings.Repeat("a", 65)), "artifacts_deception_artifact_check"},
		{"file name with separator", with(2, "a/b"), "artifacts_file_name_check"},
		{"hidden file name", with(2, ".netrc"), "artifacts_file_name_check"},
		{"file name with a line break", with(2, "a\nb"), "artifacts_file_name_check"},
		{"file name with a quote", with(2, `a"b`), "artifacts_file_name_check"},
		{"unknown format", with(3, "yaml"), "artifacts_format_check"},
		{"content too large", with(4, make([]byte, artifact.MaxContentBytes+1)), "artifacts_content_check"},
		{"long notes", with(5, strings.Repeat("x", 2001)), "artifacts_placement_notes_check"},
		{"notes with escape", with(5, "a\x1bb"), "artifacts_placement_notes_check"},
	} {
		_, err := d.owner.Exec(t.Context(), insert, tt.args...)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != tt.constraint {
			t.Errorf("%s: error = %v, want a violation of %s", tt.name, err, tt.constraint)
		}
	}
	if _, err := d.owner.Exec(t.Context(), insert, with(4, make([]byte, artifact.MaxContentBytes))...); err != nil {
		t.Fatalf("valid row: %v", err)
	}
}

// An artifact leaves its scenario only to stand alone, and never joins
// another one, also not through the console.
func TestSchema_AnArtifactNeverJoinsAScenario(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc, other := createScenario(t, d), createScenario(t, d)
	a, err := artifact.NewStore(d.console).Create(t.Context(), spec(sc))
	if err != nil {
		t.Fatal(err)
	}

	join := func(target string) error {
		_, err := d.console.Exec(t.Context(), `UPDATE artifacts SET scenario_id = $2 WHERE id = $1`, a.ID, target)
		return err
	}
	var pgErr *pgconn.PgError
	if err := join(other); !errors.As(err, &pgErr) || pgErr.ConstraintName != "artifacts_scenario_id_check" {
		t.Errorf("move to another scenario: error = %v, want a violation of artifacts_scenario_id_check", err)
	}
	if _, err := d.console.Exec(t.Context(), `UPDATE artifacts SET scenario_id = NULL WHERE id = $1`, a.ID); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if err := join(sc); !errors.As(err, &pgErr) || pgErr.ConstraintName != "artifacts_scenario_id_check" {
		t.Errorf("join after detaching: error = %v, want a violation of artifacts_scenario_id_check", err)
	}
	// Other changes of a detached artifact remain possible.
	if _, err := d.console.Exec(t.Context(), `UPDATE artifacts SET placement_notes = 'n' WHERE id = $1`, a.ID); err != nil {
		t.Errorf("change the notes of a detached artifact: %v", err)
	}
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

func create(t *testing.T, d testDB, scenarioID string) artifact.Artifact {
	t.Helper()
	a, err := artifact.NewStore(d.console).Create(t.Context(), spec(scenarioID))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestStore_GetAndContent(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	a := create(t, d, createScenario(t, d))
	s := artifact.NewStore(d.console)

	got, err := s.Get(t.Context(), a.ID)
	if err != nil || !reflect.DeepEqual(got, a) {
		t.Errorf("Get() = %+v, %v; want %+v", got, err, a)
	}
	meta, content, err := s.Content(t.Context(), a.ID)
	if err != nil || !reflect.DeepEqual(meta, a) || string(content) != "Host a\n" {
		t.Errorf("Content() = %+v, %q, %v", meta, content, err)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if _, err := s.Get(t.Context(), id); !errors.Is(err, artifact.ErrNotFound) {
			t.Errorf("Get(%q) error = %v, want ErrNotFound", id, err)
		}
		if _, _, err := s.Content(t.Context(), id); !errors.Is(err, artifact.ErrNotFound) {
			t.Errorf("Content(%q) error = %v, want ErrNotFound", id, err)
		}
	}
}

// The list pages from the newest to the oldest, also filtered by scenario,
// and an artifact that stands alone appears only without the filter.
func TestStore_List_PagesFromTheNewestAndFilters(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc, other := createScenario(t, d), createScenario(t, d)
	first, second := create(t, d, sc), create(t, d, sc)
	inOther := create(t, d, other)
	alone := create(t, d, other)
	if _, err := d.owner.Exec(t.Context(), `UPDATE artifacts SET scenario_id = NULL WHERE id = $1`, alone.ID); err != nil {
		t.Fatal(err)
	}
	s := artifact.NewStore(d.console)

	ids := func(list []artifact.Artifact) []string {
		var out []string
		for _, a := range list {
			out = append(out, a.ID)
		}
		return out
	}
	all, next, err := s.List(t.Context(), artifact.Filter{}, 3, nil)
	if err != nil || !slices.Equal(ids(all), []string{alone.ID, inOther.ID, second.ID}) || next == nil {
		t.Fatalf("List(3) = %v, %v, %v", ids(all), next, err)
	}
	rest, next, err := s.List(t.Context(), artifact.Filter{}, 3, next)
	if err != nil || !slices.Equal(ids(rest), []string{first.ID}) || next != nil {
		t.Errorf("List(after) = %v, %v, %v", ids(rest), next, err)
	}
	page, next, err := s.List(t.Context(), artifact.Filter{ScenarioID: sc}, 1, nil)
	if err != nil || !slices.Equal(ids(page), []string{second.ID}) || next == nil {
		t.Fatalf("List(scenario, 1) = %v, %v, %v", ids(page), next, err)
	}
	page, next, err = s.List(t.Context(), artifact.Filter{ScenarioID: sc}, 1, next)
	if err != nil || !slices.Equal(ids(page), []string{first.ID}) || next != nil {
		t.Errorf("List(scenario, after) = %v, %v, %v", ids(page), next, err)
	}
	for _, size := range []int{0, artifact.MaxPageSize + 1} {
		if _, _, err := s.List(t.Context(), artifact.Filter{}, size, nil); !errors.Is(err, artifact.ErrInvalidPageSize) {
			t.Errorf("List(%d) error = %v, want ErrInvalidPageSize", size, err)
		}
	}
}

func setNotes(t *testing.T, d testDB, id, notes string) (artifact.Artifact, bool, error) {
	t.Helper()
	var (
		a       artifact.Artifact
		changed bool
	)
	err := pgx.BeginFunc(t.Context(), d.console, func(tx pgx.Tx) error {
		var err error
		a, changed, err = artifact.NewStore(tx).SetPlacementNotes(t.Context(), id, notes)
		return err
	})
	return a, changed, err
}

func TestStore_SetPlacementNotes(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	a := create(t, d, createScenario(t, d))

	got, changed, err := setNotes(t, d, a.ID, "~/.ssh/config on ws07\nowner: IT")
	if err != nil || !changed || got.PlacementNotes != "~/.ssh/config on ws07\nowner: IT" || !got.UpdatedAt.After(a.UpdatedAt) ||
		got.FileName != a.FileName || got.Size != a.Size {
		t.Fatalf("SetPlacementNotes() = %+v, %v, %v", got, changed, err)
	}
	again, changed, err := setNotes(t, d, a.ID, got.PlacementNotes)
	if err != nil || changed || !again.UpdatedAt.Equal(got.UpdatedAt) {
		t.Errorf("SetPlacementNotes(same) = %+v, %v, %v; want no change", again, changed, err)
	}
	if _, _, err := setNotes(t, d, a.ID, "a\x00"); !errors.Is(err, artifact.ErrInvalidPlacementNotes) {
		t.Errorf("SetPlacementNotes(invalid) error = %v", err)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if _, _, err := setNotes(t, d, id, "n"); !errors.Is(err, artifact.ErrNotFound) {
			t.Errorf("SetPlacementNotes(%q) error = %v, want ErrNotFound", id, err)
		}
	}
}

// Changing the notes locks the artifact until the end of the transaction, so
// that a concurrent change cannot slip in between the comparison and the
// change.
func TestStore_SetPlacementNotes_LocksTheArtifact(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	a := create(t, d, createScenario(t, d))

	tx, err := d.console.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, _, err := artifact.NewStore(tx).SetPlacementNotes(t.Context(), a.ID, a.PlacementNotes); err != nil {
		t.Fatal(err)
	}
	_, err = d.owner.Exec(t.Context(), `SELECT FROM artifacts WHERE id = $1 FOR UPDATE NOWAIT`, a.ID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("probe error = %v, want lock_not_available", err)
	}
}

func TestStore_Delete(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	a := create(t, d, createScenario(t, d))
	s := artifact.NewStore(d.console)

	if err := s.Delete(t.Context(), a.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := s.Get(t.Context(), a.ID); !errors.Is(err, artifact.ErrNotFound) {
		t.Errorf("Get(deleted) error = %v, want ErrNotFound", err)
	}
	for _, id := range []string{a.ID, "not-a-uuid"} {
		if err := s.Delete(t.Context(), id); !errors.Is(err, artifact.ErrNotFound) {
			t.Errorf("Delete(%q) error = %v, want ErrNotFound", id, err)
		}
	}
}

// Changes and deletions are recorded with the field names, never the notes;
// a change that changes nothing is not recorded, and a failed entry fails
// the action.
func TestSetPlacementNotesAndDelete_RecordEveryWrite(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	a := create(t, d, createScenario(t, d))
	ctx := t.Context()

	if _, err := artifact.SetPlacementNotes(ctx, d.console, actor, a.ID, "secret place"); err != nil {
		t.Fatal(err)
	}
	if _, err := artifact.SetPlacementNotes(ctx, d.console, actor, a.ID, "secret place"); err != nil {
		t.Fatal(err)
	}
	ghost := audit.Actor{Kind: audit.ActorUser, Method: audit.AuthSession, UserID: "00000000-0000-4000-8000-000000000000"}
	if _, err := artifact.SetPlacementNotes(ctx, d.console, ghost, a.ID, "other"); err == nil {
		t.Error("SetPlacementNotes() without audit entry succeeded")
	}
	if err := artifact.Delete(ctx, d.console, ghost, a.ID); err == nil {
		t.Error("Delete() without audit entry succeeded")
	}
	if err := artifact.Delete(ctx, d.console, actor, a.ID); err != nil {
		t.Fatal(err)
	}

	rows, err := d.owner.Query(ctx, `
SELECT action || ' ' || resource_type || ' ' || resource_id::text || ' ' || array_to_string(changed_fields, ',')
FROM audit_entries ORDER BY occurred_at, id`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"artifact.update artifact " + a.ID + " placement_notes", "artifact.delete artifact " + a.ID + " "}
	if !slices.Equal(got, want) {
		t.Errorf("audit entries = %q, want %q", got, want)
	}
}

// A page after a cursor seeks into the index, also with the generic plan
// that PostgreSQL may choose for a prepared statement, and the list of a
// scenario seeks into the index of its scenario.
func TestList_CursorIsAnIndexConditionInTheGenericPlan(t *testing.T) {
	t.Parallel()
	ownerURL, _ := schematest.Console(t)
	conn, err := pgx.Connect(t.Context(), ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(t.Context())) }()

	for _, statement := range []string{
		"SET plan_cache_mode = force_generic_plan",
		"SET enable_seqscan = off",
		"PREPARE list_after AS " + artifact.ListAfter,
		"PREPARE list_scenario_after AS " + artifact.ListScenarioAfter,
	} {
		if _, err := conn.Exec(t.Context(), statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	const cursor = `'2026-10-10T12:00:00Z', '00000000-0000-4000-8000-000000000000'`
	for _, tt := range []struct{ explain, index, cond string }{
		{"EXPLAIN EXECUTE list_after(" + cursor + ", 51)", "artifacts_created_at_id_idx", "Index Cond: (ROW(created_at, id) < ROW("},
		{
			"EXPLAIN EXECUTE list_scenario_after('00000000-0000-4000-8000-000000000001', " + cursor + ", 51)",
			"artifacts_scenario_id_created_at_id_idx", "Index Cond: ((scenario_id = $1) AND (ROW(created_at, id) < ROW(",
		},
	} {
		rows, err := conn.Query(t.Context(), tt.explain)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		if text := strings.Join(plan, "\n"); !strings.Contains(text, tt.index) || !strings.Contains(text, tt.cond) {
			t.Errorf("generic plan does not seek into %s with %q:\n%s", tt.index, tt.cond, text)
		}
	}
}
