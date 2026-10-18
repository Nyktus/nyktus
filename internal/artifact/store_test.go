// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package artifact_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"nyktus.org/nyktus/internal/artifact"
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
