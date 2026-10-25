// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenario_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	embedded "nyktus.org/nyktus/catalog"
	"nyktus.org/nyktus/internal/artifact"
	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/honeypot"
	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/scenario"
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

func create(t *testing.T, d testDB, spec scenario.Spec) scenario.Scenario {
	t.Helper()
	s, err := scenario.NewStore(d.console).Create(t.Context(), spec)
	if err != nil {
		t.Fatalf("Create(%+v) error = %v", spec, err)
	}
	return s
}

// createHoneytoken creates a honeytoken in the scenario scenarioID, or alone
// if it is empty.
func createHoneytoken(t *testing.T, d testDB, scenarioID string) string {
	t.Helper()
	h, err := honeytoken.NewStore(d.console).Create(t.Context(), honeytoken.Spec{Type: honeytoken.TypeWebURL, Name: "h"})
	if err != nil {
		t.Fatal(err)
	}
	if scenarioID != "" {
		if _, err := d.owner.Exec(t.Context(), `UPDATE honeytokens SET scenario_id = $1 WHERE id = $2`, scenarioID, h.ID); err != nil {
			t.Fatal(err)
		}
	}
	return h.ID
}

// createHoneypot creates a honeypot in the scenario scenarioID, or alone if
// it is empty.
func createHoneypot(t *testing.T, d testDB, scenarioID string) string {
	t.Helper()
	h, err := honeypot.NewStore(d.console).Create(t.Context(), honeypot.Spec{Service: honeypot.ServiceSSH, Name: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if scenarioID != "" {
		if _, err := d.owner.Exec(t.Context(), `UPDATE honeypots SET scenario_id = $1 WHERE id = $2`, scenarioID, h.ID); err != nil {
			t.Fatal(err)
		}
	}
	return h.ID
}

// createArtifact stores an artifact in the scenario scenarioID through the
// console, as applying a deception does, and returns its identifier.
func createArtifact(t *testing.T, d testDB, scenarioID string) string {
	t.Helper()
	a, err := artifact.NewStore(d.console).Create(t.Context(), artifact.Spec{
		ScenarioID: scenarioID, CatalogArtifact: "config", FileName: "config", Format: catalog.FormatConfig,
		Content: []byte("Host a\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return a.ID
}

// scenarioOf returns the scenario of the honeytoken id, "" if it stands alone,
// and whether it exists.
func scenarioOf(t *testing.T, d testDB, id string) (string, bool) {
	t.Helper()
	return scenarioIn(t, d, "honeytokens", id)
}

// honeypotScenarioOf returns the scenario of the honeypot id as scenarioOf
// does.
func honeypotScenarioOf(t *testing.T, d testDB, id string) (string, bool) {
	t.Helper()
	return scenarioIn(t, d, "honeypots", id)
}

// artifactScenarioOf returns the scenario of the artifact id as scenarioOf
// does.
func artifactScenarioOf(t *testing.T, d testDB, id string) (string, bool) {
	t.Helper()
	return scenarioIn(t, d, "artifacts", id)
}

func scenarioIn(t *testing.T, d testDB, table, id string) (string, bool) {
	t.Helper()
	var s *string
	err := d.owner.QueryRow(t.Context(), `SELECT scenario_id::text FROM `+table+` WHERE id = $1`, id).Scan(&s)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	if s == nil {
		return "", true
	}
	return *s, true
}

func TestStore_CreateAndGet(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	s := scenario.NewStore(d.console)

	spec := scenario.Spec{Name: "Finance file share", Notes: "\\\\fs01\\finance\nowner: IT", EngageActivities: []string{"EAC0005", "EAC0006"}}
	sc := create(t, d, spec)
	if sc.ID == "" || sc.Name != spec.Name || sc.Notes != spec.Notes || !slices.Equal(sc.EngageActivities, spec.EngageActivities) ||
		len(sc.Deceptions) != 0 || len(sc.Persona) != 0 || !sc.CreatedAt.Equal(sc.UpdatedAt) {
		t.Errorf("Create() = %+v, want the fields of %+v, no deception, no persona and equal times", sc, spec)
	}
	got, err := s.Get(t.Context(), sc.ID)
	if err != nil || got.ID != sc.ID || got.Name != sc.Name || !slices.Equal(got.EngageActivities, sc.EngageActivities) {
		t.Errorf("Get() = %+v, %v; want %+v", got, err, sc)
	}

	minimal := create(t, d, scenario.Spec{Name: "m"})
	if minimal.Notes != "" || minimal.EngageActivities == nil || len(minimal.EngageActivities) != 0 {
		t.Errorf("Create(minimal) = %+v, want no notes and no activities", minimal)
	}

	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid", ""} {
		if _, err := s.Get(t.Context(), id); !errors.Is(err, scenario.ErrNotFound) {
			t.Errorf("Get(%q) error = %v, want ErrNotFound", id, err)
		}
	}
}

// The store validates before it writes, so that a rejected row never reaches
// the log of the database, and activities are checked against the bundled
// list of Engage, which the schema cannot do.
func TestStore_Create_ValidatesBeforeWriting(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	s := scenario.NewStore(d.console)

	many := make([]string, 0, scenario.MaxEngageActivities+1)
	for _, id := range engageIDs(t) {
		if len(many) <= scenario.MaxEngageActivities {
			many = append(many, id)
		}
	}
	if len(many) != scenario.MaxEngageActivities+1 {
		t.Fatalf("Engage has %d activities, want more than %d", len(many), scenario.MaxEngageActivities)
	}
	for _, tt := range []struct {
		name string
		spec scenario.Spec
		err  error
	}{
		{"empty name", scenario.Spec{Name: ""}, scenario.ErrInvalidName},
		{"name with spaces around", scenario.Spec{Name: " a"}, scenario.ErrInvalidName},
		{"long name", scenario.Spec{Name: strings.Repeat("x", scenario.MaxNameLength+1)}, scenario.ErrInvalidName},
		{"name with bidirectional override", scenario.Spec{Name: "a\u202eb"}, scenario.ErrInvalidName},
		{"notes with NUL", scenario.Spec{Name: "a", Notes: "\x00"}, scenario.ErrInvalidNotes},
		{"long notes", scenario.Spec{Name: "a", Notes: strings.Repeat("x", scenario.MaxNotesLength+1)}, scenario.ErrInvalidNotes},
		{"unknown activity", scenario.Spec{Name: "a", EngageActivities: []string{"EAC9999"}}, scenario.ErrInvalidEngageActivities},
		{"strategic activity", scenario.Spec{Name: "a", EngageActivities: []string{"SPR0001"}}, scenario.ErrInvalidEngageActivities},
		{"repeated activity", scenario.Spec{Name: "a", EngageActivities: []string{"EAC0005", "EAC0005"}}, scenario.ErrInvalidEngageActivities},
		{"too many activities", scenario.Spec{Name: "a", EngageActivities: many}, scenario.ErrInvalidEngageActivities},
	} {
		if _, err := s.Create(t.Context(), tt.spec); !errors.Is(err, tt.err) {
			t.Errorf("%s: Create() error = %v, want %v", tt.name, err, tt.err)
		}
	}
	if _, err := s.Create(t.Context(), scenario.Spec{Name: strings.Repeat("\u00e4", scenario.MaxNameLength), EngageActivities: many[:scenario.MaxEngageActivities]}); err != nil {
		t.Errorf("Create(longest name, most activities) error = %v", err)
	}
	var n int
	if err := d.owner.QueryRow(t.Context(), `SELECT count(*) FROM scenarios`).Scan(&n); err != nil || n != 1 {
		t.Errorf("%d scenarios stored, %v; want only the valid one", n, err)
	}
}

func TestStore_List_PagesFromTheNewest(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	s := scenario.NewStore(d.console)

	var all []string
	for range 5 {
		all = append([]string{create(t, d, scenario.Spec{Name: "s"}).ID}, all...)
	}
	for _, size := range []int{1, 2, scenario.MaxPageSize} {
		var (
			got   []string
			after *scenario.Cursor
		)
		for {
			page, next, err := s.List(t.Context(), size, after)
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}
			if len(page) > size {
				t.Fatalf("List() returned %d, want at most %d", len(page), size)
			}
			for _, sc := range page {
				got = append(got, sc.ID)
			}
			if next == nil {
				break
			}
			after = next
		}
		if !slices.Equal(got, all) {
			t.Errorf("List(size %d) = %v, want %v", size, got, all)
		}
	}
	for _, size := range []int{0, -1, scenario.MaxPageSize + 1} {
		if _, _, err := s.List(t.Context(), size, nil); !errors.Is(err, scenario.ErrInvalidPageSize) {
			t.Errorf("List(size %d) error = %v, want ErrInvalidPageSize", size, err)
		}
	}
}

func update(ctx context.Context, d testDB, id string, c scenario.Change) (scenario.Scenario, []string, error) {
	var (
		sc      scenario.Scenario
		changed []string
	)
	err := pgx.BeginFunc(ctx, d.console, func(tx pgx.Tx) error {
		var err error
		sc, changed, err = scenario.NewStore(tx).Update(ctx, id, c)
		return err
	})
	return sc, changed, err
}

func TestStore_Update(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc := create(t, d, scenario.Spec{Name: "a", EngageActivities: []string{"EAC0005"}})

	got, changed, err := update(t.Context(), d, sc.ID, scenario.Change{
		Name: ptr("b"), Notes: ptr("n"), EngageActivities: []string{"EAC0005", "EAC0006"}, SetEngageActivities: true,
	})
	want := []string{scenario.FieldName, scenario.FieldNotes, scenario.FieldEngageActivities}
	if err != nil || !slices.Equal(changed, want) || got.Name != "b" || got.Notes != "n" ||
		!slices.Equal(got.EngageActivities, []string{"EAC0005", "EAC0006"}) || !got.UpdatedAt.After(got.CreatedAt) {
		t.Fatalf("Update() = %+v, %v, %v; want every field changed", got, changed, err)
	}

	again, changed, err := update(t.Context(), d, sc.ID, scenario.Change{
		Name: ptr("b"), Notes: ptr("n"), EngageActivities: []string{"EAC0005", "EAC0006"}, SetEngageActivities: true,
	})
	if err != nil || len(changed) != 0 || !again.UpdatedAt.Equal(got.UpdatedAt) {
		t.Errorf("Update(same values) = %v, %v, updated %v; want no change", changed, err, again.UpdatedAt)
	}
	got, changed, err = update(t.Context(), d, sc.ID, scenario.Change{SetEngageActivities: true})
	if err != nil || !slices.Equal(changed, []string{scenario.FieldEngageActivities}) || got.EngageActivities == nil ||
		len(got.EngageActivities) != 0 {
		t.Errorf("Update(remove activities) = %+v, %v, %v", got, changed, err)
	}

	for _, c := range []scenario.Change{
		{Name: ptr("")},
		{Notes: ptr("\x00")},
		{EngageActivities: []string{"EAC9999"}, SetEngageActivities: true},
	} {
		if _, _, err := update(t.Context(), d, sc.ID, c); err == nil {
			t.Errorf("Update(%+v) error = nil, want a validation error", c)
		}
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if _, _, err := update(t.Context(), d, id, scenario.Change{Name: ptr("x")}); !errors.Is(err, scenario.ErrNotFound) {
			t.Errorf("Update(%q) error = %v, want ErrNotFound", id, err)
		}
	}
}

// Update compares the request with the current values under the lock of the
// scenario, so that a concurrent change cannot slip in between and the audit
// log names the fields that actually changed.
func TestStore_Update_LocksTheScenario(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc := create(t, d, scenario.Spec{Name: "a"})

	for name, c := range map[string]scenario.Change{
		"change":    {Name: ptr("b")},
		"no change": {Name: ptr("a")},
	} {
		tx, err := d.console.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := scenario.NewStore(tx).Update(t.Context(), sc.ID, c); err != nil {
			t.Fatalf("%s: Update() error = %v", name, err)
		}
		_, err = d.owner.Exec(t.Context(), `SELECT FROM scenarios WHERE id = $1 FOR NO KEY UPDATE NOWAIT`, sc.ID)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
			t.Errorf("%s: probe error = %v, want lock_not_available", name, err)
		}
		if err := tx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}

func deleteScenario(ctx context.Context, d testDB, id string, r scenario.Removal) (scenario.Removed, error) {
	return deleteWith(ctx, d, id, scenario.ResourceRemovals{Honeytokens: r, Honeypots: r, Artifacts: r})
}

func deleteWith(ctx context.Context, d testDB, id string, r scenario.ResourceRemovals) (scenario.Removed, error) {
	var removed scenario.Removed
	err := pgx.BeginFunc(ctx, d.console, func(tx pgx.Tx) error {
		var err error
		removed, err = scenario.NewStore(tx).Delete(ctx, id, r)
		return err
	})
	return removed, err
}

// Deleting a scenario deletes or detaches its artifacts, as the request
// chooses for them, independently of its honeytokens, and touches no other
// artifact. A kept artifact stands alone.
func TestStore_Delete_RemovesTheArtifactsAsChosen(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	other := create(t, d, scenario.Spec{Name: "other"})
	inOther := createArtifact(t, d, other.ID)

	for _, honeytokens := range scenario.Removals {
		for _, artifacts := range scenario.Removals {
			sc := create(t, d, scenario.Spec{Name: "s"})
			h := createHoneytoken(t, d, sc.ID)
			ids := []string{createArtifact(t, d, sc.ID), createArtifact(t, d, sc.ID)}
			removed, err := deleteWith(t.Context(), d, sc.ID, scenario.ResourceRemovals{
				Honeytokens: honeytokens, Honeypots: scenario.RemovalKeep, Artifacts: artifacts,
			})
			if err != nil {
				t.Fatalf("%s/%s: Delete() error = %v", honeytokens, artifacts, err)
			}
			got, want := removed.DetachedArtifacts, removed.DeletedArtifacts
			if artifacts == scenario.RemovalDelete {
				got, want = want, got
			}
			slices.Sort(got)
			slices.Sort(ids)
			if !slices.Equal(got, ids) || len(want) != 0 {
				t.Errorf("%s/%s: Delete() = %+v, want artifacts %v %s", honeytokens, artifacts, removed, ids, artifacts)
			}
			for _, id := range ids {
				if s, exists := artifactScenarioOf(t, d, id); exists != (artifacts == scenario.RemovalKeep) || s != "" {
					t.Errorf("%s/%s: artifact exists %v in scenario %q", honeytokens, artifacts, exists, s)
				}
			}
			if _, exists := scenarioOf(t, d, h); exists != (honeytokens == scenario.RemovalKeep) {
				t.Errorf("%s/%s: honeytoken exists %v", honeytokens, artifacts, exists)
			}
		}
	}
	if s, ok := artifactScenarioOf(t, d, inOther); !ok || s != other.ID {
		t.Errorf("an artifact of another scenario is in %q, exists %v", s, ok)
	}
	if _, err := deleteWith(t.Context(), d, other.ID, scenario.ResourceRemovals{
		Honeytokens: scenario.RemovalKeep, Honeypots: scenario.RemovalKeep, Artifacts: "cascade",
	}); !errors.Is(err, scenario.ErrInvalidRemoval) {
		t.Errorf("Delete(unknown removal of artifacts) error = %v, want ErrInvalidRemoval", err)
	}
}

// Deleting a scenario deletes or detaches its honeypots, as the request
// chooses for them, independently of its honeytokens and artifacts, and
// touches no other honeypot. A kept honeypot stands alone.
func TestStore_Delete_RemovesTheHoneypotsAsChosen(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	other := create(t, d, scenario.Spec{Name: "other"})
	inOther := createHoneypot(t, d, other.ID)
	alone := createHoneypot(t, d, "")

	for _, others := range scenario.Removals {
		for _, honeypots := range scenario.Removals {
			sc := create(t, d, scenario.Spec{Name: "s"})
			h := createHoneytoken(t, d, sc.ID)
			a := createArtifact(t, d, sc.ID)
			ids := []string{createHoneypot(t, d, sc.ID), createHoneypot(t, d, sc.ID)}
			removed, err := deleteWith(t.Context(), d, sc.ID, scenario.ResourceRemovals{
				Honeytokens: others, Honeypots: honeypots, Artifacts: others,
			})
			if err != nil {
				t.Fatalf("%s/%s: Delete() error = %v", others, honeypots, err)
			}
			got, want := removed.DetachedHoneypots, removed.DeletedHoneypots
			if honeypots == scenario.RemovalDelete {
				got, want = want, got
			}
			slices.Sort(got)
			slices.Sort(ids)
			if !slices.Equal(got, ids) || len(want) != 0 {
				t.Errorf("%s/%s: Delete() = %+v, want honeypots %v %s", others, honeypots, removed, ids, honeypots)
			}
			for _, id := range ids {
				if s, exists := honeypotScenarioOf(t, d, id); exists != (honeypots == scenario.RemovalKeep) || s != "" {
					t.Errorf("%s/%s: honeypot exists %v in scenario %q", others, honeypots, exists, s)
				}
			}
			if _, exists := scenarioOf(t, d, h); exists != (others == scenario.RemovalKeep) {
				t.Errorf("%s/%s: honeytoken exists %v", others, honeypots, exists)
			}
			if _, exists := artifactScenarioOf(t, d, a); exists != (others == scenario.RemovalKeep) {
				t.Errorf("%s/%s: artifact exists %v", others, honeypots, exists)
			}
		}
	}
	if s, ok := honeypotScenarioOf(t, d, inOther); !ok || s != other.ID {
		t.Errorf("a honeypot of another scenario is in %q, exists %v", s, ok)
	}
	if s, ok := honeypotScenarioOf(t, d, alone); !ok || s != "" {
		t.Errorf("a honeypot that stands alone is in %q, exists %v", s, ok)
	}
	if _, err := deleteWith(t.Context(), d, other.ID, scenario.ResourceRemovals{
		Honeytokens: scenario.RemovalKeep, Honeypots: "cascade", Artifacts: scenario.RemovalKeep,
	}); !errors.Is(err, scenario.ErrInvalidRemoval) {
		t.Errorf("Delete(unknown removal of honeypots) error = %v, want ErrInvalidRemoval", err)
	}
	if s, ok := honeypotScenarioOf(t, d, inOther); !ok || s != other.ID {
		t.Errorf("after a rejected deletion, the honeypot is in %q, exists %v", s, ok)
	}
}

// Deleting a scenario deletes or detaches its honeytokens, as the request
// chooses, and touches no other honeytoken.
func TestStore_Delete(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	other := create(t, d, scenario.Spec{Name: "other"})
	inOther := createHoneytoken(t, d, other.ID)
	alone := createHoneytoken(t, d, "")

	for _, r := range scenario.Removals {
		sc := create(t, d, scenario.Spec{Name: "s"})
		ids := []string{createHoneytoken(t, d, sc.ID), createHoneytoken(t, d, sc.ID)}
		removed, err := deleteScenario(t.Context(), d, sc.ID, r)
		if err != nil {
			t.Fatalf("%s: Delete() error = %v", r, err)
		}
		got, want := removed.DetachedHoneytokens, removed.DeletedHoneytokens
		if r == scenario.RemovalDelete {
			got, want = want, got
		}
		slices.Sort(got)
		slices.Sort(ids)
		if !slices.Equal(got, ids) || len(want) != 0 {
			t.Errorf("%s: Delete() = %+v, want %v %s", r, removed, ids, r)
		}
		for _, id := range ids {
			scenarioID, exists := scenarioOf(t, d, id)
			if exists != (r == scenario.RemovalKeep) || scenarioID != "" {
				t.Errorf("%s: honeytoken exists %v in scenario %q", r, exists, scenarioID)
			}
		}
		if _, err := scenario.NewStore(d.console).Get(t.Context(), sc.ID); !errors.Is(err, scenario.ErrNotFound) {
			t.Errorf("%s: Get(deleted) error = %v, want ErrNotFound", r, err)
		}
	}

	if s, ok := scenarioOf(t, d, inOther); !ok || s != other.ID {
		t.Errorf("a honeytoken of another scenario is in %q, exists %v", s, ok)
	}
	if s, ok := scenarioOf(t, d, alone); !ok || s != "" {
		t.Errorf("a honeytoken that stands alone is in %q, exists %v", s, ok)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if _, err := deleteScenario(t.Context(), d, id, scenario.RemovalKeep); !errors.Is(err, scenario.ErrNotFound) {
			t.Errorf("Delete(%q) error = %v, want ErrNotFound", id, err)
		}
	}
	if _, err := deleteScenario(t.Context(), d, other.ID, "cascade"); !errors.Is(err, scenario.ErrInvalidRemoval) {
		t.Errorf("Delete(unknown removal) error = %v, want ErrInvalidRemoval", err)
	}
	if _, err := scenario.NewStore(d.console).Get(t.Context(), other.ID); err != nil {
		t.Errorf("Get() after a rejected deletion error = %v", err)
	}
}

// The schema keeps a scenario from being deleted while a honeytoken belongs
// to it, so that no honeytoken is removed without its audit entry.
func TestSchema_KeepsAScenarioWithHoneytokens(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	createHoneytoken(t, d, sc.ID)

	_, err := d.console.Exec(t.Context(), `DELETE FROM scenarios WHERE id = $1`, sc.ID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" || pgErr.ConstraintName != "honeytokens_scenario_id_fkey" {
		t.Errorf("DELETE error = %v, want a violation of honeytokens_scenario_id_fkey", err)
	}
}

// The schema keeps a scenario from being deleted while a honeypot belongs to
// it, as for honeytokens.
func TestSchema_KeepsAScenarioWithHoneypots(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	createHoneypot(t, d, sc.ID)

	_, err := d.console.Exec(t.Context(), `DELETE FROM scenarios WHERE id = $1`, sc.ID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" || pgErr.ConstraintName != "honeypots_scenario_id_fkey" {
		t.Errorf("DELETE error = %v, want a violation of honeypots_scenario_id_fkey", err)
	}
}

// The schema keeps a scenario from being deleted while an artifact belongs to
// it, as for honeytokens.
func TestSchema_KeepsAScenarioWithArtifacts(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	createArtifact(t, d, sc.ID)

	_, err := d.console.Exec(t.Context(), `DELETE FROM scenarios WHERE id = $1`, sc.ID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" || pgErr.ConstraintName != "artifacts_scenario_id_fkey" {
		t.Errorf("DELETE error = %v, want a violation of artifacts_scenario_id_fkey", err)
	}
}

// Delete locks the scenario, then its honeytokens, then its honeypots, then
// its artifacts: a deletion that waits for an artifact already holds the
// scenario and has removed the honeytokens and the honeypots.
func TestStore_Delete_LocksTheArtifactsAfterTheScenario(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	h := createHoneytoken(t, d, sc.ID)
	p := createHoneypot(t, d, sc.ID)
	a := createArtifact(t, d, sc.ID)

	holder, err := d.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := holder.Exec(t.Context(), `SELECT FROM artifacts WHERE id = $1 FOR UPDATE`, a); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := deleteScenario(t.Context(), d, sc.ID, scenario.RemovalDelete)
		done <- err
	}()
	waitForLockWait(t, d)

	var pgErr *pgconn.PgError
	_, err = d.owner.Exec(t.Context(), `SELECT FROM scenarios WHERE id = $1 FOR KEY SHARE NOWAIT`, sc.ID)
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("probe of the scenario: error = %v, want lock_not_available", err)
	}
	_, err = d.owner.Exec(t.Context(), `SELECT FROM honeytokens WHERE id = $1 FOR KEY SHARE NOWAIT`, h)
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("probe of the honeytoken: error = %v, want lock_not_available", err)
	}
	_, err = d.owner.Exec(t.Context(), `SELECT FROM honeypots WHERE id = $1 FOR KEY SHARE NOWAIT`, p)
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("probe of the honeypot: error = %v, want lock_not_available", err)
	}
	if err := holder.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Errorf("Delete() error = %v", err)
	}
}

// Delete locks the honeypots after the honeytokens and before the artifacts:
// a deletion that waits for a honeypot already holds the scenario and has
// removed the honeytokens, but has not touched the artifacts yet.
func TestStore_Delete_LocksTheHoneypotsAfterTheHoneytokens(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	h := createHoneytoken(t, d, sc.ID)
	p := createHoneypot(t, d, sc.ID)
	a := createArtifact(t, d, sc.ID)

	holder, err := d.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := holder.Exec(t.Context(), `SELECT FROM honeypots WHERE id = $1 FOR UPDATE`, p); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := deleteScenario(t.Context(), d, sc.ID, scenario.RemovalDelete)
		done <- err
	}()
	waitForLockWait(t, d)

	var pgErr *pgconn.PgError
	_, err = d.owner.Exec(t.Context(), `SELECT FROM scenarios WHERE id = $1 FOR KEY SHARE NOWAIT`, sc.ID)
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("probe of the scenario: error = %v, want lock_not_available", err)
	}
	_, err = d.owner.Exec(t.Context(), `SELECT FROM honeytokens WHERE id = $1 FOR KEY SHARE NOWAIT`, h)
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("probe of the honeytoken: error = %v, want lock_not_available", err)
	}
	if _, err := d.owner.Exec(t.Context(), `SELECT FROM artifacts WHERE id = $1 FOR KEY SHARE NOWAIT`, a); err != nil {
		t.Errorf("probe of the artifact: error = %v, want no lock before the honeypots are removed", err)
	}
	if err := holder.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Errorf("Delete() error = %v", err)
	}
}

// Delete takes the lock of the scenario before it touches the honeytokens,
// in the order of the assignment, which locks the scenario first as well.
func TestStore_Delete_LocksTheScenarioFirst(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	h := createHoneytoken(t, d, sc.ID)

	// The honeytoken is held, so the deletion must stop at it, holding the
	// scenario already.
	holder, err := d.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err := holder.Exec(t.Context(), `SELECT FROM honeytokens WHERE id = $1 FOR UPDATE`, h); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := deleteScenario(t.Context(), d, sc.ID, scenario.RemovalDelete)
		done <- err
	}()
	waitForLockWait(t, d)

	_, err = d.owner.Exec(t.Context(), `SELECT FROM scenarios WHERE id = $1 FOR KEY SHARE NOWAIT`, sc.ID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("probe of the scenario: error = %v, want lock_not_available", err)
	}
	if err := holder.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Errorf("Delete() error = %v", err)
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
// inventory. A deletion records every honeytoken that it removes.
func TestCreateUpdateDelete_RecordEveryWrite(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	ctx := t.Context()

	kept, err := scenario.Create(ctx, d.console, actor, scenario.Spec{Name: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scenario.Update(ctx, d.console, actor, kept.ID, scenario.Change{Name: ptr("b"), Notes: ptr("n")}); err != nil {
		t.Fatal(err)
	}
	if _, err := scenario.Update(ctx, d.console, actor, kept.ID, scenario.Change{Name: ptr("b")}); err != nil {
		t.Fatal(err)
	}
	detached := createHoneytoken(t, d, kept.ID)
	detachedHoneypot := createHoneypot(t, d, kept.ID)
	detachedArtifact := createArtifact(t, d, kept.ID)
	keep := scenario.ResourceRemovals{
		Honeytokens: scenario.RemovalKeep, Honeypots: scenario.RemovalKeep, Artifacts: scenario.RemovalKeep,
	}
	if _, err := scenario.Delete(ctx, d.console, actor, kept.ID, keep); err != nil {
		t.Fatal(err)
	}
	deleted, err := scenario.Create(ctx, d.console, actor, scenario.Spec{Name: "c"})
	if err != nil {
		t.Fatal(err)
	}
	removed := createHoneytoken(t, d, deleted.ID)
	removedHoneypot := createHoneypot(t, d, deleted.ID)
	removedArtifact := createArtifact(t, d, deleted.ID)
	remove := scenario.ResourceRemovals{
		Honeytokens: scenario.RemovalDelete, Honeypots: scenario.RemovalDelete, Artifacts: scenario.RemovalDelete,
	}
	if _, err := scenario.Delete(ctx, d.console, actor, deleted.ID, remove); err != nil {
		t.Fatal(err)
	}

	want := []entry{
		{"scenario.create", "scenario", kept.ID, []string{}, actor.UserID},
		{"scenario.update", "scenario", kept.ID, []string{"name", "notes"}, actor.UserID},
		{"honeytoken.update", "honeytoken", detached, []string{"scenario_id"}, actor.UserID},
		{"honeypot.update", "honeypot", detachedHoneypot, []string{"scenario_id"}, actor.UserID},
		{"artifact.update", "artifact", detachedArtifact, []string{"scenario_id"}, actor.UserID},
		{"scenario.delete", "scenario", kept.ID, []string{}, actor.UserID},
		{"scenario.create", "scenario", deleted.ID, []string{}, actor.UserID},
		{"honeytoken.delete", "honeytoken", removed, []string{}, actor.UserID},
		{"honeypot.delete", "honeypot", removedHoneypot, []string{}, actor.UserID},
		{"artifact.delete", "artifact", removedArtifact, []string{}, actor.UserID},
		{"scenario.delete", "scenario", deleted.ID, []string{}, actor.UserID},
	}
	if got := entries(t, d); !sameEntries(got, want) {
		t.Errorf("audit entries = %+v, want %+v", got, want)
	}
}

// A failed audit entry fails the action, also one of a removed honeytoken or
// honeypot, so that no write goes unrecorded.
func TestCreateUpdateDelete_FailWithoutTheirAuditEntry(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc := create(t, d, scenario.Spec{Name: "a"})
	h := createHoneytoken(t, d, sc.ID)
	p := createHoneypot(t, d, sc.ID)
	// An actor without an account fails the check of the audit log.
	ghost := audit.Actor{Kind: audit.ActorUser, Method: audit.AuthSession, UserID: "00000000-0000-4000-8000-000000000000"}
	ctx := t.Context()

	if _, err := scenario.Create(ctx, d.console, ghost, scenario.Spec{Name: "b"}); err == nil {
		t.Error("Create() without audit entry succeeded")
	}
	if _, err := scenario.Update(ctx, d.console, ghost, sc.ID, scenario.Change{Name: ptr("c")}); err == nil {
		t.Error("Update() without audit entry succeeded")
	}
	for _, r := range scenario.Removals {
		if _, err := scenario.Delete(ctx, d.console, ghost, sc.ID, scenario.ResourceRemovals{Honeytokens: r, Honeypots: r, Artifacts: r}); err == nil {
			t.Errorf("Delete(%s) without audit entry succeeded", r)
		}
	}
	got, err := scenario.NewStore(d.console).Get(ctx, sc.ID)
	if err != nil || got.Name != "a" {
		t.Errorf("Get() = %+v, %v; want the unchanged scenario", got, err)
	}
	if s, ok := scenarioOf(t, d, h); !ok || s != sc.ID {
		t.Errorf("honeytoken in %q, exists %v; want it unchanged", s, ok)
	}
	if s, ok := honeypotScenarioOf(t, d, p); !ok || s != sc.ID {
		t.Errorf("honeypot in %q, exists %v; want it unchanged", s, ok)
	}

	// The entry of the honeypot fails first in a scenario without
	// honeytokens.
	only := create(t, d, scenario.Spec{Name: "o"})
	op := createHoneypot(t, d, only.ID)
	for _, r := range scenario.Removals {
		if _, err := scenario.Delete(ctx, d.console, ghost, only.ID, scenario.ResourceRemovals{Honeytokens: r, Honeypots: r, Artifacts: r}); err == nil {
			t.Errorf("Delete(%s) of a scenario with a honeypot without audit entry succeeded", r)
		}
	}
	if s, ok := honeypotScenarioOf(t, d, op); !ok || s != only.ID {
		t.Errorf("honeypot in %q, exists %v; want it unchanged", s, ok)
	}
}

// The schema is the last line of defense: each rule rejects a row that the
// application never writes, under the name that the store maps.
func TestSchema_ChecksScenarios(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)

	const insert = `INSERT INTO scenarios (name, notes, engage_activities, persona) VALUES ($1, $2, $3, $4)`
	valid := []any{"a", "", []string{}, `{"Domain": "corp.example.com"}`}
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
		{"empty name", with(0, ""), "scenarios_name_check"},
		{"long name", with(0, strings.Repeat("x", 101)), "scenarios_name_check"},
		{"name with spaces around", with(0, " a"), "scenarios_name_check"},
		{"name with line break", with(0, "a\nb"), "scenarios_name_check"},
		{"long notes", with(1, strings.Repeat("x", 2001)), "scenarios_notes_check"},
		{"notes with escape", with(1, "a\x1bb"), "scenarios_notes_check"},
		{"malformed activity", with(2, []string{"EAC5"}), "scenarios_engage_activities_check"},
		{"strategic activity", with(2, []string{"SPR0001"}), "scenarios_engage_activities_check"},
		{"repeated activity", with(2, []string{"EAC0005", "EAC0005"}), "scenarios_engage_activities_check"},
		{"too many activities", with(2, engageIDs(t)[:21]), "scenarios_engage_activities_check"},
		{"persona as a list", with(3, `["corp.example.com"]`), "scenarios_persona_check"},
		{"persona with a number", with(3, `{"Port": 22}`), "scenarios_persona_check"},
		{"persona too large", with(3, `{"Text": "`+strings.Repeat("a", 16384)+`"}`), "scenarios_persona_check"},
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
	var equal bool
	if err := d.owner.QueryRow(t.Context(), `SELECT created_at = updated_at FROM scenarios`).Scan(&equal); err != nil || !equal {
		t.Errorf("created_at = updated_at: %v, %v; want true", equal, err)
	}
	_, err := d.owner.Exec(t.Context(), `UPDATE scenarios SET updated_at = created_at - interval '1 second'`)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.ConstraintName != "scenarios_updated_at_check" {
		t.Errorf("update before creation: error = %v, want a violation of scenarios_updated_at_check", err)
	}
}

// engageIDs returns the identifiers of every activity of the bundled version
// of Engage.
func engageIDs(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("../engage/activities.json")
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Activities []struct {
			ID string `json:"id"`
		} `json:"activities"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(list.Activities))
	for _, a := range list.Activities {
		ids = append(ids, a.ID)
	}
	return ids
}

// The schema accepts every identifier that the code accepts: every activity
// of the bundled Engage and every deception of the embedded catalog.
func TestSchema_AcceptsTheIdentifiersOfEngageAndTheCatalog(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)

	for _, id := range engageIDs(t) {
		if err := scenario.ValidateEngageActivities([]string{id}); err != nil {
			t.Errorf("ValidateEngageActivities(%s) error = %v", id, err)
		}
		if _, err := d.owner.Exec(t.Context(), `INSERT INTO scenarios (name, engage_activities) VALUES ('a', $1)`, []string{id}); err != nil {
			t.Errorf("activity %s: %v", id, err)
		}
	}
	c, err := catalog.Load(embedded.FS())
	if err != nil {
		t.Fatal(err)
	}
	var scenarioID string
	if err := d.owner.QueryRow(t.Context(), `INSERT INTO scenarios (name) VALUES ('a') RETURNING id`).Scan(&scenarioID); err != nil {
		t.Fatal(err)
	}
	// A scenario holds 20 deceptions at most, so each goes into a scenario of its own.
	for _, dec := range c.Deceptions() {
		for _, lang := range catalog.Languages {
			if err := d.owner.QueryRow(t.Context(), `INSERT INTO scenarios (name) VALUES ('a') RETURNING id`).Scan(&scenarioID); err != nil {
				t.Fatal(err)
			}
			_, err := d.owner.Exec(t.Context(), `INSERT INTO scenario_deceptions (scenario_id, deception_id, language, guide) VALUES ($1, $2, $3, 'g')`, scenarioID, dec.ID, lang)
			if err != nil {
				t.Errorf("deception %s in %s: %v", dec.ID, lang, err)
			}
		}
	}
}
