// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenario_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"nyktus.org/nyktus/internal/artifact"
	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/scenario"
)

func join(t *testing.T, c *catalog.Catalog, id string, persona map[string]string) scenario.Join {
	t.Helper()
	d, ok := c.Lookup(id)
	if !ok {
		t.Fatalf("no deception %s", id)
	}
	return scenario.Join{Deception: d, Language: "en", Persona: persona, TriggerURL: triggerURL, DNSZone: dnsZone}
}

func artifactOf(t *testing.T, c *catalog.Catalog, id string) catalog.Artifact {
	t.Helper()
	a, ok := c.LookupArtifact(id)
	if !ok {
		t.Fatalf("no artifact %s", id)
	}
	return a
}

func addDeception(t *testing.T, d testDB, actor audit.Actor, id string, j scenario.Join) scenario.Applied {
	t.Helper()
	applied, err := scenario.AddDeception(t.Context(), d.console, actor, scenario.Addition{ScenarioID: id, Join: j})
	if err != nil {
		t.Fatalf("AddDeception(%s) error = %v", j.Deception.ID, err)
	}
	return applied
}

func content(t *testing.T, d testDB, artifactID string) string {
	t.Helper()
	var s string
	if err := d.owner.QueryRow(t.Context(), `SELECT convert_from(content, 'UTF8') FROM artifacts WHERE id = $1`, artifactID).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

var domain = map[string]string{"Domain": "corp.example.com"}

// A deception joins a scenario that exists with its honeytokens, artifacts and
// guide, and the persona of the scenario grows by the keys it lacks.
func TestAddDeception_JoinsTheScenario(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s", EngageActivities: []string{"EAC0006"}})

	first := addDeception(t, d, actor, sc.ID, join(t, c, "ssh", domain))
	if got := first.Scenario; len(got.Deceptions) != 1 || got.Deceptions[0].DeceptionID != "ssh" || got.Persona["Domain"] != "corp.example.com" ||
		!slices.Equal(got.EngageActivities, []string{"EAC0006", "EAC0005", "EAC0012"}) || !got.UpdatedAt.After(sc.UpdatedAt) {
		t.Errorf("scenario = %+v", got)
	}
	if len(first.Honeytokens) != 2 || first.Honeytokens[0].ScenarioID == nil || *first.Honeytokens[0].ScenarioID != sc.ID ||
		first.Honeytokens[1].ScenarioID == nil || *first.Honeytokens[1].ScenarioID != sc.ID {
		t.Fatalf("honeytokens = %+v, want two in the scenario", first.Honeytokens)
	}
	if len(first.Artifacts) != 1 {
		t.Fatalf("%d artifacts, want 1", len(first.Artifacts))
	}
	a := first.Artifacts[0]
	host := first.Honeytokens[0].TriggerValue + "." + dnsZone
	if a.CatalogArtifact != "ssh" || a.ScenarioID == nil || *a.ScenarioID != sc.ID ||
		a.Placing != "Place it on a host of corp.example.com." ||
		len(a.Bindings) != 1 || a.Bindings["Gateway"] != first.Honeytokens[0].ID || !strings.Contains(content(t, d, a.ID), host) {
		t.Errorf("artifact = %+v", a)
	}

	// The second deception asks for the company as well and takes the domain
	// that the scenario has.
	second := addDeception(t, d, actor, sc.ID, join(t, c, "rdp", map[string]string{"Company": "Example Ltd"}))
	if got := second.Scenario; len(got.Deceptions) != 2 || got.Deceptions[1].DeceptionID != "rdp" ||
		got.Persona["Domain"] != "corp.example.com" || got.Persona["Company"] != "Example Ltd" || len(got.Persona) != 2 {
		t.Errorf("scenario = %+v", got)
	}
	if content := content(t, d, second.Artifacts[0].ID); !strings.Contains(content, "corp.example.com") {
		t.Errorf("artifact = %q, want the domain of the scenario", content)
	}

	guides, err := scenario.NewStore(d.console).Guides(t.Context(), sc.ID)
	if err != nil || len(guides) != 2 || guides[0].DeceptionID != "ssh" || guides[1].DeceptionID != "rdp" ||
		!strings.Contains(guides[1].Content, "Example Ltd") {
		t.Errorf("Guides() = %+v, %v; want the guides of ssh and rdp in order", guides, err)
	}

	got := entries(t, d)
	var actions []string
	for _, e := range got {
		actions = append(actions, e.Action)
		if e.Action == "scenario.update" {
			actions[len(actions)-1] += ":" + strings.Join(e.ChangedFields, ",")
		}
	}
	wantActions := []string{
		"honeytoken.create", "honeytoken.create", "artifact.create", "scenario.update:deceptions,persona,engage_activities",
		"honeytoken.create", "honeytoken.create", "artifact.create", "scenario.update:deceptions,persona",
	}
	if !slices.Equal(actions, wantActions) {
		t.Errorf("audit entries = %v, want %v", actions, wantActions)
	}
}

// The persona only grows: a value that the scenario has is kept, repeated or
// left out, and any other is refused without naming a value.
func TestAddDeception_PersonaOnlyGrows(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	addDeception(t, d, actor, sc.ID, join(t, c, "ssh", domain))

	for _, tt := range []struct {
		name    string
		persona map[string]string
		want    error
		key     string
	}{
		{"another value", map[string]string{"Domain": "other.example.com", "Company": "Example Ltd"}, catalog.ErrPersonaConflict, "Domain"},
		{"another case", map[string]string{"Domain": "Corp.Example.Com", "Company": "Example Ltd"}, catalog.ErrPersonaConflict, "Domain"},
		{"missing key the scenario lacks", map[string]string{"Domain": "corp.example.com"}, catalog.ErrInvalidPersona, "Company"},
		{"empty value", map[string]string{"Company": ""}, catalog.ErrInvalidPersona, "Company"},
		{"too long for its kind", map[string]string{"Company": strings.Repeat("a", catalog.MaxTextLength+1)}, catalog.ErrInvalidPersona, "Company"},
		{"unknown key", map[string]string{"Company": "Example Ltd", "Zone": "x"}, catalog.ErrInvalidPersona, "Zone"},
	} {
		_, err := scenario.AddDeception(t.Context(), d.console, actor, scenario.Addition{ScenarioID: sc.ID, Join: join(t, c, "rdp", tt.persona)})
		if !errors.Is(err, tt.want) {
			t.Errorf("%s: AddDeception() error = %v, want %v", tt.name, err, tt.want)
			continue
		}
		for _, secret := range []string{"other.example.com", "Corp.Example.Com", "corp.example.com"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: the error repeats a value of the persona: %v", tt.name, err)
			}
		}
		if !strings.Contains(err.Error(), tt.key) {
			t.Errorf("%s: error = %v, want it to name %s", tt.name, err, tt.key)
		}
	}
	got, err := scenario.NewStore(d.console).Get(t.Context(), sc.ID)
	if err != nil || len(got.Persona) != 1 || got.Persona["Domain"] != "corp.example.com" || len(got.Deceptions) != 1 {
		t.Errorf("scenario = %+v, %v; want nothing added", got, err)
	}
	if n := count(t, d, `SELECT count(*) FROM honeytokens`); n != 2 {
		t.Errorf("%d honeytokens, want the 2 of the first deception", n)
	}

	// The value may be repeated.
	addDeception(t, d, actor, sc.ID, join(t, c, "rdp", map[string]string{"Domain": "corp.example.com", "Company": "Example Ltd"}))
}

// A deception joins a scenario at most once, and a scenario holds at most as
// many deceptions as the schema allows.
func TestAddDeception_JoinsOnceAndHasALimit(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	addDeception(t, d, actor, sc.ID, join(t, c, "ssh", domain))

	_, err := scenario.AddDeception(t.Context(), d.console, actor, scenario.Addition{ScenarioID: sc.ID, Join: join(t, c, "ssh", domain)})
	if !errors.Is(err, scenario.ErrDeceptionAdded) {
		t.Errorf("AddDeception(twice) error = %v, want ErrDeceptionAdded", err)
	}
	if n := count(t, d, `SELECT count(*) FROM honeytokens`) + count(t, d, `SELECT count(*) FROM artifacts`); n != 3 {
		t.Errorf("%d honeytokens and artifacts, want the 3 of the first", n)
	}
	// The schema says the same.
	_, err = d.owner.Exec(t.Context(), `INSERT INTO scenario_deceptions (scenario_id, deception_id, language, guide) VALUES ($1, 'ssh', 'en', 'g')`, sc.ID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.ConstraintName != "scenario_deceptions_pkey" {
		t.Errorf("insert twice: error = %v, want a violation of scenario_deceptions_pkey", err)
	}

	// Fill the scenario up to the limit.
	if _, err := d.owner.Exec(t.Context(), `
INSERT INTO scenario_deceptions (scenario_id, deception_id, language, guide)
SELECT $1, 'filler-' || n, 'en', 'g' FROM generate_series(1, $2::int - 1) AS n`, sc.ID, scenario.MaxDeceptions); err != nil {
		t.Fatal(err)
	}
	_, err = scenario.AddDeception(t.Context(), d.console, actor, scenario.Addition{ScenarioID: sc.ID, Join: join(t, c, "rdp", map[string]string{"Company": "Example Ltd"})})
	if !errors.Is(err, scenario.ErrTooManyDeceptions) {
		t.Errorf("AddDeception(over the limit) error = %v, want ErrTooManyDeceptions", err)
	}
	_, err = d.owner.Exec(t.Context(), `INSERT INTO scenario_deceptions (scenario_id, deception_id, language, guide) VALUES ($1, 'one-more', 'en', 'g')`, sc.ID)
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "scenario_deceptions_limit_check" {
		t.Errorf("insert over the limit: error = %v, want a violation of scenario_deceptions_limit_check", err)
	}
	if n := count(t, d, `SELECT count(*) FROM scenario_deceptions`); n != scenario.MaxDeceptions {
		t.Errorf("%d deceptions, want %d", n, scenario.MaxDeceptions)
	}
}

// A scenario holds at most as many artifacts as the schema allows, also when a
// deception brings several.
func TestAdd_ArtifactsHaveALimit(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	if _, err := d.owner.Exec(t.Context(), `
INSERT INTO artifacts (scenario_id, catalog_artifact, file_name, format, content)
SELECT $1, 'filler', 'f', 'text', '\x41' FROM generate_series(1, $2::int - 1)`, sc.ID, artifact.MaxPerScenario); err != nil {
		t.Fatal(err)
	}

	// One artifact more fits, two do not.
	_, err := scenario.AddDeception(t.Context(), d.console, actor, scenario.Addition{ScenarioID: sc.ID, Join: join(t, c, "pair", domain)})
	if !errors.Is(err, artifact.ErrLimit) {
		t.Errorf("AddDeception(two artifacts at the limit) error = %v, want artifact.ErrLimit", err)
	}
	if n := count(t, d, `SELECT count(*) FROM honeytokens`); n != 0 {
		t.Errorf("%d honeytokens after a refusal, want none", n)
	}
	one := join(t, c, "pair", domain)
	one.Artifacts = []string{"ssh"}
	addDeception(t, d, actor, sc.ID, one)

	_, err = scenario.AddArtifact(t.Context(), d.console, actor, scenario.ArtifactAddition{
		ScenarioID: sc.ID, Artifact: artifactOf(t, c, "memo"), Language: "en",
	})
	if !errors.Is(err, artifact.ErrLimit) {
		t.Errorf("AddArtifact(over the limit) error = %v, want artifact.ErrLimit", err)
	}
	_, err = d.owner.Exec(t.Context(), `INSERT INTO artifacts (scenario_id, catalog_artifact, file_name, format, content) VALUES ($1, 'one-more', 'f', 'text', '\x41')`, sc.ID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "artifacts_limit_check" {
		t.Errorf("insert over the limit: error = %v, want a violation of artifacts_limit_check", err)
	}
	// The store maps the same violation.
	_, err = artifact.NewStore(d.console).Create(t.Context(), artifact.Spec{ScenarioID: sc.ID, CatalogArtifact: "memo", FileName: "m", Format: catalog.FormatText})
	if !errors.Is(err, artifact.ErrLimit) {
		t.Errorf("Create(over the limit) error = %v, want artifact.ErrLimit", err)
	}
}

// Only some of the artifacts of a deception can be created, in its order, and
// only those that it recommends.
func TestAddDeception_SelectsArtifacts(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)

	for _, tt := range []struct {
		name      string
		artifacts []string
		want      []string
		err       error
	}{
		{"all", nil, []string{"rdp", "ssh"}, nil},
		{"none", []string{}, nil, nil},
		{"one", []string{"ssh"}, []string{"ssh"}, nil},
		{"in another order", []string{"ssh", "rdp"}, []string{"rdp", "ssh"}, nil},
		{"not recommended", []string{"memo"}, nil, scenario.ErrInvalidSelection},
		{"twice", []string{"ssh", "ssh"}, nil, scenario.ErrInvalidSelection},
		{"unknown", []string{"nothing"}, nil, scenario.ErrInvalidSelection},
	} {
		j := join(t, c, "pair", domain)
		j.Artifacts = tt.artifacts
		applied, err := scenario.Apply(t.Context(), d.console, actor, scenario.Application{Join: j, Name: tt.name})
		if !errors.Is(err, tt.err) {
			t.Errorf("%s: Apply() error = %v, want %v", tt.name, err, tt.err)
			continue
		}
		var got []string
		for _, a := range applied.Artifacts {
			got = append(got, a.CatalogArtifact)
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s: artifacts = %v, want %v", tt.name, got, tt.want)
		}
		if tt.err == nil && len(applied.Honeytokens) != 2 {
			t.Errorf("%s: %d honeytokens, want those of the deception whatever artifacts are chosen", tt.name, len(applied.Honeytokens))
		}
	}
}

// Adding is atomic: a value that makes an artifact reveal what it is, a
// resource that cannot be stored or an audit entry that cannot be written
// leaves the scenario as it was.
func TestAddDeception_IsAtomic(t *testing.T) {
	t.Parallel()
	c := testCatalog(t)

	assertUnchanged := func(t *testing.T, d testDB, scID, name string) {
		t.Helper()
		got, err := scenario.NewStore(d.console).Get(t.Context(), scID)
		if err != nil || len(got.Deceptions) != 0 || len(got.Persona) != 0 || len(got.EngageActivities) != 0 {
			t.Errorf("%s: scenario = %+v, %v; want it as created", name, got, err)
		}
		for _, table := range []string{"scenario_deceptions", "honeytokens", "artifacts"} {
			if n := count(t, d, `SELECT count(*) FROM `+table); n != 0 {
				t.Errorf("%s: %d rows in %s, want none", name, n, table)
			}
		}
		if n := count(t, d, `SELECT count(*) FROM audit_entries`); n != 0 {
			t.Errorf("%s: %d audit entries, want none", name, n)
		}
	}
	inject := func(t *testing.T, d testDB, table string) {
		t.Helper()
		for _, statement := range []string{
			`CREATE FUNCTION fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$`,
			`CREATE TRIGGER fail BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION fail()`,
		} {
			if _, err := d.owner.Exec(t.Context(), statement); err != nil {
				t.Fatal(err)
			}
		}
	}

	t.Run("render", func(t *testing.T) {
		t.Parallel()
		d := newTestDB(t)
		sc := create(t, d, scenario.Spec{Name: "s"})
		j := join(t, c, "ssh", domain)
		j.DNSZone = "canary.example.net"
		_, err := scenario.AddDeception(t.Context(), d.console, createUser(t, d), scenario.Addition{ScenarioID: sc.ID, Join: j})
		var re *catalog.RevealError
		if !errors.As(err, &re) || re.Artifact != "ssh" || re.Marker != "canary" {
			t.Errorf("AddDeception() error = %v, want a RevealError of ssh", err)
		}
		assertUnchanged(t, d, sc.ID, "render")
	})
	for _, table := range []string{"honeytokens", "scenario_deceptions", "artifacts"} {
		t.Run(table, func(t *testing.T) {
			t.Parallel()
			d := newTestDB(t)
			sc := create(t, d, scenario.Spec{Name: "s"})
			actor := createUser(t, d)
			inject(t, d, table)
			// The user is created before the failing trigger counts anything.
			if _, err := d.owner.Exec(t.Context(), `DELETE FROM audit_entries`); err != nil {
				t.Fatal(err)
			}
			_, err := scenario.AddDeception(t.Context(), d.console, actor, scenario.Addition{ScenarioID: sc.ID, Join: join(t, c, "ssh", domain)})
			if err == nil || !strings.Contains(err.Error(), "injected") {
				t.Errorf("AddDeception() error = %v, want the injected failure", err)
			}
			assertUnchanged(t, d, sc.ID, table)
		})
	}
	t.Run("audit", func(t *testing.T) {
		t.Parallel()
		d := newTestDB(t)
		sc := create(t, d, scenario.Spec{Name: "s"})
		// An actor without an account fails the check of the audit log.
		ghost := audit.Actor{Kind: audit.ActorUser, Method: audit.AuthSession, UserID: "00000000-0000-4000-8000-000000000000"}
		if _, err := scenario.AddDeception(t.Context(), d.console, ghost, scenario.Addition{ScenarioID: sc.ID, Join: join(t, c, "ssh", domain)}); err == nil {
			t.Error("AddDeception() without audit entry succeeded")
		}
		assertUnchanged(t, d, sc.ID, "audit")
	})
	t.Run("the audit entry of the scenario", func(t *testing.T) {
		t.Parallel()
		d := newTestDB(t)
		sc := create(t, d, scenario.Spec{Name: "s"})
		actor := createUser(t, d)
		// The entry that records the change of the scenario is the last write.
		for _, statement := range []string{
			`CREATE FUNCTION fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = 'scenario.update' THEN RAISE EXCEPTION 'injected'; END IF; RETURN NEW; END $$`,
			`CREATE TRIGGER fail BEFORE INSERT ON audit_entries FOR EACH ROW EXECUTE FUNCTION fail()`,
		} {
			if _, err := d.owner.Exec(t.Context(), statement); err != nil {
				t.Fatal(err)
			}
		}
		_, err := scenario.AddDeception(t.Context(), d.console, actor, scenario.Addition{ScenarioID: sc.ID, Join: join(t, c, "ssh", domain)})
		if err == nil || !strings.Contains(err.Error(), "injected") {
			t.Errorf("AddDeception() error = %v, want the injected failure", err)
		}
		got, getErr := scenario.NewStore(d.console).Get(t.Context(), sc.ID)
		if getErr != nil || len(got.Deceptions) != 0 || len(got.Persona) != 0 {
			t.Errorf("scenario = %+v, %v; want it as created", got, getErr)
		}
		for _, table := range []string{"scenario_deceptions", "honeytokens", "artifacts"} {
			if n := count(t, d, `SELECT count(*) FROM `+table); n != 0 {
				t.Errorf("%d rows in %s, want none", n, table)
			}
		}
	})
}

// A scenario that does not exist is not found, and nothing is created.
func TestAdd_UnknownScenario(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)

	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		_, err := scenario.AddDeception(t.Context(), d.console, actor, scenario.Addition{ScenarioID: id, Join: join(t, c, "ssh", domain)})
		if !errors.Is(err, scenario.ErrNotFound) {
			t.Errorf("AddDeception(%q) error = %v, want ErrNotFound", id, err)
		}
		_, err = scenario.AddArtifact(t.Context(), d.console, actor, scenario.ArtifactAddition{ScenarioID: id, Artifact: artifactOf(t, c, "memo"), Language: "en"})
		if !errors.Is(err, scenario.ErrNotFound) {
			t.Errorf("AddArtifact(%q) error = %v, want ErrNotFound", id, err)
		}
	}
	for _, table := range []string{"honeytokens", "artifacts", "audit_entries"} {
		if n := count(t, d, `SELECT count(*) FROM `+table); n != 0 {
			t.Errorf("%d rows in %s, want none", n, table)
		}
	}
}

// Every value of an addition is validated before anything is written.
func TestAddDeception_ValidatesBeforeWriting(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})

	for name, tt := range map[string]struct {
		change func(*scenario.Join)
		want   error
	}{
		"language": {func(j *scenario.Join) { j.Language = "fr" }, scenario.ErrInvalidLanguage},
		"no zone":  {func(j *scenario.Join) { j.DNSZone = "" }, scenario.ErrDNSNotConfigured},
		"artifact": {func(j *scenario.Join) { j.Artifacts = []string{"memo"} }, scenario.ErrInvalidSelection},
	} {
		j := join(t, c, "ssh", domain)
		tt.change(&j)
		if _, err := scenario.AddDeception(t.Context(), d.console, actor, scenario.Addition{ScenarioID: sc.ID, Join: j}); !errors.Is(err, tt.want) {
			t.Errorf("%s: AddDeception() error = %v, want %v", name, err, tt.want)
		}
	}
	if n := count(t, d, `SELECT count(*) FROM audit_entries`) + count(t, d, `SELECT count(*) FROM honeytokens`); n != 0 {
		t.Errorf("%d rows after refusals, want none", n)
	}
}

// Deleting a scenario removes its deceptions, and its resources are kept or
// deleted as before.
func TestDelete_RemovesTheDeceptionsOfTheScenario(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)

	for _, removal := range []scenario.Removal{scenario.RemovalKeep, scenario.RemovalDelete} {
		sc := create(t, d, scenario.Spec{Name: string(removal)})
		addDeception(t, d, actor, sc.ID, join(t, c, "ssh", domain))
		addDeception(t, d, actor, sc.ID, join(t, c, "rdp", map[string]string{"Company": "Example Ltd"}))

		removed, err := scenario.Delete(t.Context(), d.console, actor, sc.ID, scenario.ResourceRemovals{Honeytokens: removal, Honeypots: removal, Artifacts: removal})
		if err != nil {
			t.Fatalf("Delete(%s) error = %v", removal, err)
		}
		if n := count(t, d, `SELECT count(*) FROM scenario_deceptions WHERE scenario_id = $1`, sc.ID); n != 0 {
			t.Errorf("Delete(%s): %d deceptions left, want none", removal, n)
		}
		if removal == scenario.RemovalKeep && (len(removed.DetachedHoneytokens) != 4 || len(removed.DetachedArtifacts) != 2) {
			t.Errorf("Delete(keep) = %+v, want 4 honeytokens and 2 artifacts detached", removed)
		}
		if removal == scenario.RemovalDelete && (len(removed.DeletedHoneytokens) != 4 || len(removed.DeletedArtifacts) != 2) {
			t.Errorf("Delete(delete) = %+v, want 4 honeytokens and 2 artifacts deleted", removed)
		}
	}
}

// The activities of a scenario gain those that follow from what joins, but
// never beyond the most a scenario may name: the rest is left out, and what
// joins is not refused for it.
func TestAddDeception_StopsAddingActivitiesAtTheLimit(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)

	var full []string
	for _, id := range engageIDs(t) {
		if id != "EAC0005" && id != "EAC0012" && len(full) < scenario.MaxEngageActivities {
			full = append(full, id)
		}
	}
	sc := create(t, d, scenario.Spec{Name: "s", EngageActivities: full})

	applied := addDeception(t, d, actor, sc.ID, join(t, c, "ssh", domain))
	if !slices.Equal(applied.Scenario.EngageActivities, full) {
		t.Errorf("activities = %v, want the %d that it had", applied.Scenario.EngageActivities, len(full))
	}
	// One place is left: it goes to the first that follows.
	few := create(t, d, scenario.Spec{Name: "few", EngageActivities: full[:scenario.MaxEngageActivities-1]})
	got := addDeception(t, d, actor, few.ID, join(t, c, "ssh", domain))
	want := append(slices.Clone(full[:scenario.MaxEngageActivities-1]), "EAC0005")
	if !slices.Equal(got.Scenario.EngageActivities, want) {
		t.Errorf("activities = %v, want %v", got.Scenario.EngageActivities, want)
	}
}

// The guides come in the order the deceptions joined, whatever their names.
func TestGuides_AreInTheOrderTheDeceptionsJoined(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	addDeception(t, d, actor, sc.ID, join(t, c, "rdp", map[string]string{"Domain": "corp.example.com", "Company": "Example Ltd"}))
	addDeception(t, d, actor, sc.ID, join(t, c, "ssh", domain))
	addDeception(t, d, actor, sc.ID, join(t, c, "pair", domain))

	guides, err := scenario.NewStore(d.console).Guides(t.Context(), sc.ID)
	var ids []string
	for _, g := range guides {
		ids = append(ids, g.DeceptionID)
	}
	if err != nil || !slices.Equal(ids, []string{"rdp", "ssh", "pair"}) {
		t.Errorf("Guides() = %v, %v; want rdp, ssh and pair in the order they joined", ids, err)
	}
	got, err := scenario.NewStore(d.console).Get(t.Context(), sc.ID)
	var joined []string
	for _, dec := range got.Deceptions {
		joined = append(joined, dec.DeceptionID)
	}
	if err != nil || !slices.Equal(joined, []string{"rdp", "ssh", "pair"}) {
		t.Errorf("Get() deceptions = %v, %v; want the same order", joined, err)
	}
}

// A deception that is part of the scenario already, or a scenario that holds
// the most it may, is told before the persona is judged: a repeat with another
// value is a repeat, not a conflict of the persona.
func TestAddDeception_TellsARepeatBeforeThePersona(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	addDeception(t, d, actor, sc.ID, join(t, c, "ssh", domain))

	other := map[string]string{"Domain": "other.example.com"}
	_, err := scenario.AddDeception(t.Context(), d.console, actor, scenario.Addition{ScenarioID: sc.ID, Join: join(t, c, "ssh", other)})
	if !errors.Is(err, scenario.ErrDeceptionAdded) || errors.Is(err, catalog.ErrPersonaConflict) {
		t.Errorf("AddDeception(repeat with another value) error = %v, want ErrDeceptionAdded", err)
	}

	// At the limit, a repeat is still a repeat.
	if _, err := d.owner.Exec(t.Context(), `
INSERT INTO scenario_deceptions (scenario_id, deception_id, language, guide)
SELECT $1, 'filler-' || n, 'en', 'g' FROM generate_series(1, $2::int - 1) AS n`, sc.ID, scenario.MaxDeceptions); err != nil {
		t.Fatal(err)
	}
	_, err = scenario.AddDeception(t.Context(), d.console, actor, scenario.Addition{ScenarioID: sc.ID, Join: join(t, c, "ssh", domain)})
	if !errors.Is(err, scenario.ErrDeceptionAdded) {
		t.Errorf("AddDeception(repeat at the limit) error = %v, want ErrDeceptionAdded", err)
	}
	// A scenario that is full is told so before the persona is judged.
	_, err = scenario.AddDeception(t.Context(), d.console, actor, scenario.Addition{ScenarioID: sc.ID, Join: join(t, c, "rdp", nil)})
	if !errors.Is(err, scenario.ErrTooManyDeceptions) {
		t.Errorf("AddDeception(at the limit, without a persona) error = %v, want ErrTooManyDeceptions", err)
	}
	// Nothing was created by the refusals.
	if n := count(t, d, `SELECT count(*) FROM honeytokens`); n != 2 {
		t.Errorf("%d honeytokens, want the 2 of the first deception", n)
	}
}

// The largest persona that the code accepts is the largest that the schema
// accepts: the schema counts the text of the jsonb, which has a space after
// every colon and comma.
func TestMergePersona_LimitIsTheLimitOfTheSchema(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	dec, _ := c.Lookup("ssh")

	// Ten keys that the deception does not ask for hold the rest, with
	// characters that JSON writes in more than one byte or escapes.
	padded := func(n int) map[string]string {
		stored := map[string]string{}
		for i := range 10 {
			stored["Pad"+string(rune('A'+i))] = strings.Repeat("v", n/10) + strings.Repeat("\"", i)
		}
		return stored
	}
	size := 0
	for n := 10000; ; n += 10 {
		if _, _, err := dec.MergePersona(padded(n), domain); err != nil {
			break
		}
		size = n
	}
	if size == 0 {
		t.Fatal("no persona fits")
	}
	merged, _, err := dec.MergePersona(padded(size), domain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.owner.Exec(t.Context(), `UPDATE scenarios SET persona = $2 WHERE id = $1`, sc.ID, merged); err != nil {
		t.Errorf("a persona that the code accepts: %v", err)
	}
	var length int
	if err := d.owner.QueryRow(t.Context(), `SELECT octet_length(persona::text) FROM scenarios WHERE id = $1`, sc.ID).Scan(&length); err != nil ||
		length > catalog.MaxPersonaBytes || length < catalog.MaxPersonaBytes-200 {
		t.Errorf("persona has %d bytes as text, %v; want just below %d", length, err, catalog.MaxPersonaBytes)
	}
	// A little more than the code accepts is more than the schema accepts.
	over := padded(size + 400)
	for k, v := range domain {
		over[k] = v
	}
	if _, err := d.owner.Exec(t.Context(), `UPDATE scenarios SET persona = $2 WHERE id = $1`, sc.ID, over); err == nil {
		t.Error("a persona beyond the limit was stored")
	}
}
