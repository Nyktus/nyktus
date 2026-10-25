// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenario_test

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/scenario"
)

func addArtifact(t *testing.T, d testDB, actor audit.Actor, a scenario.ArtifactAddition) scenario.Applied {
	t.Helper()
	applied, err := scenario.AddArtifact(t.Context(), d.console, actor, a)
	if err != nil {
		t.Fatalf("AddArtifact(%s) error = %v", a.Artifact.ID, err)
	}
	return applied
}

func artifactAddition(t *testing.T, c *catalog.Catalog, scenarioID, id string, bindings, persona map[string]string) scenario.ArtifactAddition {
	t.Helper()
	return scenario.ArtifactAddition{
		ScenarioID: scenarioID, Artifact: artifactOf(t, c, id), Language: "en", Persona: persona, Bindings: bindings,
		TriggerURL: triggerURL, DNSZone: dnsZone,
	}
}

func auditActions(t *testing.T, d testDB) []string {
	t.Helper()
	var actions []string
	for _, e := range entries(t, d) {
		a := e.Action
		if len(e.ChangedFields) > 0 {
			a += ":" + strings.Join(e.ChangedFields, ",")
		}
		actions = append(actions, a)
	}
	return actions
}

// An artifact is added with a honeytoken of the scenario in its slot, the
// persona of the scenario and secrets of its own, and is rendered like one that
// applying a deception renders.
func TestAddArtifact_FillsTheSlotsWithHoneytokensOfTheScenario(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	first := addDeception(t, d, actor, sc.ID, join(t, c, "ssh", domain))
	gateway := first.Honeytokens[0]
	if _, err := d.owner.Exec(t.Context(), `DELETE FROM audit_entries`); err != nil {
		t.Fatal(err)
	}

	applied := addArtifact(t, d, actor, artifactAddition(t, c, sc.ID, "rdp", map[string]string{"Gateway": gateway.ID}, nil))
	if len(applied.Artifacts) != 1 || len(applied.Honeytokens) != 0 {
		t.Fatalf("applied = %+v, want one artifact and no honeytoken", applied)
	}
	a := applied.Artifacts[0]
	host := gateway.TriggerValue + "." + dnsZone
	body := content(t, d, a.ID)
	older := content(t, d, first.Artifacts[0].ID)
	if a.CatalogArtifact != "rdp" || a.ScenarioID == nil || *a.ScenarioID != sc.ID || a.FileName != "rdp.conf" ||
		a.Format != catalog.FormatConfig || a.Placing != "" ||
		!slices.Equal(slices.Collect(maps.Values(a.Bindings)), []string{gateway.ID}) ||
		!strings.Contains(body, host+" corp.example.com ") {
		t.Errorf("artifact = %+v, content %q", a, body)
	}
	// Every artifact generates secrets of its own: the password of the older
	// file is not the one of the new file.
	password := func(s string) string { f := strings.Fields(s); return f[len(f)-1] }
	if len(password(body)) != 16 || password(body) == password(older) {
		t.Errorf("passwords %q and %q, want 16 characters each and different", password(body), password(older))
	}
	// Nor does a second file of the same artifact repeat it.
	again := addArtifact(t, d, actor, artifactAddition(t, c, sc.ID, "rdp", map[string]string{"Gateway": gateway.ID}, nil))
	if repeated := content(t, d, again.Artifacts[0].ID); password(repeated) == password(body) || password(repeated) == password(older) {
		t.Errorf("password %q of a second file repeats an earlier one", password(repeated))
	}
	// Nothing about the scenario changes: its persona has the domain, and
	// the activities have the lure and the persona.
	if got := applied.Scenario; !slices.Equal(got.EngageActivities, first.Scenario.EngageActivities) || len(got.Persona) != 1 ||
		!got.UpdatedAt.Equal(first.Scenario.UpdatedAt) {
		t.Errorf("scenario = %+v", got)
	}
	if got := auditActions(t, d); !slices.Equal(got[:1], []string{"artifact.create"}) {
		t.Errorf("audit entries = %v, want the artifact first", got)
	}
}

// The text that says where to place the artifact is rendered with the
// persona, in the language of the request.
func TestAddArtifact_RendersWhereToPlaceIt(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	first := addDeception(t, d, actor, sc.ID, join(t, c, "rdp", map[string]string{"Domain": "corp.example.com", "Company": "Example Ltd"}))

	add := artifactAddition(t, c, sc.ID, "ssh", map[string]string{"Gateway": first.Honeytokens[0].ID}, nil)
	add.Language = "de"
	got := addArtifact(t, d, actor, add).Artifacts[0]
	if got.Placing != "Lege es auf einen Host von corp.example.com." {
		t.Errorf("placing = %q", got.Placing)
	}
}

// Without a honeytoken in an optional slot, the artifact is pocket litter, and
// the scenario carries out that activity. With one it is a lure. A scenario put
// together by hand takes artifacts as well.
func TestAddArtifact_PocketLitterAndLures(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})

	litter := addArtifact(t, d, actor, artifactAddition(t, c, sc.ID, "memo", nil, nil))
	a := litter.Artifacts[0]
	if a.Bindings == nil || len(a.Bindings) != 0 || content(t, d, a.ID) != "Reminder\n" ||
		!slices.Equal(litter.Scenario.EngageActivities, []string{"EAC0011"}) || len(litter.Scenario.Persona) != 0 {
		t.Errorf("pocket litter = %+v, content %q, scenario %+v", a, content(t, d, a.ID), litter.Scenario)
	}

	image := createHoneytoken(t, d, sc.ID)
	lure := addArtifact(t, d, actor, artifactAddition(t, c, sc.ID, "memo", map[string]string{"Image": image}, nil))
	l := lure.Artifacts[0]
	var path string
	if err := d.owner.QueryRow(t.Context(), `SELECT '/' || trigger_value FROM honeytokens WHERE id = $1`, image).Scan(&path); err != nil {
		t.Fatal(err)
	}
	if l.Bindings["Image"] != image || !strings.Contains(content(t, d, l.ID), triggerURL) ||
		!slices.Equal(lure.Scenario.EngageActivities, []string{"EAC0011", "EAC0005"}) {
		t.Errorf("lure = %+v, content %q, scenario %+v", l, content(t, d, l.ID), lure.Scenario)
	}

	want := []string{"artifact.create", "scenario.update:engage_activities", "artifact.create", "scenario.update:engage_activities"}
	if got := auditActions(t, d); !slices.Equal(got, want) {
		t.Errorf("audit entries = %v, want %v", got, want)
	}
}

// A honeytoken fills a slot only if it belongs to the scenario and has a type
// that the slot takes. A honeytoken that does not exist and one of another
// scenario are answered alike.
func TestAddArtifact_RefusesBindingsThatDoNotFit(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	other := create(t, d, scenario.Spec{Name: "other"})
	first := addDeception(t, d, actor, sc.ID, join(t, c, "ssh", domain))
	gateway, image := first.Honeytokens[0].ID, first.Honeytokens[1].ID
	foreign := createHoneytoken(t, d, other.ID)
	standalone := createHoneytoken(t, d, "")
	if _, err := d.owner.Exec(t.Context(), `DELETE FROM audit_entries`); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name     string
		artifact string
		bindings map[string]string
		slot     string
		reason   string
	}{
		{"unknown slot", "rdp", map[string]string{"Gateway": gateway, "Other": gateway}, "Other", "is not a slot"},
		{"malformed slot", "rdp", map[string]string{"Gateway": gateway, "bad key": gateway}, "with a malformed key", "is not a slot"},
		{"required slot left out", "rdp", nil, "Gateway", "needs a honeytoken"},
		{"honeytoken of another scenario", "rdp", map[string]string{"Gateway": foreign}, "Gateway", "is not filled by a honeytoken of the scenario"},
		{"honeytoken without scenario", "rdp", map[string]string{"Gateway": standalone}, "Gateway", "is not filled by a honeytoken of the scenario"},
		{"honeytoken that does not exist", "rdp", map[string]string{"Gateway": "00000000-0000-4000-8000-000000000000"}, "Gateway", "is not filled by a honeytoken of the scenario"},
		{"identifier that is no uuid", "rdp", map[string]string{"Gateway": "not-a-uuid"}, "Gateway", "is not filled by a honeytoken of the scenario"},
		{"type the slot does not take", "rdp", map[string]string{"Gateway": image}, "Gateway", "does not take honeytokens of that type"},
	} {
		_, err := scenario.AddArtifact(t.Context(), d.console, actor, artifactAddition(t, c, sc.ID, tt.artifact, tt.bindings, nil))
		var be *scenario.BindingError
		if !errors.Is(err, scenario.ErrInvalidBinding) || !errors.As(err, &be) || be.Slot != tt.slot || !strings.Contains(be.Reason, tt.reason) {
			t.Errorf("%s: AddArtifact() error = %v, want a BindingError of %s %q", tt.name, err, tt.slot, tt.reason)
		}
		if err != nil && (strings.Contains(err.Error(), foreign) || strings.Contains(err.Error(), standalone)) {
			t.Errorf("%s: the error names a honeytoken: %v", tt.name, err)
		}
	}
	if n := count(t, d, `SELECT count(*) FROM artifacts`); n != 1 {
		t.Errorf("%d artifacts, want the one of the deception", n)
	}
	if got := auditActions(t, d); len(got) != 0 {
		t.Errorf("audit entries = %v, want none", got)
	}

	// A DNS honeytoken needs the zone of the DNS role.
	noZone := artifactAddition(t, c, sc.ID, "rdp", map[string]string{"Gateway": gateway}, nil)
	noZone.DNSZone = ""
	if _, err := scenario.AddArtifact(t.Context(), d.console, actor, noZone); !errors.Is(err, scenario.ErrDNSNotConfigured) {
		t.Errorf("AddArtifact(without zone) error = %v, want ErrDNSNotConfigured", err)
	}
	// The language is checked like everywhere.
	badLanguage := artifactAddition(t, c, sc.ID, "rdp", map[string]string{"Gateway": gateway}, nil)
	badLanguage.Language = "fr"
	if _, err := scenario.AddArtifact(t.Context(), d.console, actor, badLanguage); !errors.Is(err, scenario.ErrInvalidLanguage) {
		t.Errorf("AddArtifact(language fr) error = %v, want ErrInvalidLanguage", err)
	}
}

// The honeytokens of an artifact are locked until the end of the transaction,
// so that none leaves the scenario or is deleted while the file names it.
func TestAddArtifact_LocksTheHoneytokensItNames(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	gateway := addDeception(t, d, actor, sc.ID, join(t, c, "ssh", domain)).Honeytokens[0].ID

	tx, err := d.console.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := scenario.AddArtifact(t.Context(), tx, actor, artifactAddition(t, c, sc.ID, "rdp", map[string]string{"Gateway": gateway}, nil)); err != nil {
		t.Fatal(err)
	}
	// A deletion or a change would take the row lock FOR UPDATE.
	assertLockedAgainst(t, d, `SELECT id FROM honeytokens WHERE id = $1 FOR UPDATE NOWAIT`, gateway)
}

// A file must not name what it is: the identifiers of the artifact and of the
// deceptions of the scenario are markers, checked when the artifact is added.
func TestAddArtifact_ChecksTheMarkersOfTheScenario(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	addDeception(t, d, actor, sc.ID, join(t, c, "ssh", domain))

	for _, tt := range []struct{ company, marker string }{
		{"ssh holding", "ssh"},
		{"Holding note", "note"},
		{"Canary Ltd", "canary"},
	} {
		_, err := scenario.AddArtifact(t.Context(), d.console, actor, artifactAddition(t, c, sc.ID, "note", nil, map[string]string{"Company": tt.company}))
		var re *catalog.RevealError
		if !errors.As(err, &re) || re.Marker != tt.marker {
			t.Errorf("AddArtifact(%q) error = %v, want a RevealError for %q", tt.company, err, tt.marker)
		}
	}
	got, err := scenario.NewStore(d.console).Get(t.Context(), sc.ID)
	if err != nil || len(got.Persona) != 1 {
		t.Errorf("scenario = %+v, %v; want the persona as it was", got, err)
	}
	if n := count(t, d, `SELECT count(*) FROM artifacts WHERE catalog_artifact = 'note'`); n != 0 {
		t.Errorf("%d artifacts of the refused file, want none", n)
	}
}

// An artifact adds the keys of its persona that the scenario lacks, keeps the
// values it has, and takes the kind of the key from the artifact.
func TestAddArtifact_PersonaOnlyGrows(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})

	grown := addArtifact(t, d, actor, artifactAddition(t, c, sc.ID, "note", nil, map[string]string{"Company": "Example Ltd"}))
	if grown.Scenario.Persona["Company"] != "Example Ltd" {
		t.Fatalf("persona = %v, want the company", grown.Scenario.Persona)
	}
	if got := auditActions(t, d); !slices.Equal(got, []string{"artifact.create", "scenario.update:persona,engage_activities"}) {
		t.Errorf("audit entries = %v", got)
	}

	for _, tt := range []struct {
		name     string
		artifact string
		persona  map[string]string
		want     error
	}{
		{"left out", "note", nil, nil},
		{"repeated", "note", map[string]string{"Company": "Example Ltd"}, nil},
		{"another value", "note", map[string]string{"Company": "Other Ltd"}, catalog.ErrPersonaConflict},
		// The stored value is no host name, whatever the scenario says.
		{"another kind", "hostco", nil, catalog.ErrInvalidPersona},
		{"another kind with a new value", "hostco", map[string]string{"Company": "example.com"}, catalog.ErrPersonaConflict},
		{"unknown key", "note", map[string]string{"Zone": "x"}, catalog.ErrInvalidPersona},
	} {
		_, err := scenario.AddArtifact(t.Context(), d.console, actor, artifactAddition(t, c, sc.ID, tt.artifact, nil, tt.persona))
		if !errors.Is(err, tt.want) {
			t.Errorf("%s: AddArtifact() error = %v, want %v", tt.name, err, tt.want)
		}
		if err != nil && (strings.Contains(err.Error(), "Other Ltd") || strings.Contains(err.Error(), "Example Ltd")) {
			t.Errorf("%s: the error repeats a value of the persona: %v", tt.name, err)
		}
	}
	if n := count(t, d, `SELECT count(*) FROM artifacts`); n != 3 {
		t.Errorf("%d artifacts, want the first, and the two that fit", n)
	}
}

// Adding an artifact is atomic: when the artifact cannot be stored, the persona
// does not grow.
func TestAddArtifact_IsAtomic(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	for _, statement := range []string{
		`CREATE FUNCTION fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$`,
		`CREATE TRIGGER fail BEFORE INSERT ON artifacts FOR EACH ROW EXECUTE FUNCTION fail()`,
	} {
		if _, err := d.owner.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	_, err := scenario.AddArtifact(t.Context(), d.console, actor, artifactAddition(t, c, sc.ID, "note", nil, map[string]string{"Company": "Example Ltd"}))
	if err == nil || !strings.Contains(err.Error(), "injected") {
		t.Errorf("AddArtifact() error = %v, want the injected failure", err)
	}
	got, getErr := scenario.NewStore(d.console).Get(t.Context(), sc.ID)
	if getErr != nil || len(got.Persona) != 0 || len(got.EngageActivities) != 0 {
		t.Errorf("scenario = %+v, %v; want it as created", got, getErr)
	}
	if got := auditActions(t, d); len(got) != 0 {
		t.Errorf("audit entries = %v, want none", got)
	}
}
