// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenario_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	embedded "nyktus.org/nyktus/catalog"
	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/honeypot"
	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/platform/secretbox/secretboxtest"
	"nyktus.org/nyktus/internal/scenario"
)

// The catalog of these tests: two deceptions with the slots of every kind, and
// one that asks for nothing but a file.
//
//   - ssh asks for a DNS and an image honeytoken and for an SSH honeypot.
//   - rdp asks for a URL honeytoken and a PostgreSQL honeypot, and names
//     EAC0011 as well as ssh does EAC0005.
//   - hint has no honeytoken, only a honeypot.
const testDeception = `{
  "schema_version": 3,
  "id": "%ID%",
  "category": "network",
  "title": {"en": "Title %ID%", "de": "Titel %ID%"},
  "summary": {"en": "Summary.", "de": "Zusammenfassung."},
  "techniques": ["T1021.004"],
  "engage_activities": [%ACTIVITIES%],
  "honeytokens": [%HONEYTOKENS%],
  "honeypots": [%HONEYPOTS%],
  "files": [],
  "guide": {"en": "guide.en.md", "de": "guide.de.md"}
}`

const (
	dnsToken   = `{"label": {"en": "Gateway", "de": "Zugang"}, "type": "dns", "techniques": ["T1021.004"], "severity": "high"}`
	imageToken = `{"label": {"en": "Image", "de": "Bild"}, "type": "web_image", "techniques": []}`
	urlToken   = `{"label": {"en": "Link", "de": "Verweis"}, "type": "web_url", "techniques": ["T1566"]}`
	sshPot     = `{"label": {"en": "Jump host", "de": "Sprungserver"}, "service": "ssh"}`
	pgPot      = `{"label": {"en": "Database", "de": "Datenbank"}, "service": "postgres"}`
)

func testCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	file := func(content string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(content)} }
	fsys := fstest.MapFS{}
	for id, def := range map[string]struct{ activities, tokens, pots string }{
		"ssh":  {`"EAC0005"`, dnsToken + "," + imageToken, sshPot},
		"rdp":  {`"EAC0005", "EAC0011"`, urlToken, pgPot},
		"hint": {`"EAC0011"`, "", sshPot},
	} {
		fsys["deceptions/"+id+"/deception.json"] = file(strings.NewReplacer(
			"%ID%", id, "%ACTIVITIES%", def.activities, "%HONEYTOKENS%", def.tokens, "%HONEYPOTS%", def.pots).Replace(testDeception))
		fsys["deceptions/"+id+"/guide.en.md"] = file("Guide.\n")
		fsys["deceptions/"+id+"/guide.de.md"] = file("Anleitung.\n")
	}
	c, err := catalog.Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func deception(t *testing.T, c *catalog.Catalog, id string) catalog.Deception {
	t.Helper()
	d, ok := c.Lookup(id)
	if !ok {
		t.Fatalf("no deception %s", id)
	}
	return d
}

// join returns how the deception id joins a scenario, with the resources if
// create says so.
func join(t *testing.T, c *catalog.Catalog, id string, create bool) scenario.Join {
	t.Helper()
	return scenario.Join{
		Deception: deception(t, c, id), Language: "de", CreateResources: create, DNSConfigured: true, Keys: secretboxtest.Keyring(t),
	}
}

func application(t *testing.T, c *catalog.Catalog, id string, create bool) scenario.Application {
	t.Helper()
	return scenario.Application{Join: join(t, c, id, create), Name: "Jump server", Notes: "admin workstation"}
}

func count(t *testing.T, d testDB, query string) int {
	t.Helper()
	var n int
	if err := d.owner.QueryRow(t.Context(), query).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// assertNothingStored fails the test if anything of an application remains.
func assertNothingStored(t *testing.T, d testDB, name string) {
	t.Helper()
	for _, table := range []string{"scenarios", "scenario_deceptions", "honeytokens", "honeypots", "audit_entries"} {
		if n := count(t, d, `SELECT count(*) FROM `+table); n != 0 {
			t.Errorf("%s: %d rows in %s, want none", name, n, table)
		}
	}
}

// Applying a deception creates a scenario that holds nothing of it but its
// identifier: no honeytoken, no honeypot, no copy of the guide. The
// activities of its story join those of the scenario.
func TestApply_StoresOnlyTheIdentifierOfTheDeception(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)

	applied, err := scenario.Apply(t.Context(), d.console, actor, application(t, c, "rdp", false))
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	sc := applied.Scenario
	if sc.Name != "Jump server" || sc.Notes != "admin workstation" || len(sc.Deceptions) != 1 ||
		sc.Deceptions[0].DeceptionID != "rdp" || sc.Deceptions[0].CreatedAt.IsZero() ||
		!slices.Equal(sc.EngageActivities, []string{"EAC0005", "EAC0011"}) {
		t.Errorf("scenario = %+v", sc)
	}
	if len(applied.Honeytokens) != 0 || len(applied.Honeypots) != 0 {
		t.Errorf("created %d honeytokens and %d honeypots, want none", len(applied.Honeytokens), len(applied.Honeypots))
	}
	for _, table := range []string{"honeytokens", "honeypots"} {
		if n := count(t, d, `SELECT count(*) FROM `+table); n != 0 {
			t.Errorf("%d rows in %s, want none", n, table)
		}
	}
	// The scenario is the only thing that is recorded.
	want := []entry{{"scenario.create", "scenario", sc.ID, []string{}, actor.UserID}}
	if got := entries(t, d); !sameEntries(got, want) {
		t.Errorf("audit entries = %+v, want %+v", got, want)
	}
}

// With the resources, the honeytokens and honeypots of the deception are
// created in the scenario, named after the labels of the language, with the
// severity and the techniques of the slot, and each is recorded with the field
// scenario_id. The secret of a honeypot is readable afterwards.
func TestApply_CreatesTheResourcesWhenAsked(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	dec := deception(t, c, "ssh")
	a := application(t, c, "ssh", true)

	applied, err := scenario.Apply(t.Context(), d.console, actor, a)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	sc := applied.Scenario
	if len(applied.Honeytokens) != 2 || len(applied.Honeypots) != 1 {
		t.Fatalf("created %d honeytokens and %d honeypots, want 2 and 1", len(applied.Honeytokens), len(applied.Honeypots))
	}
	h := applied.Honeytokens[0]
	slot := dec.Honeytokens[0]
	if h.ScenarioID == nil || *h.ScenarioID != sc.ID || h.Name != "Zugang" || h.Type != honeytoken.TypeDNS ||
		h.Severity != slot.Severity || !slices.Equal(h.Techniques, slot.Techniques) || !h.Enabled {
		t.Errorf("honeytoken = %+v, want the slot %+v in the scenario", h, slot)
	}
	if applied.Honeytokens[1].Name != "Bild" || applied.Honeytokens[1].Severity != honeytoken.TypeWebImage.DefaultSeverity() {
		t.Errorf("second honeytoken = %+v", applied.Honeytokens[1])
	}
	p := applied.Honeypots[0]
	if p.ScenarioID == nil || *p.ScenarioID != sc.ID || p.Name != "Sprungserver" || p.Service != honeypot.ServiceSSH || !p.Enabled {
		t.Errorf("honeypot = %+v, want the slot in the scenario", p)
	}

	// The honeypot has a secret that its sensor can be configured with.
	read, err := honeypot.NewStore(d.console, a.Keys).Secret(t.Context(), p.ID)
	if err != nil || read.Secret == "" {
		t.Errorf("Secret() error = %v, want the secret of the new honeypot", err)
	}

	// The scenario is created first, then everything that joins it, each
	// with the field of its scenario.
	want := []entry{
		{"scenario.create", "scenario", sc.ID, []string{}, actor.UserID},
		{"honeytoken.create", "honeytoken", h.ID, []string{"scenario_id"}, actor.UserID},
		{"honeytoken.create", "honeytoken", applied.Honeytokens[1].ID, []string{"scenario_id"}, actor.UserID},
		{"honeypot.create", "honeypot", p.ID, []string{"scenario_id"}, actor.UserID},
	}
	if got := entries(t, d); !sameEntries(got, want) {
		t.Errorf("audit entries = %+v, want %+v", got, want)
	}
	if secretEntries := count(t, d, `SELECT count(*) FROM audit_entries WHERE changed_fields::text ILIKE '%secret%'`); secretEntries != 0 {
		t.Errorf("%d audit entries name a secret", secretEntries)
	}
}

// Every deception of the embedded catalog can be applied with its resources in
// both languages: its labels are valid names, and its slots are what the
// stores create.
func TestApply_EveryDeceptionOfTheCatalogWithItsResources(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c, err := catalog.Load(embedded.FS())
	if err != nil {
		t.Fatal(err)
	}
	keys := secretboxtest.Keyring(t)

	for _, dec := range c.Deceptions() {
		for _, lang := range catalog.Languages {
			a := scenario.Application{
				Join: scenario.Join{Deception: dec, Language: lang, CreateResources: true, DNSConfigured: true, Keys: keys},
				Name: dec.ID,
			}
			applied, err := scenario.Apply(t.Context(), d.console, actor, a)
			if err != nil {
				t.Errorf("%s in %s: Apply() error = %v", dec.ID, lang, err)
				continue
			}
			if len(applied.Honeytokens) != len(dec.Honeytokens) || len(applied.Honeypots) != len(dec.Honeypots) {
				t.Errorf("%s in %s: created %d and %d resources, want %d and %d", dec.ID, lang,
					len(applied.Honeytokens), len(applied.Honeypots), len(dec.Honeytokens), len(dec.Honeypots))
			}
			for i, h := range applied.Honeytokens {
				if h.Name != dec.Honeytokens[i].Label[lang] {
					t.Errorf("%s in %s: honeytoken %d is named %q, want %q", dec.ID, lang, i, h.Name, dec.Honeytokens[i].Label[lang])
				}
			}
		}
	}
}

// Applying is atomic: a resource that cannot be stored, and an audit entry
// that cannot be written, leave nothing behind, also the scenario.
func TestApply_IsAtomic(t *testing.T) {
	t.Parallel()
	c := testCatalog(t)

	t.Run("honeypot", func(t *testing.T) {
		t.Parallel()
		d := newTestDB(t)
		// The last write of an application fails.
		for _, statement := range []string{
			`CREATE FUNCTION fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$`,
			`CREATE TRIGGER fail BEFORE INSERT ON honeypots FOR EACH ROW EXECUTE FUNCTION fail()`,
		} {
			if _, err := d.owner.Exec(t.Context(), statement); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := scenario.Apply(t.Context(), d.console, createUser(t, d), application(t, c, "ssh", true)); err == nil || !strings.Contains(err.Error(), "injected") {
			t.Errorf("Apply() error = %v, want the injected failure", err)
		}
		assertNothingStored(t, d, "honeypot")
	})

	t.Run("deception", func(t *testing.T) {
		t.Parallel()
		d := newTestDB(t)
		// The assignment of the deception is written last.
		for _, statement := range []string{
			`CREATE FUNCTION fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$`,
			`CREATE TRIGGER fail BEFORE INSERT ON scenario_deceptions FOR EACH ROW EXECUTE FUNCTION fail()`,
		} {
			if _, err := d.owner.Exec(t.Context(), statement); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := scenario.Apply(t.Context(), d.console, createUser(t, d), application(t, c, "ssh", true)); err == nil || !strings.Contains(err.Error(), "injected") {
			t.Errorf("Apply() error = %v, want the injected failure", err)
		}
		assertNothingStored(t, d, "deception")
	})

	t.Run("audit", func(t *testing.T) {
		t.Parallel()
		d := newTestDB(t)
		// An actor without an account fails the check of the audit log.
		ghost := audit.Actor{Kind: audit.ActorUser, Method: audit.AuthSession, UserID: "00000000-0000-4000-8000-000000000000"}
		for _, create := range []bool{false, true} {
			if _, err := scenario.Apply(t.Context(), d.console, ghost, application(t, c, "ssh", create)); err == nil {
				t.Errorf("Apply(create %v) without audit entry succeeded", create)
			}
			assertNothingStored(t, d, "audit")
		}
	})
}

// Every value of an application is validated before anything is written.
func TestApply_ValidatesBeforeWriting(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)

	tests := []struct {
		name   string
		mutate func(*scenario.Application)
		want   error
	}{
		{"empty name", func(a *scenario.Application) { a.Name = "" }, scenario.ErrInvalidName},
		{"name with a line break", func(a *scenario.Application) { a.Name = "a\nb" }, scenario.ErrInvalidName},
		{"notes with an escape", func(a *scenario.Application) { a.Notes = "a\x1bb" }, scenario.ErrInvalidNotes},
		{"unknown language", func(a *scenario.Application) { a.Language = "fr" }, scenario.ErrInvalidLanguage},
		{"DNS honeytoken without a zone", func(a *scenario.Application) { a.DNSConfigured = false }, scenario.ErrDNSNotConfigured},
	}
	for _, tt := range tests {
		a := application(t, c, "ssh", true)
		tt.mutate(&a)
		if _, err := scenario.Apply(t.Context(), d.console, actor, a); !errors.Is(err, tt.want) {
			t.Errorf("%s: Apply() error = %v, want %v", tt.name, err, tt.want)
		}
	}
	assertNothingStored(t, d, "validation")

	// Without the resources, nothing needs a zone: the deception only joins.
	a := application(t, c, "ssh", false)
	a.DNSConfigured = false
	if _, err := scenario.Apply(t.Context(), d.console, actor, a); err != nil {
		t.Errorf("Apply() without resources and without a zone error = %v, want none", err)
	}
	// A deception without a DNS honeytoken needs no zone for its resources.
	a = application(t, c, "rdp", true)
	a.DNSConfigured = false
	if _, err := scenario.Apply(t.Context(), d.console, actor, a); err != nil {
		t.Errorf("Apply() of a deception without DNS honeytoken, without a zone: error = %v, want none", err)
	}
}

func addition(t *testing.T, c *catalog.Catalog, scenarioID, deceptionID string, create bool) scenario.Addition {
	t.Helper()
	return scenario.Addition{ScenarioID: scenarioID, Join: join(t, c, deceptionID, create)}
}

// Adding a deception to a scenario adds its identifier and its activities, up
// to the limit of the scenario, and creates the resources in the scenario when
// asked; it records the change of the scenario and each resource.
func TestAddDeception_JoinsTheScenario(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s", EngageActivities: []string{"EAC0012"}})

	applied, err := scenario.AddDeception(t.Context(), d.console, actor, addition(t, c, sc.ID, "rdp", true))
	if err != nil {
		t.Fatalf("AddDeception() error = %v", err)
	}
	got := applied.Scenario
	if len(got.Deceptions) != 1 || got.Deceptions[0].DeceptionID != "rdp" ||
		!slices.Equal(got.EngageActivities, []string{"EAC0012", "EAC0005", "EAC0011"}) || !got.UpdatedAt.After(sc.UpdatedAt) {
		t.Errorf("scenario = %+v, want rdp and the activities after those of the scenario", got)
	}
	if len(applied.Honeytokens) != 1 || len(applied.Honeypots) != 1 ||
		applied.Honeytokens[0].ScenarioID == nil || *applied.Honeytokens[0].ScenarioID != sc.ID ||
		applied.Honeypots[0].ScenarioID == nil || *applied.Honeypots[0].ScenarioID != sc.ID {
		t.Errorf("applied = %+v, want a honeytoken and a honeypot in the scenario", applied)
	}
	want := []entry{
		{"honeytoken.create", "honeytoken", applied.Honeytokens[0].ID, []string{"scenario_id"}, actor.UserID},
		{"honeypot.create", "honeypot", applied.Honeypots[0].ID, []string{"scenario_id"}, actor.UserID},
		{"scenario.update", "scenario", sc.ID, []string{"deceptions", "engage_activities"}, actor.UserID},
	}
	if got := entries(t, d); !sameEntries(got, want) {
		t.Errorf("audit entries = %+v, want %+v", got, want)
	}

	// A second deception whose activities the scenario has changes only its
	// deceptions.
	if _, err := scenario.AddDeception(t.Context(), d.console, actor, addition(t, c, sc.ID, "hint", false)); err != nil {
		t.Fatal(err)
	}
	last := entries(t, d)[len(entries(t, d))-1]
	if !slices.Equal(last.ChangedFields, []string{"deceptions"}) {
		t.Errorf("the second addition records %v, want only deceptions", last.ChangedFields)
	}
}

// A deception joins a scenario once, and a repeat creates nothing.
func TestAddDeception_JoinsOnce(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})

	if _, err := scenario.AddDeception(t.Context(), d.console, actor, addition(t, c, sc.ID, "ssh", true)); err != nil {
		t.Fatal(err)
	}
	before := count(t, d, `SELECT (SELECT count(*) FROM honeytokens) + (SELECT count(*) FROM honeypots) + (SELECT count(*) FROM audit_entries)`)
	if _, err := scenario.AddDeception(t.Context(), d.console, actor, addition(t, c, sc.ID, "ssh", true)); !errors.Is(err, scenario.ErrDeceptionAdded) {
		t.Errorf("a repeat: error = %v, want ErrDeceptionAdded", err)
	}
	if after := count(t, d, `SELECT (SELECT count(*) FROM honeytokens) + (SELECT count(*) FROM honeypots) + (SELECT count(*) FROM audit_entries)`); after != before {
		t.Errorf("a repeat left %d rows, want the %d before", after, before)
	}
}

// The activities of a scenario stop at the limit of the schema, and a deception
// whose activities do not fit still joins.
func TestAddDeception_StopsAddingActivitiesAtTheLimit(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	// 19 activities that are neither of rdp and the first of rdp: the second
	// of rdp does not fit.
	others := slices.DeleteFunc(engageIDs(t), func(id string) bool { return id == "EAC0005" || id == "EAC0011" })
	sc := create(t, d, scenario.Spec{Name: "s", EngageActivities: append(slices.Clone(others[:scenario.MaxEngageActivities-1]), "EAC0005")})

	applied, err := scenario.AddDeception(t.Context(), d.console, actor, addition(t, c, sc.ID, "rdp", false))
	if err != nil {
		t.Fatalf("AddDeception() error = %v", err)
	}
	if len(applied.Scenario.EngageActivities) != scenario.MaxEngageActivities || slices.Contains(applied.Scenario.EngageActivities, "EAC0011") ||
		len(applied.Scenario.Deceptions) != 1 {
		t.Errorf("scenario = %+v, want the full list without EAC0011 and the deception", applied.Scenario)
	}
}

// Adding to a scenario that does not exist creates nothing, and neither does
// a deception that fails.
func TestAddDeception_IsAtomicAndNeedsAScenario(t *testing.T) {
	t.Parallel()
	c := testCatalog(t)

	t.Run("unknown scenario", func(t *testing.T) {
		t.Parallel()
		d := newTestDB(t)
		actor := createUser(t, d)
		for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
			if _, err := scenario.AddDeception(t.Context(), d.console, actor, addition(t, c, id, "ssh", true)); !errors.Is(err, scenario.ErrNotFound) {
				t.Errorf("AddDeception(%s) error = %v, want ErrNotFound", id, err)
			}
		}
		for _, table := range []string{"scenario_deceptions", "honeytokens", "honeypots"} {
			if n := count(t, d, `SELECT count(*) FROM `+table); n != 0 {
				t.Errorf("%d rows in %s, want none", n, table)
			}
		}
	})

	t.Run("audit", func(t *testing.T) {
		t.Parallel()
		d := newTestDB(t)
		sc := create(t, d, scenario.Spec{Name: "s"})
		ghost := audit.Actor{Kind: audit.ActorUser, Method: audit.AuthSession, UserID: "00000000-0000-4000-8000-000000000000"}
		if _, err := scenario.AddDeception(t.Context(), d.console, ghost, addition(t, c, sc.ID, "ssh", true)); err == nil {
			t.Fatal("AddDeception() without audit entry succeeded")
		}
		got, err := scenario.NewStore(d.console).Get(t.Context(), sc.ID)
		if err != nil || len(got.Deceptions) != 0 || len(got.EngageActivities) != 0 || !got.UpdatedAt.Equal(sc.UpdatedAt) {
			t.Errorf("Get() = %+v, %v; want the scenario as it was", got, err)
		}
		for _, table := range []string{"honeytokens", "honeypots"} {
			if n := count(t, d, `SELECT count(*) FROM `+table); n != 0 {
				t.Errorf("%d rows in %s, want none", n, table)
			}
		}
	})

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		d := newTestDB(t)
		actor := createUser(t, d)
		sc := create(t, d, scenario.Spec{Name: "s"})
		a := addition(t, c, sc.ID, "ssh", true)
		a.Language = "fr"
		if _, err := scenario.AddDeception(t.Context(), d.console, actor, a); !errors.Is(err, scenario.ErrInvalidLanguage) {
			t.Errorf("AddDeception() error = %v, want ErrInvalidLanguage", err)
		}
		a = addition(t, c, sc.ID, "ssh", true)
		a.DNSConfigured = false
		if _, err := scenario.AddDeception(t.Context(), d.console, actor, a); !errors.Is(err, scenario.ErrDNSNotConfigured) {
			t.Errorf("AddDeception() error = %v, want ErrDNSNotConfigured", err)
		}
		if n := count(t, d, `SELECT count(*) FROM audit_entries`); n != 0 {
			t.Errorf("%d audit entries, want none", n)
		}
	})
}

// Removing a deception ends the assignment and nothing else: the resources
// that were created for it stay in the scenario, and so do the activities, and
// the deception can be added again.
func TestRemoveDeception_EndsTheAssignmentOnly(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	applied, err := scenario.AddDeception(t.Context(), d.console, actor, addition(t, c, sc.ID, "ssh", true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scenario.AddDeception(t.Context(), d.console, actor, addition(t, c, sc.ID, "hint", false)); err != nil {
		t.Fatal(err)
	}
	before := len(entries(t, d))
	held, err := scenario.NewStore(d.console).Get(t.Context(), sc.ID)
	if err != nil {
		t.Fatal(err)
	}

	got, err := scenario.RemoveDeception(t.Context(), d.console, actor, sc.ID, "ssh")
	if err != nil {
		t.Fatalf("RemoveDeception() error = %v", err)
	}
	if len(got.Deceptions) != 1 || got.Deceptions[0].DeceptionID != "hint" ||
		!slices.Equal(got.EngageActivities, held.EngageActivities) || len(held.EngageActivities) == 0 {
		t.Errorf("scenario = %+v, want only hint and the activities kept", got)
	}
	for _, h := range applied.Honeytokens {
		if s, ok := scenarioOf(t, d, h.ID); !ok || s != sc.ID {
			t.Errorf("honeytoken in %q, exists %v; want it kept in the scenario", s, ok)
		}
	}
	if s, ok := honeypotScenarioOf(t, d, applied.Honeypots[0].ID); !ok || s != sc.ID {
		t.Errorf("honeypot in %q, exists %v; want it kept in the scenario", s, ok)
	}
	all := entries(t, d)
	if len(all) != before+1 || !sameEntries(all[before:], []entry{{"scenario.update", "scenario", sc.ID, []string{"deceptions"}, actor.UserID}}) {
		t.Errorf("audit entries = %+v, want one more: scenario.update of the field deceptions", all)
	}

	if _, err := scenario.RemoveDeception(t.Context(), d.console, actor, sc.ID, "ssh"); !errors.Is(err, scenario.ErrDeceptionNotAdded) {
		t.Errorf("removing it twice: error = %v, want ErrDeceptionNotAdded", err)
	}
	if _, err := scenario.RemoveDeception(t.Context(), d.console, actor, "00000000-0000-4000-8000-000000000000", "ssh"); !errors.Is(err, scenario.ErrNotFound) {
		t.Errorf("unknown scenario: error = %v, want ErrNotFound", err)
	}
	if _, err := scenario.AddDeception(t.Context(), d.console, actor, addition(t, c, sc.ID, "ssh", false)); err != nil {
		t.Errorf("adding it again: error = %v", err)
	}
}

// A deception that the catalog does not know any more can be removed: the
// assignment is a row of the scenario, not of the catalog.
func TestRemoveDeception_AcceptsADeceptionThatTheCatalogLost(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	sc := create(t, d, scenario.Spec{Name: "s"})
	if _, err := d.owner.Exec(t.Context(), `INSERT INTO scenario_deceptions (scenario_id, deception_id) VALUES ($1, 'retired')`, sc.ID); err != nil {
		t.Fatal(err)
	}
	got, err := scenario.NewStore(d.console).Get(t.Context(), sc.ID)
	if err != nil || len(got.Deceptions) != 1 || got.Deceptions[0].DeceptionID != "retired" {
		t.Fatalf("Get() = %+v, %v; want the deception that the catalog lacks", got, err)
	}
	if got, err = scenario.RemoveDeception(t.Context(), d.console, actor, sc.ID, "retired"); err != nil || len(got.Deceptions) != 0 {
		t.Errorf("RemoveDeception() = %+v, %v; want it removed", got, err)
	}
}

// Deleting a scenario removes its deceptions with it.
func TestDelete_RemovesTheDeceptionsOfTheScenario(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c := testCatalog(t)
	sc := create(t, d, scenario.Spec{Name: "s"})
	if _, err := scenario.AddDeception(t.Context(), d.console, actor, addition(t, c, sc.ID, "hint", false)); err != nil {
		t.Fatal(err)
	}
	keep := scenario.ResourceRemovals{Honeytokens: scenario.RemovalKeep, Honeypots: scenario.RemovalKeep}
	if _, err := scenario.Delete(t.Context(), d.console, actor, sc.ID, keep); err != nil {
		t.Fatal(err)
	}
	if n := count(t, d, `SELECT count(*) FROM scenario_deceptions`); n != 0 {
		t.Errorf("%d deceptions left, want none", n)
	}
}
