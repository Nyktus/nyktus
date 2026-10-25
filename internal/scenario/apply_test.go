// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package scenario_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	embedded "nyktus.org/nyktus/catalog"
	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/catalog"
	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/scenario"
	"nyktus.org/nyktus/internal/severity"
)

const (
	triggerURL = "https://t.example.net"
	dnsZone    = "d.example.net"
)

func deception(t *testing.T, id string) catalog.Deception {
	t.Helper()
	c, err := catalog.Load(embedded.FS())
	if err != nil {
		t.Fatal(err)
	}
	d, ok := c.Lookup(id)
	if !ok {
		t.Fatalf("no deception %s", id)
	}
	return d
}

// examples returns the persona of d with the example of each value.
func examples(d catalog.Deception) map[string]string {
	persona := map[string]string{}
	for _, p := range d.Persona {
		persona[p.Key] = p.Example
	}
	return persona
}

func application(d catalog.Deception) scenario.Application {
	return scenario.Application{
		Join: scenario.Join{
			Deception: d, Language: "de", Persona: examples(d), TriggerURL: triggerURL, DNSZone: dnsZone,
		},
		Name: "Jump server", Notes: "admin workstation",
	}
}

func count(t *testing.T, d testDB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := d.owner.QueryRow(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// Applying a deception creates a scenario with its honeytokens, in the
// scenario, with the label of the language as name and the severity of the
// deception, its artifacts rendered with the names of those honeytokens, and
// its guide, and records each of them.
func TestApply_CreatesTheScenarioWithItsResources(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	dec := deception(t, "netrc")

	applied, err := scenario.Apply(t.Context(), d.console, actor, application(dec))
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	sc := applied.Scenario
	if sc.Name != "Jump server" || sc.Notes != "admin workstation" || len(sc.Deceptions) != 1 ||
		sc.Deceptions[0].DeceptionID != "netrc" || sc.Deceptions[0].Language != "de" ||
		!slices.Equal(sc.EngageActivities, []string{"EAC0005", "EAC0012"}) ||
		len(sc.Persona) != len(dec.Persona) || sc.Persona["Account"] != examples(dec)["Account"] {
		t.Errorf("scenario = %+v", sc)
	}

	if len(applied.Honeytokens) != len(dec.Honeytokens) {
		t.Fatalf("%d honeytokens, want %d", len(applied.Honeytokens), len(dec.Honeytokens))
	}
	h := applied.Honeytokens[0]
	slot := dec.Honeytokens[0]
	if h.ScenarioID == nil || *h.ScenarioID != sc.ID || h.Name != slot.Label["de"] || h.Type != slot.Type ||
		h.Severity != severity.High || !slices.Equal(h.Techniques, slot.Techniques) || !h.Enabled {
		t.Errorf("honeytoken = %+v, want the slot %+v in the scenario", h, slot)
	}

	name := h.TriggerValue + "." + dnsZone
	if len(applied.Artifacts) != len(dec.Artifacts) {
		t.Fatalf("%d artifacts, want %d", len(applied.Artifacts), len(dec.Artifacts))
	}
	for i, a := range applied.Artifacts {
		if a.ScenarioID == nil || *a.ScenarioID != sc.ID || a.FileName != dec.Artifacts[i].FileName ||
			a.Format != dec.Artifacts[i].Format || a.Size == 0 || a.PlacementNotes != "" {
			t.Errorf("artifact = %+v", a)
		}
		var content string
		if err := d.owner.QueryRow(t.Context(), `SELECT convert_from(content, 'UTF8') FROM artifacts WHERE id = $1`, a.ID).Scan(&content); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(content, name) || len(content) != a.Size {
			t.Errorf("artifact %s = %q, want the name %s", a.FileName, content, name)
		}
	}

	guides, err := scenario.NewStore(d.console).Guides(t.Context(), sc.ID)
	if err != nil || len(guides) != 1 || guides[0].DeceptionID != "netrc" || guides[0].Language != "de" ||
		!strings.Contains(guides[0].Content, name) || !strings.Contains(guides[0].Content, "## ") {
		t.Errorf("Guides() = %+v, %v; want the German guide with %s", guides, err, name)
	}

	// The scenario is created first, then everything that joins it.
	want := []entry{
		{"scenario.create", "scenario", sc.ID, []string{}, actor.UserID},
		{"honeytoken.create", "honeytoken", h.ID, []string{}, actor.UserID},
	}
	for _, a := range applied.Artifacts {
		want = append(want, entry{"artifact.create", "artifact", a.ID, []string{}, actor.UserID})
	}
	if got := entries(t, d); !sameEntries(got, want) {
		t.Errorf("audit entries = %+v, want %+v", got, want)
	}
}

// A URL honeytoken is placed with the address of the trigger, an image with
// its .gif.
func TestApply_PlacesTheURLsOfTheTrigger(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)

	applied, err := scenario.Apply(t.Context(), d.console, createUser(t, d), application(deception(t, "browser-bookmarks")))
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	h := applied.Honeytokens[0]
	var content string
	if err := d.owner.QueryRow(t.Context(), `SELECT convert_from(content, 'UTF8') FROM artifacts WHERE scenario_id = $1`, applied.Scenario.ID).Scan(&content); err != nil {
		t.Fatal(err)
	}
	if want := triggerURL + h.TriggerPath(); h.Type != honeytoken.TypeWebURL || !strings.Contains(content, want) {
		t.Errorf("bookmarks = %q, want the URL %s", content, want)
	}
}

// Every deception of the catalog applies in every language, and none of its
// artifacts names the product or what it is.
func TestApply_EveryDeceptionInEveryLanguage(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	c, err := catalog.Load(embedded.FS())
	if err != nil {
		t.Fatal(err)
	}

	for _, dec := range c.Deceptions() {
		for _, lang := range catalog.Languages {
			a := application(dec)
			a.Language = lang
			applied, err := scenario.Apply(t.Context(), d.console, actor, a)
			if err != nil {
				t.Errorf("%s in %s: Apply() error = %v", dec.ID, lang, err)
				continue
			}
			// The artifacts are those that the deception recommends, in order.
			if len(applied.Artifacts) != len(dec.Artifacts) {
				t.Errorf("%s in %s: %d artifacts, want %d", dec.ID, lang, len(applied.Artifacts), len(dec.Artifacts))
				continue
			}
			for i, art := range applied.Artifacts {
				want := dec.Artifacts[i]
				if art.CatalogArtifact != want.ID || art.FileName != want.FileName || art.Format != want.Format {
					t.Errorf("%s in %s: artifact %d is %s (%s, %s), want %s (%s, %s)", dec.ID, lang, i,
						art.CatalogArtifact, art.FileName, art.Format, want.ID, want.FileName, want.Format)
				}
				var content []byte
				if err := d.owner.QueryRow(t.Context(), `SELECT content FROM artifacts WHERE id = $1`, art.ID).Scan(&content); err != nil {
					t.Fatal(err)
				}
				if m := want.Reveals(content, dec.ID); m != "" {
					t.Errorf("%s in %s: %s contains %q", dec.ID, lang, art.FileName, m)
				}
			}
		}
	}
}

// assertNothingStored fails the test if anything of an application remains.
func assertNothingStored(t *testing.T, d testDB, name string) {
	t.Helper()
	for _, table := range []string{"scenarios", "scenario_deceptions", "honeytokens", "artifacts", "audit_entries"} {
		if n := count(t, d, `SELECT count(*) FROM `+table); n != 0 {
			t.Errorf("%s: %d rows in %s, want none", name, n, table)
		}
	}
}

// Applying is atomic: a value that makes an artifact reveal what it is, a
// resource that cannot be stored, or an audit entry that cannot be written
// leaves nothing behind.
func TestApply_IsAtomic(t *testing.T) {
	t.Parallel()
	dec := deception(t, "ssh-config")

	t.Run("render", func(t *testing.T) {
		t.Parallel()
		d := newTestDB(t)
		a := application(dec)
		// A zone that names what the honeytoken is reaches the artifact.
		a.DNSZone = "canary.example.net"
		_, err := scenario.Apply(t.Context(), d.console, createUser(t, d), a)
		var re *catalog.RevealError
		if !errors.As(err, &re) || re.Artifact != "ssh-config" || re.Marker != "canary" {
			t.Errorf("Apply() error = %v, want a RevealError of ssh-config", err)
		}
		assertNothingStored(t, d, "render")
	})

	t.Run("resource", func(t *testing.T) {
		t.Parallel()
		d := newTestDB(t)
		// The last write of an application fails.
		for _, statement := range []string{
			`CREATE FUNCTION fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$`,
			`CREATE TRIGGER fail BEFORE INSERT ON artifacts FOR EACH ROW EXECUTE FUNCTION fail()`,
		} {
			if _, err := d.owner.Exec(t.Context(), statement); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := scenario.Apply(t.Context(), d.console, createUser(t, d), application(dec)); err == nil || !strings.Contains(err.Error(), "injected") {
			t.Errorf("Apply() error = %v, want the injected failure", err)
		}
		assertNothingStored(t, d, "resource")
	})

	t.Run("audit", func(t *testing.T) {
		t.Parallel()
		d := newTestDB(t)
		// An actor without an account fails the check of the audit log.
		ghost := audit.Actor{Kind: audit.ActorUser, Method: audit.AuthSession, UserID: "00000000-0000-4000-8000-000000000000"}
		if _, err := scenario.Apply(t.Context(), d.console, ghost, application(dec)); err == nil {
			t.Error("Apply() without audit entry succeeded")
		}
		assertNothingStored(t, d, "audit")
	})
}

// Every value of an application is validated before anything is written.
func TestApply_ValidatesBeforeWriting(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	actor := createUser(t, d)
	dec := deception(t, "ssh-config")

	for _, tt := range []struct {
		name   string
		change func(*scenario.Application)
		want   error
	}{
		{"name", func(a *scenario.Application) { a.Name = " " }, scenario.ErrInvalidName},
		{"notes", func(a *scenario.Application) { a.Notes = "\x00" }, scenario.ErrInvalidNotes},
		{"language", func(a *scenario.Application) { a.Language = "fr" }, scenario.ErrInvalidLanguage},
		{"persona", func(a *scenario.Application) { a.Persona = map[string]string{"Domain": "corp.example.com"} }, catalog.ErrInvalidPersona},
		{"no zone", func(a *scenario.Application) { a.DNSZone = "" }, scenario.ErrDNSNotConfigured},
	} {
		a := application(dec)
		tt.change(&a)
		if _, err := scenario.Apply(t.Context(), d.console, actor, a); !errors.Is(err, tt.want) {
			t.Errorf("%s: Apply() error = %v, want %v", tt.name, err, tt.want)
		}
	}
	assertNothingStored(t, d, "validation")
	// Without a DNS honeytoken, no zone is needed.
	a := application(deception(t, "browser-bookmarks"))
	a.DNSZone = ""
	if _, err := scenario.Apply(t.Context(), d.console, actor, a); err != nil {
		t.Errorf("Apply(URL deception without zone) error = %v", err)
	}
}

// A scenario put together by hand holds no deception, so it has no guides and
// an empty persona.
func TestStore_Guides_OfAScenarioByHand(t *testing.T) {
	t.Parallel()
	d := newTestDB(t)
	sc := create(t, d, scenario.Spec{Name: "s"})

	guides, err := scenario.NewStore(d.console).Guides(t.Context(), sc.ID)
	if err != nil || guides == nil || len(guides) != 0 {
		t.Errorf("Guides(by hand) = %v, %v; want an empty list", guides, err)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if _, err := scenario.NewStore(d.console).Guides(t.Context(), id); !errors.Is(err, scenario.ErrNotFound) {
			t.Errorf("Guides(%q) error = %v, want ErrNotFound", id, err)
		}
	}
	got, err := scenario.NewStore(d.console).Get(t.Context(), sc.ID)
	if err != nil || got.Deceptions == nil || len(got.Deceptions) != 0 || got.Persona == nil || len(got.Persona) != 0 {
		t.Errorf("Get(by hand) = %+v, %v; want no deceptions and an empty persona", got, err)
	}
}
