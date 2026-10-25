// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"nyktus.org/nyktus/internal/severity"
)

func loaded(t *testing.T, fsys fstest.MapFS) *Catalog {
	t.Helper()
	c, err := Load(fsys)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return c
}

func sample(t *testing.T, fsys fstest.MapFS) Deception {
	t.Helper()
	d, _ := loaded(t, fsys).Lookup("sample")
	return d
}

func artifactOf(t *testing.T, fsys fstest.MapFS, id string) Artifact {
	t.Helper()
	a, ok := loaded(t, fsys).LookupArtifact(id)
	if !ok {
		t.Fatalf("the catalog has no artifact %s", id)
	}
	return a
}

// A honeytoken of a deception has the severity that the deception chooses,
// or the default of its type.
func TestLoad_SetsTheSeverityOfEachHoneytoken(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	edit(t, sampleJSON, `"techniques": []}`, `"techniques": [], "severity": "high"}`)(fsys)
	d := sample(t, fsys)
	if d.Honeytokens[0].Severity != severity.Medium || d.Honeytokens[1].Severity != severity.High {
		t.Errorf("severities %s, %s; want the default medium of dns and the chosen high", d.Honeytokens[0].Severity, d.Honeytokens[1].Severity)
	}
}

// The persona holds exactly the values of the deception or the artifact, each
// of its kind and none empty; the error names the key but never the value.
func TestValidatePersona(t *testing.T) {
	t.Parallel()
	d := sample(t, validFiles())
	a := artifactOf(t, validFiles(), "note")

	valid := map[string]string{"Domain": "corp.example.com", "Company": "Example Ltd"}
	if err := d.ValidatePersona(valid); err != nil {
		t.Fatalf("Deception.ValidatePersona(valid) = %v", err)
	}
	if err := a.ValidatePersona(valid); err != nil {
		t.Fatalf("Artifact.ValidatePersona(valid) = %v", err)
	}
	with := func(k, v string) map[string]string {
		p := map[string]string{"Domain": valid["Domain"], "Company": valid["Company"]}
		if v == "-" {
			delete(p, k)
		} else {
			p[k] = v
		}
		return p
	}
	for _, tt := range []struct {
		name    string
		persona map[string]string
		key     string
	}{
		{"missing", with("Domain", "-"), "Domain"},
		{"empty", with("Company", ""), "Company"},
		{"host in upper case", with("Domain", "Corp.Example.com"), "Domain"},
		{"host with a space", with("Domain", "corp example.com"), "Domain"},
		{"text with a line break", with("Company", "Example\nLtd"), "Company"},
		{"text too long", with("Company", strings.Repeat("a", MaxTextLength+1)), "Company"},
		{"unknown key", with("Zone", "x"), "Zone"},
		{"malformed unknown key", with("<b>x</b>", "x"), "with a malformed key"},
	} {
		for owner, validate := range map[string]func(map[string]string) error{"deception": d.ValidatePersona, "artifact": a.ValidatePersona} {
			err := validate(tt.persona)
			var pe *PersonaError
			if !errors.Is(err, ErrInvalidPersona) || !errors.As(err, &pe) || pe.Key != tt.key {
				t.Errorf("%s %s: ValidatePersona() = %v, want a PersonaError for %s", owner, tt.name, err, tt.key)
				continue
			}
			for _, v := range tt.persona {
				if v != "" && strings.Contains(err.Error(), v) {
					t.Errorf("%s %s: the error %q contains the value %q", owner, tt.name, err, v)
				}
			}
		}
	}
}

// Secrets have the length of their declaration, consist of letters and
// digits, and differ between applications.
func TestArtifact_NewSecrets(t *testing.T) {
	t.Parallel()
	a := artifactOf(t, validFiles(), "config")

	format := regexp.MustCompile(`^[A-Za-z0-9]{16}$`)
	seen := map[string]bool{}
	letters := map[byte]bool{}
	for range 200 {
		s := a.NewSecrets()
		if len(s) != 1 || !format.MatchString(s["Password"]) || seen[s["Password"]] {
			t.Fatalf("NewSecrets() = %v, want a new password of 16 letters and digits", s)
		}
		seen[s["Password"]] = true
		for i := range len(s["Password"]) {
			letters[s["Password"][i]] = true
		}
	}
	// 3200 characters from an alphabet of 62 cover all of it.
	if len(letters) != len(secretAlphabet) {
		t.Errorf("the secrets use %d of %d characters", len(letters), len(secretAlphabet))
	}
}

// A deception generates the secrets of its artifacts, each artifact its own.
func TestDeception_NewSecrets(t *testing.T) {
	t.Parallel()
	d := sample(t, validFiles())

	s := d.NewSecrets()
	if len(s) != 1 || len(s["config"]["Password"]) != 16 {
		t.Errorf("NewSecrets() = %v, want a password for config only", s)
	}
}

func placedGateway(gateway string) map[string]Placed {
	return map[string]Placed{"Gateway": {Host: gateway}, "Link": {URL: "https://t.example.net/q3xwz7a2kfm4ub6tyc5nre2lpa"}}
}

var (
	secretsOfSample = map[string]map[string]string{"config": {"Password": "Xy7Xy7Xy7Xy7Xy7X"}}
	personaOfSample = func(company string) map[string]string {
		return map[string]string{"Domain": "corp.example.com", "Company": company}
	}
)

func TestDeception_Render(t *testing.T) {
	t.Parallel()
	d := sample(t, validFiles())

	r, err := d.Render(placedGateway("q3xwz7a2kfm4ub6tyc5nre2lpa.d.example.net"), personaOfSample("Example Ltd"), secretsOfSample, "de")
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if len(r.Artifacts) != 2 || r.Artifacts[0].ID != "config" || r.Artifacts[1].FileName != "Read me.txt" ||
		string(r.Artifacts[0].Content) != "Host q3xwz7a2kfm4ub6tyc5nre2lpa.d.example.net\nPassword Xy7Xy7Xy7Xy7Xy7X\n" ||
		string(r.Artifacts[1].Content) != "Example Ltd: https://t.example.net/q3xwz7a2kfm4ub6tyc5nre2lpa on corp.example.com\r\n" {
		t.Errorf("Render() artifacts = %+v", r.Artifacts)
	}
	if string(r.Guide) != "Legen Sie den Honeytoken q3xwz7a2kfm4ub6tyc5nre2lpa.d.example.net ab.\n" {
		t.Errorf("Render() guide = %q, want the German guide", r.Guide)
	}
	if _, err := d.Render(placedGateway("a.d.example.net"), personaOfSample("Example Ltd"), secretsOfSample, "fr"); !errors.Is(err, ErrUnknownLanguage) {
		t.Errorf("Render(fr) error = %v, want ErrUnknownLanguage", err)
	}
}

// A slot without a honeytoken is empty if the artifact allows it: the note
// becomes pocket litter. A required slot, a missing value of the persona and a
// missing secret fail instead of rendering as nothing.
func TestDeception_Render_FillsSlotsAndRefusesMissingValues(t *testing.T) {
	t.Parallel()
	d := sample(t, validFiles())
	gateway := Placed{Host: "a.d.example.net"}

	r, err := d.Render(map[string]Placed{"Gateway": gateway}, personaOfSample("Example Ltd"), secretsOfSample, "en")
	if err != nil || string(r.Artifacts[1].Content) != "Example Ltd on corp.example.com\r\n" {
		t.Errorf("Render(without the link) = %+v, %v, want the note without a link", r.Artifacts, err)
	}

	for name, c := range map[string]struct {
		placed  map[string]Placed
		persona map[string]string
		secrets map[string]map[string]string
	}{
		"required slot":          {map[string]Placed{"Link": {URL: "https://t.example.net/x"}}, personaOfSample("A"), secretsOfSample},
		"required slot is empty": {map[string]Placed{"Gateway": {URL: "https://t.example.net/x"}}, personaOfSample("A"), secretsOfSample},
		"persona":                {map[string]Placed{"Gateway": gateway}, map[string]string{"Domain": "corp.example.com"}, secretsOfSample},
		"persona is empty":       {map[string]Placed{"Gateway": gateway}, personaOfSample(""), secretsOfSample},
		"secret":                 {map[string]Placed{"Gateway": gateway}, personaOfSample("A"), nil},
		"secret is empty":        {map[string]Placed{"Gateway": gateway}, personaOfSample("A"), map[string]map[string]string{"config": {"Password": ""}}},
	} {
		if _, err := d.Render(c.placed, c.persona, c.secrets, "en"); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%s: Render() error = %v, want ErrInvalidValue", name, err)
		}
	}
}

// Values that the catalog does not control, such as the persona and the zone
// of the DNS role, can reveal an artifact. Rendering finds them, but not in
// the guide, which only administrators read.
func TestDeception_Render_RejectsAnArtifactThatReveals(t *testing.T) {
	t.Parallel()
	d := sample(t, validFiles())

	for _, tt := range []struct {
		company, gateway, artifact, marker string
	}{
		{"Canary Corp", "a.d.example.net", "note", "canary"},
		{"Example Ltd", "a.decoys.example.net", "config", "decoy"},
		// The identifier of the deception and the one of the artifact are the
		// same in every installation.
		{"Sample Ltd", "a.d.example.net", "note", "sample"},
		{"Note Ltd", "a.d.example.net", "note", "note"},
		{"Example Ltd", "config.d.example.net", "config", "config"},
		{"Licensed CC BY 4.0", "a.d.example.net", "note", "cc by"},
	} {
		_, err := d.Render(placedGateway(tt.gateway), personaOfSample(tt.company), secretsOfSample, "en")
		var re *RevealError
		if !errors.Is(err, ErrArtifactReveals) || !errors.As(err, &re) || re.Artifact != tt.artifact || re.Marker != tt.marker {
			t.Errorf("Render(%s, %s) error = %v, want artifact %s revealing %q", tt.company, tt.gateway, err, tt.artifact, tt.marker)
		}
	}
	// A license is recognized as a word of its own, not inside another one.
	for _, company := range []string{"Acc Bypass Ltd", "Built with gcc by default"} {
		if _, err := d.Render(placedGateway("a.d.example.net"), personaOfSample(company), secretsOfSample, "en"); err != nil {
			t.Errorf("Render(%s) error = %v", company, err)
		}
	}
}

// An artifact renders on its own with the persona, the secrets and the
// honeytokens that are bound to its slots, and refuses what would reveal it:
// its own identifier and the identifiers of the deceptions it is rendered for.
func TestArtifact_Render(t *testing.T) {
	t.Parallel()
	note := artifactOf(t, validFiles(), "note")

	values, err := note.Values(map[string]Placed{"Link": {URL: "https://t.example.net/x"}, "Other": {URL: "https://t.example.net/y"}},
		map[string]string{"Domain": "corp.example.com", "Company": "Example Ltd", "Zone": "ignored"}, nil)
	if err != nil {
		t.Fatalf("Values() error = %v", err)
	}
	if len(values) != 3 {
		t.Errorf("Values() = %v, want the slot and the two values of the persona only", values)
	}
	out, err := note.Render(values)
	if err != nil || string(out) != "Example Ltd: https://t.example.net/x on corp.example.com\r\n" {
		t.Errorf("Render(bound) = %q, %v", out, err)
	}

	// An optional slot that is not bound renders as pocket litter, and so
	// does one that the honeytoken does not fill.
	for name, placed := range map[string]map[string]Placed{"unbound": nil, "empty": {"Link": {Host: "a.d.example.net"}}} {
		values, err = note.Values(placed, map[string]string{"Domain": "corp.example.com", "Company": "Example Ltd"}, nil)
		if err != nil {
			t.Fatalf("%s: Values() error = %v", name, err)
		}
		if out, err = note.Render(values); err != nil || string(out) != "Example Ltd on corp.example.com\r\n" {
			t.Errorf("%s: Render() = %q, %v, want the note without a link", name, out, err)
		}
	}

	cfg := artifactOf(t, validFiles(), "config")
	if _, err := cfg.Values(nil, nil, map[string]string{"Password": "Xy7Xy7Xy7Xy7Xy7X"}); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("Values(without the required slot) error = %v, want ErrInvalidValue", err)
	}
	values, err = cfg.Values(map[string]Placed{"Gateway": {Host: "a.d.example.net"}}, nil, map[string]string{"Password": "Xy7Xy7Xy7Xy7Xy7X"})
	if err != nil {
		t.Fatal(err)
	}
	if out, err = cfg.Render(values); err != nil || string(out) != "Host a.d.example.net\nPassword Xy7Xy7Xy7Xy7Xy7X\n" {
		t.Errorf("Render(config) = %q, %v", out, err)
	}
	var re *RevealError
	values["Honeytokens.Gateway.Host"] = "config.d.example.net"
	if _, err := cfg.Render(values); !errors.As(err, &re) || re.Marker != "config" {
		t.Errorf("Render(host with the identifier of the artifact) error = %v, want a RevealError for config", err)
	}
	values["Honeytokens.Gateway.Host"] = "sample.d.example.net"
	if _, err := cfg.Render(values); err != nil {
		t.Errorf("Render(host with the identifier of a deception it is not rendered for) error = %v", err)
	}
	if _, err := cfg.Render(values, "sample"); !errors.As(err, &re) || re.Marker != "sample" {
		t.Errorf("Render(host with the identifier of its deception) error = %v, want a RevealError for sample", err)
	}
}

// What a deception can render is bounded by its static text and the longest
// values, escaped at the highest cost; free text in HTML escapes the most.
func TestDeception_MaxRenderedBytesBoundsTheOutput(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	edit(t, noteJSON, `"format": "text"`, `"format": "html"`)(fsys)
	fsys[noteTmpl] = mapFile("<p title=\"{{.Persona.Company}}\">{{.Persona.Company}}</p>\n{{if .Honeytokens.Link.URL}}<a href=\"{{.Honeytokens.Link.URL}}\">{{.Persona.Domain}}</a>{{end}}\n")
	d := sample(t, fsys)

	placed := map[string]Placed{
		"Gateway": {Host: strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)},
		"Link":    {URL: "https://a.example/" + strings.Repeat("&", maxURLLength-len("https://a.example/"))},
	}
	persona := map[string]string{"Domain": strings.Repeat("e", 63) + ".example.com", "Company": strings.Repeat("&", MaxTextLength)}
	r, err := d.Render(placed, persona, map[string]map[string]string{"config": {"Password": strings.Repeat("X", 16)}}, "en")
	if err != nil {
		t.Fatal(err)
	}
	n := len(r.Guide)
	for _, a := range r.Artifacts {
		n += len(a.Content)
	}
	if bound := d.maxRenderedBytes(); n > bound {
		t.Errorf("rendered %d bytes, more than the bound %d", n, bound)
	}

	// A file with carriage returns renders two bytes for every line feed of
	// its template.
	fsys = validFiles()
	fsys[noteTmpl] = mapFile(strings.Repeat("\n", maxFileBytes-100) + "{{.Persona.Company}}{{if .Honeytokens.Link.URL}}{{.Honeytokens.Link.URL}}{{end}}{{.Persona.Domain}}")
	d = sample(t, fsys)
	r, err = d.Render(placedGateway("a.d.example.net"), personaOfSample("Example Ltd"), secretsOfSample, "en")
	if err != nil {
		t.Fatal(err)
	}
	n = len(r.Guide)
	for _, a := range r.Artifacts {
		n += len(a.Content)
	}
	if bound := d.maxRenderedBytes(); n > bound {
		t.Errorf("rendered %d bytes with carriage returns, more than the bound %d", n, bound)
	}
}
