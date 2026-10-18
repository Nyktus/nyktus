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

func sample(t *testing.T, fsys fstest.MapFS) Deception {
	t.Helper()
	c, err := Load(fsys)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	d, _ := c.Lookup("sample")
	return d
}

// A honeytoken of a deception has the severity that the deception chooses,
// or the default of its type.
func TestLoad_SetsTheSeverityOfEachHoneytoken(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	s := strings.Replace(string(fsys["sample/deception.json"].Data), `"techniques": []}`, `"techniques": [], "severity": "high"}`, 1)
	fsys["sample/deception.json"] = &fstest.MapFile{Data: []byte(s)}
	d := sample(t, fsys)
	if d.Honeytokens[0].Severity != severity.Medium || d.Honeytokens[1].Severity != severity.High {
		t.Errorf("severities %s, %s; want the default medium of dns and the chosen high", d.Honeytokens[0].Severity, d.Honeytokens[1].Severity)
	}
}

// The persona holds exactly the values of the deception, each of its kind and
// none empty; the error names the key but never the value.
func TestDeception_ValidatePersona(t *testing.T) {
	t.Parallel()
	d := sample(t, validFiles())

	valid := map[string]string{"Domain": "corp.example.com", "Company": "Example Ltd"}
	if err := d.ValidatePersona(valid); err != nil {
		t.Fatalf("ValidatePersona(valid) = %v", err)
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
		err := d.ValidatePersona(tt.persona)
		var pe *PersonaError
		if !errors.Is(err, ErrInvalidPersona) || !errors.As(err, &pe) || pe.Key != tt.key {
			t.Errorf("%s: ValidatePersona() = %v, want a PersonaError for %s", tt.name, err, tt.key)
			continue
		}
		for _, v := range tt.persona {
			if v != "" && strings.Contains(err.Error(), v) {
				t.Errorf("%s: the error %q contains the value %q", tt.name, err, v)
			}
		}
	}
}

// Secrets have the length of their declaration, consist of letters and
// digits, and differ between applications.
func TestDeception_NewSecrets(t *testing.T) {
	t.Parallel()
	d := sample(t, validFiles())

	format := regexp.MustCompile(`^[A-Za-z0-9]{16}$`)
	seen := map[string]bool{}
	letters := map[byte]bool{}
	for range 200 {
		s := d.NewSecrets()
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

func placedValues(d Deception, company, gateway string) map[string]string {
	return d.Values(
		map[string]Placed{"Gateway": {Host: gateway}, "Link": {URL: "https://t.example.net/q3xwz7a2kfm4ub6tyc5nre2lpa"}},
		map[string]string{"Domain": "corp.example.com", "Company": company},
		map[string]string{"Password": "Xy7Xy7Xy7Xy7Xy7X"},
	)
}

func TestDeception_Render(t *testing.T) {
	t.Parallel()
	d := sample(t, validFiles())

	r, err := d.Render(placedValues(d, "Example Ltd", "q3xwz7a2kfm4ub6tyc5nre2lpa.d.example.net"), "de")
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if len(r.Artifacts) != 2 || r.Artifacts[0].Key != "config" || r.Artifacts[1].FileName != "Read me.txt" ||
		string(r.Artifacts[0].Content) != "Host q3xwz7a2kfm4ub6tyc5nre2lpa.d.example.net\nPassword Xy7Xy7Xy7Xy7Xy7X\n" ||
		string(r.Artifacts[1].Content) != "Example Ltd: https://t.example.net/q3xwz7a2kfm4ub6tyc5nre2lpa on corp.example.com\r\n" {
		t.Errorf("Render() artifacts = %+v", r.Artifacts)
	}
	if string(r.Guide) != "Legen Sie den Honeytoken q3xwz7a2kfm4ub6tyc5nre2lpa.d.example.net ab.\n" {
		t.Errorf("Render() guide = %q, want the German guide", r.Guide)
	}
	if _, err := d.Render(placedValues(d, "Example Ltd", "a.d.example.net"), "fr"); !errors.Is(err, ErrUnknownLanguage) {
		t.Errorf("Render(fr) error = %v, want ErrUnknownLanguage", err)
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
		{"Sample Ltd", "a.d.example.net", "note", "sample"},
		{"Licensed CC BY 4.0", "a.d.example.net", "note", "cc by"},
	} {
		_, err := d.Render(placedValues(d, tt.company, tt.gateway), "en")
		var re *RevealError
		if !errors.Is(err, ErrArtifactReveals) || !errors.As(err, &re) || re.Artifact != tt.artifact || re.Marker != tt.marker {
			t.Errorf("Render(%s, %s) error = %v, want artifact %s revealing %q", tt.company, tt.gateway, err, tt.artifact, tt.marker)
		}
	}
	// A license is recognized as a word of its own, not inside another one.
	for _, company := range []string{"Acc Bypass Ltd", "Built with gcc by default"} {
		if _, err := d.Render(placedValues(d, company, "a.d.example.net"), "en"); err != nil {
			t.Errorf("Render(%s) error = %v", company, err)
		}
	}
}

// What a deception can render is bounded by its static text and the longest
// values, escaped at the highest cost; free text in HTML escapes the most.
func TestDeception_MaxRenderedBytesBoundsTheOutput(t *testing.T) {
	t.Parallel()

	fsys := validFiles()
	s := strings.Replace(string(fsys["sample/deception.json"].Data), `"format": "text", "line_endings": "crlf"`, `"format": "html", "line_endings": "crlf"`, 1)
	fsys["sample/deception.json"] = &fstest.MapFile{Data: []byte(s)}
	fsys["sample/note.txt.tmpl"] = &fstest.MapFile{Data: []byte("<p title=\"{{.Persona.Company}}\">{{.Persona.Company}}</p>\n<a href=\"{{.Honeytokens.Link.URL}}\">{{.Persona.Domain}}</a>\n")}
	d := sample(t, fsys)

	values := d.Values(
		map[string]Placed{
			"Gateway": {Host: strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)},
			"Link":    {URL: "https://a.example/" + strings.Repeat("&", maxURLLength-len("https://a.example/"))},
		},
		map[string]string{"Domain": strings.Repeat("e", 63) + ".example.com", "Company": strings.Repeat("&", MaxTextLength)},
		map[string]string{"Password": strings.Repeat("X", 16)},
	)
	r, err := d.Render(values, "en")
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
	fsys["sample/note.txt.tmpl"] = &fstest.MapFile{Data: []byte(strings.Repeat("\n", maxFileBytes-100) + "{{.Persona.Company}}{{.Honeytokens.Link.URL}}{{.Persona.Domain}}")}
	d = sample(t, fsys)
	r, err = d.Render(placedValues(d, "Example Ltd", "a.d.example.net"), "en")
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
