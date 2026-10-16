// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"errors"
	"strings"
	"testing"
)

var testFields = Fields{
	"Gateway.Host":    KindHost,
	"Gateway.URL":     KindURL,
	"Account":         KindName,
	"Password":        KindSecret,
	"Persona.Company": KindText,
}

func testValues() map[string]string {
	return map[string]string{
		"Gateway.Host":    "vpn.corp.example",
		"Gateway.URL":     "https://t.example.net/abc",
		"Account":         "svc_backup",
		"Password":        "Hx7Lq2Pz9Wm4",
		"Persona.Company": "Example & Partner <Ltd>",
	}
}

func mustRender(t *testing.T, f Format, src string, values map[string]string) string {
	t.Helper()
	tmpl, err := Compile("test", f, src, testFields)
	if err != nil {
		t.Fatalf("Compile(%q) error = %v", src, err)
	}
	out, err := tmpl.Render(values)
	if err != nil {
		t.Fatalf("Render(%q) error = %v", src, err)
	}
	return string(out)
}

func TestCompile_AllowsTextValuesAndConditions(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		src, want string
	}{
		{"", ""},
		{"Host {{.Gateway.Host}}\n  User {{.Account}}\n", "Host vpn.corp.example\n  User svc_backup\n"},
		{"{{if .Account}}user={{.Account}}{{else}}none{{end}}", "user=svc_backup"},
		{"{{if .Gateway.Host}}a{{else if .Account}}b{{end}}", "a"},
		{"a {{- .Account -}} b", "asvc_backupb"},
		{"{{/* removed */}}x", "x"},
	} {
		if got := mustRender(t, FormatConfig, tt.src, testValues()); got != tt.want {
			t.Errorf("render %q = %q, want %q", tt.src, got, tt.want)
		}
	}

	values := testValues()
	values["Account"] = ""
	if got := mustRender(t, FormatConfig, "{{if .Account}}set{{else}}unset{{end}}", values); got != "unset" {
		t.Errorf("{{if}} on an empty value = %q, want unset", got)
	}
}

// Templates are data: every construct beyond text, values and {{if}} could
// call functions, loop, recurse or produce output out of proportion to the
// template, so each is rejected before the template is used.
func TestCompile_RejectsConstructsOutsideTheAllowedSet(t *testing.T) {
	t.Parallel()

	for name, src := range map[string]string{
		"range over a value":     "{{range .Account}}x{{end}}",
		"range over a number":    "{{range 1000000000}}{{end}}",
		"with":                   "{{with .Account}}{{.}}{{end}}",
		"define":                 `{{define "a"}}x{{end}}`,
		"block":                  `{{block "a" .}}x{{end}}`,
		"template":               `{{template "test" .}}`,
		"variable":               "{{$a := .Account}}{{$a}}",
		"assignment in if":       "{{if $a := .Account}}x{{end}}",
		"pipeline":               `{{.Account | printf "%s"}}`,
		"value with arguments":   `{{.Account "x"}}`,
		"function":               `{{printf "%s" .Account}}`,
		"builtin":                "{{len .Account}}",
		"call":                   "{{call .Account}}",
		"comparison":             `{{if eq .Account "x"}}y{{end}}`,
		"string literal":         `{{"text"}}`,
		"number literal":         "{{1}}",
		"dot":                    "{{.}}",
		"parenthesized":          "{{(.Account)}}",
		"chain":                  "{{(.Gateway).Host}}",
		"unknown value":          "{{.Gateway.Port}}",
		"group of values":        "{{.Gateway}}",
		"unknown value in if":    "{{if .Other}}x{{end}}",
		"unknown value in else":  "{{if .Account}}x{{else}}{{.Other}}{{end}}",
		"control character":      "a\x00b",
		"bidirectional override": "a\u202eb",
		"invalid UTF-8":          "a\xffb",
		"parse error":            "{{.Account",
		"too large":              strings.Repeat("a", MaxTemplateBytes+1),
	} {
		// The test render would catch some of these as well; the check of
		// the template must reject them before it.
		if _, err := Compile("test", FormatText, src, testFields); !errors.Is(err, ErrInvalidTemplate) || strings.Contains(err.Error(), "test render") {
			t.Errorf("%s: Compile(%.40q) error = %v, want ErrInvalidTemplate before the test render", name, src, err)
		}
	}
}

func TestCompile_RejectsInvalidDeclarations(t *testing.T) {
	t.Parallel()

	if _, err := Compile("test", "yaml", "x", testFields); !errors.Is(err, ErrInvalidTemplate) {
		t.Errorf("unknown format: error = %v, want ErrInvalidTemplate", err)
	}
	for name, fields := range map[string]Fields{
		"unknown kind":    {"A": "number"},
		"malformed name":  {"a-b": KindName},
		"empty segment":   {"A..B": KindName},
		"leading digit":   {"1A": KindName},
		"value and group": {"A": KindName, "A.B": KindName},
	} {
		if _, err := Compile("test", FormatText, "x", fields); !errors.Is(err, ErrInvalidTemplate) {
			t.Errorf("%s: error = %v, want ErrInvalidTemplate", name, err)
		}
	}
}

// Free text could change what a tool does with a file it interprets, so it
// appears only in files that a person reads.
func TestCompile_AllowsFreeTextOnlyInInertFormats(t *testing.T) {
	t.Parallel()

	src := "{{.Persona.Company}}"
	for _, f := range []Format{FormatText, FormatMarkdown, FormatHTML} {
		if _, err := Compile("test", f, src, testFields); err != nil {
			t.Errorf("%s: Compile() error = %v", f, err)
		}
	}
	for _, src := range []string{src, "{{if .Persona.Company}}x{{end}}"} {
		if _, err := Compile("test", FormatConfig, src, testFields); !errors.Is(err, ErrInvalidTemplate) {
			t.Errorf("config %q: Compile() error = %v, want ErrInvalidTemplate", src, err)
		}
	}
}

func TestRender_EscapesFreeTextForTheFormat(t *testing.T) {
	t.Parallel()

	src := "{{.Persona.Company}}"
	if got := mustRender(t, FormatText, src, testValues()); got != "Example & Partner <Ltd>" {
		t.Errorf("text = %q", got)
	}
	if got := mustRender(t, FormatMarkdown, src, testValues()); got != `Example \& Partner \<Ltd\>` {
		t.Errorf("markdown = %q", got)
	}
	values := testValues()
	values["Persona.Company"] = "[x](javascript:alert(1)) `y` *z* #h"
	if got := mustRender(t, FormatMarkdown, src, values); got != "\\[x\\]\\(javascript\\:alert\\(1\\)\\) \\`y\\` \\*z\\* \\#h" {
		t.Errorf("markdown with markup = %q", got)
	}
	// Values that are not free text are written as they are, so that a URL
	// in a guide stays usable.
	if got := mustRender(t, FormatMarkdown, "<{{.Gateway.URL}}>", testValues()); got != "<https://t.example.net/abc>" {
		t.Errorf("markdown URL = %q", got)
	}
}

func TestRender_EscapesHTMLForItsContext(t *testing.T) {
	t.Parallel()

	src := `<a href="{{.Gateway.URL}}" title="{{.Persona.Company}}">{{.Persona.Company}}</a>`
	values := testValues()
	values["Persona.Company"] = `"><script>alert(1)</script>`
	got := mustRender(t, FormatHTML, src, values)
	want := `<a href="https://t.example.net/abc" title="&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;">&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;</a>`
	if got != want {
		t.Errorf("html =\n%s\nwant\n%s", got, want)
	}
}

// html/template decides how to escape on the first execution, so a template
// that it cannot escape is rejected when it is compiled, not when an
// administrator first applies the deception.
func TestCompile_RejectsHTMLThatCannotBeEscaped(t *testing.T) {
	t.Parallel()

	for _, src := range []string{
		`{{if .Account}}<a href="{{end}}x">`,
		`<a href="x{{.Account}}`,
	} {
		if _, err := Compile("test", FormatHTML, src, testFields); !errors.Is(err, ErrInvalidTemplate) {
			t.Errorf("Compile(%q) error = %v, want ErrInvalidTemplate", src, err)
		}
	}
}

func TestRender_RejectsInvalidValues(t *testing.T) {
	t.Parallel()

	tmpl, err := Compile("test", FormatText, "{{.Gateway.Host}}{{.Gateway.URL}}{{.Account}}{{.Password}}{{.Persona.Company}}", testFields)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		path, value string
	}{
		{"Gateway.Host", "Vpn.corp.example"},
		{"Gateway.Host", "vpn corp"},
		{"Gateway.Host", "vpn..corp"},
		{"Gateway.Host", "-vpn.corp"},
		{"Gateway.Host", "vpn.corp."},
		{"Gateway.Host", "10.0.0.1"},
		{"Gateway.Host", "vpn.corp\nHost x"},
		{"Gateway.Host", strings.Repeat("a.", 127) + "aa"},
		{"Gateway.URL", "ftp://t.example.net/abc"},
		{"Gateway.URL", "https://t.example.net/a b"},
		{"Gateway.URL", `https://t.example.net/a"b`},
		{"Gateway.URL", "https://t.example.net/a'b"},
		{"Gateway.URL", "https://t.example.net/a<b"},
		{"Gateway.URL", `https://t.example.net/a\b`},
		{"Gateway.URL", "https://user@t.example.net/"},
		{"Gateway.URL", "https:///path"},
		{"Gateway.URL", "https://t.example.net/\u00e4"},
		{"Gateway.URL", "https://t.example.net/" + strings.Repeat("a", maxURLLength)},
		{"Account", "svc backup"},
		{"Account", ".hidden"},
		{"Account", "a;b"},
		{"Account", strings.Repeat("a", 65)},
		{"Password", "short"},
		{"Password", "with$dollar1"},
		{"Password", strings.Repeat("a", 129)},
		{"Persona.Company", "two\nlines"},
		{"Persona.Company", "tab\tbetween"},
		{"Persona.Company", "a\u202eb"},
		{"Persona.Company", "a\xffb"},
		{"Persona.Company", strings.Repeat("a", MaxTextLength+1)},
	} {
		values := testValues()
		values[tt.path] = tt.value
		if _, err := tmpl.Render(values); !errors.Is(err, ErrInvalidValue) {
			t.Errorf(".%s = %.40q: Render() error = %v, want ErrInvalidValue", tt.path, tt.value, err)
		} else if strings.Contains(err.Error(), tt.value) {
			t.Errorf(".%s: the error %q contains the value", tt.path, err)
		}
	}

	values := testValues()
	delete(values, "Password")
	if _, err := tmpl.Render(values); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("missing value: Render() error = %v, want ErrInvalidValue", err)
	}
}

func TestRender_AcceptsValuesAtTheirLimits(t *testing.T) {
	t.Parallel()

	tmpl, err := Compile("test", FormatText, "{{.Gateway.Host}}{{.Gateway.URL}}{{.Account}}{{.Password}}{{.Persona.Company}}", testFields)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"Gateway.Host":    strings.Repeat("a.", 125) + "aaa",
		"Gateway.URL":     "http://t.example.net:8080/" + strings.Repeat("a", maxURLLength-26) + "",
		"Account":         "A" + strings.Repeat("b", 63),
		"Password":        strings.Repeat("a", 128),
		"Persona.Company": strings.Repeat("\u00e4", MaxTextLength),
	}
	if _, err := tmpl.Render(values); err != nil {
		t.Errorf("Render() error = %v", err)
	}
	// An empty value means that it is not set.
	if _, err := tmpl.Render(map[string]string{"Gateway.Host": "", "Gateway.URL": "", "Account": "", "Password": "", "Persona.Company": ""}); err != nil {
		t.Errorf("Render(empty values) error = %v", err)
	}
}

func TestRender_BoundsTheOutput(t *testing.T) {
	t.Parallel()

	// Each reference adds a URL of almost 2 KiB, so the output grows far
	// beyond the template.
	src := strings.Repeat("{{.Gateway.URL}}", MaxOutputBytes/1000)
	values := testValues()
	values["Gateway.URL"] = "https://t.example.net/" + strings.Repeat("a", 2000)
	for _, f := range []Format{FormatText, FormatHTML} {
		tmpl, err := Compile("test", f, src, testFields)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tmpl.Render(values); !errors.Is(err, ErrOutputTooLarge) {
			t.Errorf("%s: Render() error = %v, want ErrOutputTooLarge", f, err)
		}
	}
}

// Render checks that every value is present before it executes the template.
// The template itself also runs with missingkey=error, so that a value missing
// from the data can never render as "<no value>".
func TestCompile_RunsTemplatesWithMissingKeyError(t *testing.T) {
	t.Parallel()

	for _, f := range []Format{FormatText, FormatHTML} {
		tmpl, err := Compile("test", f, "{{.Account}}", testFields)
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		if tmpl.text != nil {
			err = tmpl.text.Execute(&b, map[string]any{})
		} else {
			err = tmpl.html.Execute(&b, map[string]any{})
		}
		if err == nil {
			t.Errorf("%s: executing without the value rendered %q, want an error", f, b.String())
		}
	}
}
