// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"encoding/json"
	"io/fs"
	"path"
	"slices"
	"strings"
	"testing"

	embedded "nyktus.org/nyktus/catalog"
)

// Files that a tool interprets receive only values that the server generates,
// such as URLs, host names of honeytokens and secrets, or values of the
// persona that match the pattern of their kind; free text appears only in
// files that a person reads.
func TestEmbeddedCatalog_ExecutableFormatsTakeOnlyAllowedValues(t *testing.T) {
	t.Parallel()

	c, err := Load(embedded.FS())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range c.Artifacts() {
		if a.Format.inert() {
			continue
		}
		for path, kind := range a.Template.fields {
			if kind != KindHost && kind != KindURL && kind != KindName && kind != KindSecret {
				t.Errorf("%s: .%s of kind %s in a file that a tool interprets", a.ID, path, kind)
			}
		}
	}
}

// quotedExtensions are the file types in which a value is a string of the
// language around it. The kinds of values exclude every quote character, so a
// value inside quotes cannot end the string; outside quotes, a character such
// as a semicolon or a dot would be code.
var quotedExtensions = []string{".ps1", ".js", ".sql", ".reg", ".json", ".tf"}

// firstUnquoted returns the first reference to a value in line that is not
// inside single quotes, double quotes or square brackets, and whether there is
// one.
func firstUnquoted(line string) (string, bool) {
	var closer byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case strings.HasPrefix(line[i:], "{{"):
			if closer == 0 {
				return line[i:], true
			}
			if end := strings.Index(line[i:], "}}"); end >= 0 {
				i += end + 1
			}
		case closer == 0 && (c == '\'' || c == '"'):
			closer = c
		case closer == 0 && c == '[':
			closer = ']'
		case c == closer:
			closer = 0
		}
	}
	return "", false
}

func TestFirstUnquoted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		line string
		want bool
	}{
		{`$user = '{{.Persona.Account}}'`, false},
		{`"Server"="{{.Honeytokens.Server.Host}}"`, false},
		{`[HKEY_CURRENT_USER\Software\{{.Persona.Vendor}}\Backup]`, false},
		{`EXEC xp_dirtree N'\\{{.Honeytokens.Share.Host}}\{{.Persona.ShareName}}', 1, 1;`, false},
		{`address = "https://{{.Honeytokens.State.Host}}/state/{{.Persona.Project}}"`, false},
		{`$server = {{.Honeytokens.Share.Host}}`, true},
		{`Invoke-Command {{.Persona.Account}}; 'x'`, true},
		{`'a' {{.Persona.Account}} 'b'`, true},
		{`"it's" {{.Persona.Account}}`, true},
		{`"{{.Persona.Account}}" {{.Secrets.Password}}`, true},
	}
	for _, tt := range tests {
		if _, got := firstUnquoted(tt.line); got != tt.want {
			t.Errorf("firstUnquoted(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

// Values in scripts and data files stand inside quotes, so that a value of the
// persona, whose pattern allows dots and hyphens, can never be read as code.
func TestEmbeddedCatalog_ScriptsTakeValuesOnlyInsideQuotes(t *testing.T) {
	t.Parallel()

	root, err := fs.Sub(embedded.FS(), "artifacts")
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := fs.ReadDir(root, ".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, dir := range dirs {
		raw, err := fs.ReadFile(root, path.Join(dir.Name(), "artifact.json"))
		if err != nil {
			t.Fatal(err)
		}
		var def struct {
			FileName string `json:"file_name"`
			Template string `json:"template"`
		}
		if err := json.Unmarshal(raw, &def); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(quotedExtensions, strings.ToLower(path.Ext(def.FileName))) {
			continue
		}
		src, err := fs.ReadFile(root, path.Join(dir.Name(), def.Template))
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for n, line := range strings.Split(string(src), "\n") {
			if ref, bad := firstUnquoted(line); bad {
				t.Errorf("%s/%s line %d: a value outside quotes: %s", dir.Name(), def.Template, n+1, ref)
			}
		}
	}
	if checked == 0 {
		t.Error("no script was checked")
	}
}
