// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeypot_test

import (
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"nyktus.org/nyktus/internal/honeypot"
)

// goldenEntry is the entry that the sensor reads in its own tests. The sensor
// is a module of its own, so the two sides cannot import each other: this
// file is what they agree on.
const (
	goldenEntry    = "../../sensor/internal/config/testdata/console_entry.yaml"
	goldenSSHEntry = "../../sensor/internal/config/testdata/console_entry_ssh.yaml"
)

func TestCreated_SensorConfig_IsTheEntryThatTheSensorReads(t *testing.T) {
	t.Parallel()

	want, err := os.ReadFile(goldenEntry)
	if err != nil {
		t.Fatal(err)
	}
	c := honeypot.Created{
		Honeypot: honeypot.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: honeypot.ServiceTelnet, Name: "Switch console", Notes: "rack 4"},
		Secret:   honeypot.Secret(strings.Repeat("A", 43)),
	}
	if got := c.SensorConfig(); got != string(want) {
		t.Errorf("SensorConfig() = %q, want the content of %s: %q", got, goldenEntry, want)
	}
}

// The entry of an SSH honeypot names the file of its host key, which the sensor
// requires.
func TestCreated_SensorConfig_SSH_IsTheEntryThatTheSensorReads(t *testing.T) {
	t.Parallel()

	want, err := os.ReadFile(goldenSSHEntry)
	if err != nil {
		t.Fatal(err)
	}
	c := honeypot.Created{
		Honeypot: honeypot.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: honeypot.ServiceSSH, Name: "Jump host"},
		Secret:   honeypot.Secret(strings.Repeat("A", 43)),
	}
	if got := c.SensorConfig(); got != string(want) {
		t.Errorf("SensorConfig() = %q, want the content of %s: %q", got, goldenSSHEntry, want)
	}
}

func TestCreated_SensorConfig_NamesTheUsualPortOfEveryService(t *testing.T) {
	t.Parallel()

	want := map[honeypot.Service]string{
		honeypot.ServiceSSH:      ":22",
		honeypot.ServiceTelnet:   ":23",
		honeypot.ServicePostgres: ":5432",
		honeypot.ServiceLDAP:     ":389",
	}
	for _, service := range honeypot.Services {
		if _, ok := want[service]; !ok {
			t.Fatalf("service %s is missing in the table of the test", service)
		}
		var entry []struct {
			Service string `yaml:"service"`
			Listen  string `yaml:"listen"`
		}
		c := honeypot.Created{Honeypot: honeypot.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: service}, Secret: "x"}
		if err := yaml.Unmarshal([]byte(c.SensorConfig()), &entry); err != nil {
			t.Fatalf("%s: %v", service, err)
		}
		if len(entry) != 1 || entry[0].Service != string(service) || entry[0].Listen != want[service] {
			t.Errorf("%s: entry = %+v, want the service and the port %s", service, entry, want[service])
		}
	}
}

// Whatever the values are, they stay values of their own entry: none of them
// can end its line, start a comment or add a member.
func TestCreated_SensorConfig_QuotesEveryValue(t *testing.T) {
	t.Parallel()

	hostile := []string{
		"plain",
		"a: b",
		"a\nb: c",
		"\"quoted\"",
		"back\\slash",
		"- list",
		"# comment",
		"&anchor *alias !tag",
		"line\r\nbreak",
		"tab\tand\x00nul",
		"no",
		"123",
		"~",
		"\u00e4\u2028\u2029",
	}
	for _, v := range hostile {
		c := honeypot.Created{Honeypot: honeypot.Honeypot{ID: v, Service: honeypot.Service(v)}, Secret: honeypot.Secret(v)}
		var entries []map[string]string
		if err := yaml.Unmarshal([]byte(c.SensorConfig()), &entries); err != nil {
			t.Errorf("%q: %v", v, err)
			continue
		}
		if len(entries) != 1 || len(entries[0]) != 4 || entries[0]["id"] != v || entries[0]["service"] != v || entries[0]["secret"] != v {
			t.Errorf("%q: entries = %q, want one entry with the value in id, service and secret", v, entries)
		}
	}
}
