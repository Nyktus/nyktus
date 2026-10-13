// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
)

func TestLoadServe_TriggerDefaults(t *testing.T) {
	t.Parallel()

	src := fakeSource{
		env: map[string]string{
			"NYKTUS_TRIGGER_DATABASE_URL_FILE": "/run/secrets/trigger",
			"NYKTUS_TRIGGER_DEFAULT_REDIRECT":  "https://www.example.com/",
		},
		files: map[string]string{"/run/secrets/trigger": "postgres://trigger@db/nyktus\n"},
	}
	cfg, err := LoadServe(src.source(), []Role{RoleTrigger})
	if err != nil {
		t.Fatalf("LoadServe() error = %v", err)
	}
	want := Trigger{Addr: "127.0.0.1:8081", DatabaseURL: "postgres://trigger@db/nyktus", DefaultRedirect: "https://www.example.com/"}
	if cfg.Trigger != want {
		t.Errorf("Trigger = %+v, want %+v", cfg.Trigger, want)
	}
	if cfg.Has(RoleConsole) || cfg.EncryptionKeys != nil {
		t.Error("the trigger alone read the settings of the console")
	}
}

func TestLoadServe_TriggerReportsAllProblems(t *testing.T) {
	t.Parallel()

	src := fakeSource{env: map[string]string{"NYKTUS_TRIGGER_ADDR": "8081"}}
	_, err := LoadServe(src.source(), []Role{RoleTrigger})
	if err == nil {
		t.Fatal("LoadServe() returned no error")
	}
	for _, want := range []string{"NYKTUS_TRIGGER_ADDR", "NYKTUS_TRIGGER_DATABASE_URL", "NYKTUS_TRIGGER_DEFAULT_REDIRECT is required"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
	for _, unwanted := range []string{"NYKTUS_CONSOLE", "NYKTUS_ENCRYPTION_KEYS", "NYKTUS_TRIGGER_URL"} {
		if strings.Contains(err.Error(), unwanted) {
			t.Errorf("error mentions %s, a setting of the console: %v", unwanted, err)
		}
	}
}

func TestLoadServe_TriggerDefaultRedirect(t *testing.T) {
	t.Parallel()

	const invalid = "NYKTUS_TRIGGER_DEFAULT_REDIRECT: must be an http or https URL"
	tests := []struct {
		name        string
		development bool
		value       string
		err         string
	}{
		{name: "https", value: "https://www.example.com"},
		{name: "path and query", value: "https://www.example.com/news?page=2"},
		{name: "http in production", value: "http://www.example.com", err: "NYKTUS_TRIGGER_DEFAULT_REDIRECT: must start with https://"},
		{name: "http in development", development: true, value: "http://www.example.com"},
		{name: "other scheme", value: "ftp://www.example.com", err: invalid},
		{name: "IP address", value: "https://192.0.2.1/", err: invalid},
		{name: "numeric host", value: "https://2130706433/", err: invalid},
		{name: "user information", value: "https://user@www.example.com", err: invalid},
		{name: "space", value: "https://www.example.com/a b", err: invalid},
		{name: "too long", value: "https://www.example.com/" + strings.Repeat("a", 2048), err: invalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := map[string]string{
				"NYKTUS_TRIGGER_DATABASE_URL":     "postgres://trigger@db/nyktus",
				"NYKTUS_TRIGGER_DEFAULT_REDIRECT": tt.value,
			}
			if tt.development {
				env["NYKTUS_ENV"] = "development"
			}
			cfg, err := LoadServe(fakeSource{env: env}.source(), []Role{RoleTrigger})
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Errorf("LoadServe() error = %v, want it to contain %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadServe() error = %v", err)
			}
			if cfg.Trigger.DefaultRedirect != tt.value {
				t.Errorf("DefaultRedirect = %q, want %q", cfg.Trigger.DefaultRedirect, tt.value)
			}
		})
	}
}
