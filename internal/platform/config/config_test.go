// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
	"strings"
	"testing"
)

type fakeSource struct {
	env   map[string]string
	files map[string]string
}

func (f fakeSource) source() Source {
	return Source{
		Getenv: func(key string) string { return f.env[key] },
		ReadFile: func(name string) ([]byte, error) {
			content, ok := f.files[name]
			if !ok {
				return nil, fs.ErrNotExist
			}
			return []byte(content), nil
		},
	}
}

func TestLoadServe_Defaults(t *testing.T) {
	t.Parallel()

	src := fakeSource{env: map[string]string{"NYKTUS_CONSOLE_DATABASE_URL": "postgres://console@db/nyktus"}}
	cfg, err := LoadServe(src.source(), []Role{RoleConsole})
	if err != nil {
		t.Fatalf("LoadServe() error = %v", err)
	}

	if cfg.Environment != Production {
		t.Errorf("Environment = %q, want %q", cfg.Environment, Production)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want %v", cfg.LogLevel, slog.LevelInfo)
	}
	if cfg.Console.Addr != "127.0.0.1:8080" {
		t.Errorf("Console.Addr = %q, want loopback default", cfg.Console.Addr)
	}
	if got := cfg.Console.DatabaseURL.Value(); got != "postgres://console@db/nyktus" {
		t.Errorf("Console.DatabaseURL = %q", got)
	}
}

func TestLoadServe_ReportsAllProblems(t *testing.T) {
	t.Parallel()

	src := fakeSource{env: map[string]string{
		"NYKTUS_ENV":          "staging",
		"NYKTUS_LOG_LEVEL":    "verbose",
		"NYKTUS_CONSOLE_ADDR": "8080",
	}}
	_, err := LoadServe(src.source(), []Role{RoleConsole})
	if err == nil {
		t.Fatal("LoadServe() returned no error")
	}
	for _, want := range []string{"NYKTUS_ENV", "NYKTUS_LOG_LEVEL", "NYKTUS_CONSOLE_ADDR", "NYKTUS_CONSOLE_DATABASE_URL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
}

func TestLoadServe_SkipsSettingsOfDisabledRoles(t *testing.T) {
	t.Parallel()

	cfg, err := LoadServe(fakeSource{}.source(), nil)
	if err != nil {
		t.Fatalf("LoadServe() without roles error = %v", err)
	}
	if cfg.Has(RoleConsole) {
		t.Error("Has(RoleConsole) = true without the role enabled")
	}
}

func TestLoadMigrate_SecretFromFile(t *testing.T) {
	t.Parallel()

	src := fakeSource{
		env:   map[string]string{"NYKTUS_DATABASE_URL_FILE": "/run/secrets/db"},
		files: map[string]string{"/run/secrets/db": "postgres://owner@db/nyktus\n"},
	}
	cfg, err := LoadMigrate(src.source())
	if err != nil {
		t.Fatalf("LoadMigrate() error = %v", err)
	}
	if got := cfg.DatabaseURL.Value(); got != "postgres://owner@db/nyktus" {
		t.Errorf("DatabaseURL = %q, want value without trailing newline", got)
	}
}

func TestLoadMigrate_RejectsAmbiguousSecret(t *testing.T) {
	t.Parallel()

	src := fakeSource{
		env:   map[string]string{"NYKTUS_DATABASE_URL": "postgres://a", "NYKTUS_DATABASE_URL_FILE": "/run/secrets/db"},
		files: map[string]string{"/run/secrets/db": "postgres://b"},
	}
	if _, err := LoadMigrate(src.source()); err == nil || !strings.Contains(err.Error(), "both set") {
		t.Errorf("LoadMigrate() error = %v, want ambiguity error", err)
	}
}

func TestLoadMigrate_MissingSecretFile(t *testing.T) {
	t.Parallel()

	src := fakeSource{env: map[string]string{"NYKTUS_DATABASE_URL_FILE": "/run/secrets/missing"}}
	_, err := LoadMigrate(src.source())
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("LoadMigrate() error = %v, want fs.ErrNotExist", err)
	}
}

func TestLoadMigrate_DevelopmentEnvironment(t *testing.T) {
	t.Parallel()

	src := fakeSource{env: map[string]string{"NYKTUS_ENV": "development", "NYKTUS_DATABASE_URL": "postgres://a", "NYKTUS_LOG_LEVEL": "debug"}}
	cfg, err := LoadMigrate(src.source())
	if err != nil {
		t.Fatalf("LoadMigrate() error = %v", err)
	}
	if cfg.Environment != Development || cfg.LogLevel != slog.LevelDebug {
		t.Errorf("Common = %+v, want development at debug level", cfg.Common)
	}
}

func TestSecret_NeverFormatsItsValue(t *testing.T) {
	t.Parallel()

	const value = "postgres://user:hunter2@db/nyktus"
	secret := Secret(value)

	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("test", "secret", secret)

	encoded, err := json.Marshal(struct{ S Secret }{secret})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	outputs := map[string]string{
		"%v":   fmt.Sprintf("%v", secret),
		"%s":   fmt.Sprintf("secret=%s", secret),
		"%#v":  fmt.Sprintf("%#v", secret),
		"%+v":  fmt.Sprintf("%+v", struct{ S Secret }{secret}),
		"log":  logged.String(),
		"json": string(encoded),
	}
	for format, out := range outputs {
		if strings.Contains(out, "hunter2") {
			t.Errorf("format %s leaks the secret: %s", format, out)
		}
	}
	if secret.Value() != value {
		t.Errorf("Value() = %q, want the clear-text value", secret.Value())
	}
}

func TestParseRoles(t *testing.T) {
	t.Parallel()

	all, err := ParseRoles("")
	if err != nil || !slices.Equal(all, Roles) {
		t.Errorf("ParseRoles(\"\") = %v, %v; want all roles", all, err)
	}

	roles, err := ParseRoles(" console , console")
	if err != nil || !slices.Equal(roles, []Role{RoleConsole}) {
		t.Errorf("ParseRoles() = %v, %v; want deduplicated console role", roles, err)
	}

	if _, err := ParseRoles("console,unknown"); err == nil {
		t.Error("ParseRoles() accepted an unknown role")
	}
}
