// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/platform/config"
	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/migrate"
	"nyktus.org/nyktus/migrations"
)

func source(env map[string]string) config.Source {
	return config.Source{
		Getenv:   func(key string) string { return env[key] },
		ReadFile: func(string) ([]byte, error) { return nil, nil },
	}
}

func TestRun_ExitCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		env  map[string]string
		want int
	}{
		{name: "no command", args: nil, want: exitUsage},
		{name: "unknown command", args: []string{"frobnicate"}, want: exitUsage},
		{name: "version", args: []string{"version"}, want: exitOK},
		{name: "help", args: []string{"help"}, want: exitOK},
		{name: "serve with unknown flag", args: []string{"serve", "--verbose"}, want: exitUsage},
		{name: "serve with unknown role", args: []string{"serve", "--roles=dns"}, want: exitUsage},
		{name: "serve with positional argument", args: []string{"serve", "extra"}, want: exitUsage},
		{name: "serve flag help", args: []string{"serve", "-h"}, want: exitOK},
		{name: "serve without configuration", args: []string{"serve"}, want: exitFailure},
		{name: "migrate without configuration", args: []string{"migrate"}, want: exitFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if got := run(t.Context(), tt.args, source(tt.env), &stdout, &stderr); got != tt.want {
				t.Errorf("run(%v) = %d, want %d; stderr: %s", tt.args, got, tt.want, stderr.String())
			}
		})
	}
}

func TestRun_ConfigurationErrorsNameEveryProblem(t *testing.T) {
	t.Parallel()

	var stderr bytes.Buffer
	env := map[string]string{"NYKTUS_ENV": "staging"}
	run(t.Context(), []string{"serve"}, source(env), &bytes.Buffer{}, &stderr)

	for _, want := range []string{"NYKTUS_ENV", "NYKTUS_CONSOLE_DATABASE_URL"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr does not mention %s: %s", want, stderr.String())
		}
	}
}

func TestRun_RuntimeFailuresAreLoggedAsJSON(t *testing.T) {
	t.Parallel()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	env := map[string]string{"NYKTUS_DATABASE_URL": "postgres://nyktus:hunter2@" + addr + "/nyktus"}
	var stderr bytes.Buffer
	if code := run(t.Context(), []string{"migrate"}, source(env), &bytes.Buffer{}, &stderr); code != exitFailure {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, exitFailure, stderr.String())
	}

	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	for _, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Errorf("stderr line is not JSON: %s", line)
		}
	}
	if last := lines[len(lines)-1]; !strings.Contains(last, `"msg":"nyktus: command failed"`) || !strings.Contains(last, `"command":"migrate"`) {
		t.Errorf("last record is not the failure of migrate: %s", last)
	}
	if strings.Contains(stderr.String(), "hunter2") {
		t.Errorf("stderr leaks the database password: %s", stderr.String())
	}
}

func TestEmbeddedMigrationsAreValid(t *testing.T) {
	t.Parallel()

	if _, err := migrate.Load(migrations.FS); err != nil {
		t.Fatalf("embedded migrations are invalid: %v", err)
	}
}

func TestRun_MigrateAppliesEmbeddedMigrations(t *testing.T) {
	t.Parallel()

	env := map[string]string{"NYKTUS_DATABASE_URL": dbtest.New(t)}
	for i, want := range []string{`"applied":1`, `"applied":0`} {
		var stderr bytes.Buffer
		if code := run(t.Context(), []string{"migrate"}, source(env), &bytes.Buffer{}, &stderr); code != exitOK {
			t.Fatalf("run %d: migrate exit code = %d; stderr: %s", i+1, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("run %d: log does not contain %s: %s", i+1, want, stderr.String())
		}
	}
}
