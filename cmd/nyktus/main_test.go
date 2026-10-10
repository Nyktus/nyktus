// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/auth/setup"
	"nyktus.org/nyktus/internal/platform/config"
	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/migrate"
	"nyktus.org/nyktus/internal/platform/schematest"
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

	all, err := migrate.Load(migrations.FS)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	env := map[string]string{"NYKTUS_DATABASE_URL": dbtest.New(t)}
	dbtest.GroupRole(t, schematest.ConsoleRole)
	for i, want := range []string{fmt.Sprintf(`"applied":%d`, len(all)), `"applied":0`} {
		var stderr bytes.Buffer
		if code := run(t.Context(), []string{"migrate"}, source(env), &bytes.Buffer{}, &stderr); code != exitOK {
			t.Fatalf("run %d: migrate exit code = %d; stderr: %s", i+1, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("run %d: log does not contain %s: %s", i+1, want, stderr.String())
		}
	}
}

func TestAnnounceSetup_PrintsURLToStdoutAndKeepsTokenOutOfLog(t *testing.T) {
	t.Parallel()

	_, consoleURL := schematest.Console(t)
	pool := schematest.Open(t, consoleURL)
	svc := setup.NewService(pool)

	var stdout, log bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&log, nil))
	if err := announceSetup(t.Context(), svc, "https://nyktus.example.com", logger, &stdout); err != nil {
		t.Fatalf("announceSetup() error = %v", err)
	}

	match := regexp.MustCompile(`https://nyktus\.example\.com/setup#token=([A-Za-z0-9_-]{43})\n`).FindStringSubmatch(stdout.String())
	if match == nil {
		t.Fatalf("stdout does not contain the setup URL:\n%s", stdout.String())
	}
	if valid, err := svc.Valid(t.Context(), match[1]); err != nil || !valid {
		t.Errorf("printed token is not valid: %v, %v", valid, err)
	}
	if !strings.Contains(log.String(), `"msg":"console: setup pending"`) || !strings.Contains(log.String(), `"expires_at"`) {
		t.Errorf("log does not record the pending setup: %s", log.String())
	}
	if strings.Contains(log.String(), match[1]) {
		t.Errorf("log contains the setup token: %s", log.String())
	}

	if _, err := pool.Exec(t.Context(),
		`INSERT INTO users (email, display_name, role, status) VALUES ('ada@example.com', 'Ada', 'admin', 'pending')`); err != nil {
		t.Fatalf("create administrator: %v", err)
	}
	stdout.Reset()
	log.Reset()
	if err := announceSetup(t.Context(), svc, "https://nyktus.example.com", logger, &stdout); err != nil {
		t.Fatalf("announceSetup() error = %v", err)
	}
	if stdout.Len() != 0 || log.Len() != 0 {
		t.Errorf("announced a setup although an administrator exists: stdout %q, log %q", stdout.String(), log.String())
	}
}

// A start that fails must not leave a valid setup token behind, for example in a
// crash loop that would otherwise fill the container log with valid setup URLs.
func TestRun_FailedStartIssuesNoSetupToken(t *testing.T) {
	t.Parallel()

	ownerURL, consoleURL := schematest.Console(t)
	occupied, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = occupied.Close() }()

	env := map[string]string{
		"NYKTUS_CONSOLE_DATABASE_URL": consoleURL,
		"NYKTUS_CONSOLE_ADDR":         occupied.Addr().String(),
		"NYKTUS_CONSOLE_URL":          "https://nyktus.example.com",
	}
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"serve", "--roles=console"}, source(env), &stdout, &stderr); code != exitFailure {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, exitFailure, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing", stdout.String())
	}
	var tokens int
	if err := schematest.Open(t, ownerURL).QueryRow(t.Context(), "SELECT count(*) FROM setup_tokens").Scan(&tokens); err != nil {
		t.Fatalf("count setup tokens: %v", err)
	}
	if tokens != 0 {
		t.Errorf("%d setup tokens issued by a failed start, want none", tokens)
	}
}
