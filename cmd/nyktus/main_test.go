// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/miekg/dns"

	"nyktus.org/nyktus/internal/auth/setup"
	"nyktus.org/nyktus/internal/platform/config"
	"nyktus.org/nyktus/internal/platform/dbtest"
	"nyktus.org/nyktus/internal/platform/migrate"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/platform/secretbox"
	"nyktus.org/nyktus/migrations"
)

func source(env map[string]string) config.Source {
	return config.Source{
		Getenv:   func(key string) string { return env[key] },
		ReadFile: func(string) ([]byte, error) { return nil, nil },
	}
}

// testKeys returns a valid keyring for encryption at rest, generated for each
// test so that no key material is written into the source.
func testKeys(t *testing.T) string {
	t.Helper()
	raw := make([]byte, secretbox.KeySize)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return "1:" + base64.StdEncoding.EncodeToString(raw)
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
		{name: "serve with unknown role", args: []string{"serve", "--roles=worker"}, want: exitUsage},
		{name: "serve without roles", args: []string{"serve"}, want: exitUsage},
		{name: "serve with positional argument", args: []string{"serve", "extra"}, want: exitUsage},
		{name: "serve flag help", args: []string{"serve", "-h"}, want: exitOK},
		{name: "serve without configuration", args: []string{"serve", "--roles=console"}, want: exitFailure},
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
	run(t.Context(), []string{"serve", "--roles=console,trigger,dns"}, source(env), &bytes.Buffer{}, &stderr)

	for _, want := range []string{
		"NYKTUS_ENV", "NYKTUS_CONSOLE_DATABASE_URL", "NYKTUS_TRIGGER_DATABASE_URL", "NYKTUS_TRIGGER_DEFAULT_REDIRECT",
		"NYKTUS_DNS_DATABASE_URL", "NYKTUS_DNS_ZONES", "NYKTUS_DNS_NAMESERVERS",
	} {
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
	schematest.GroupRoles(t)
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
		"NYKTUS_TRIGGER_URL":          "https://t.example.com",
		"NYKTUS_CONSOLE_ADDR":         occupied.Addr().String(),
		"NYKTUS_CONSOLE_URL":          "https://nyktus.example.com",
		"NYKTUS_ENCRYPTION_KEYS":      testKeys(t),
	}
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"serve", "--roles=console"}, source(env), &stdout, &stderr); code != exitFailure {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, exitFailure, stderr.String())
	}
	// The start must fail at the listener, after the configuration was accepted.
	if !strings.Contains(stderr.String(), "address already in use") {
		t.Errorf("stderr = %q, want the failure of the listener", stderr.String())
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

// A secret encrypted with a key that the configuration no longer lists could
// never be decrypted, and its user could not sign in. The console refuses to
// start instead, before it accepts requests or issues a setup token.
func TestRun_RefusesToStartWithoutTheKeyOfStoredSecrets(t *testing.T) {
	t.Parallel()

	ownerURL, consoleURL := schematest.Console(t)
	owner := schematest.Open(t, ownerURL)
	var id string
	if err := owner.QueryRow(t.Context(), `
INSERT INTO users (email, display_name, role, status) VALUES ('ada@example.com', 'Ada', 'viewer', 'pending') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	// The secret names key 7.
	if _, err := owner.Exec(t.Context(), `INSERT INTO totp_factors (user_id, secret) VALUES ($1, decode('07' || repeat('00', 48), 'hex'))`, id); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"NYKTUS_CONSOLE_DATABASE_URL": consoleURL,
		"NYKTUS_TRIGGER_URL":          "https://t.example.com",
		"NYKTUS_CONSOLE_ADDR":         "127.0.0.1:0",
		"NYKTUS_CONSOLE_URL":          "https://nyktus.example.com",
		"NYKTUS_ENCRYPTION_KEYS":      testKeys(t),
	}
	// A console that starts anyway serves until the deadline, and the test
	// fails instead of hanging.
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	if code := run(ctx, []string{"serve", "--roles=console"}, source(env), &stdout, &stderr); code != exitFailure {
		t.Fatalf("exit code = %d, want %d; stderr: %s", code, exitFailure, stderr.String())
	}
	if !strings.Contains(stderr.String(), "key ID 7, which is not configured") {
		t.Errorf("stderr = %q, want it to name the missing key", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want no setup URL", stdout.String())
	}
}

func TestRunRoles_AFailedRoleStopsTheOthers(t *testing.T) {
	t.Parallel()

	// A role that keeps running would make runRoles wait for the deadline, and
	// the test fails instead of hanging.
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	failure := errors.New("listener failed")
	stopped := make(chan struct{})
	err := runRoles(ctx, []role{
		func(ctx context.Context, started func(), _ <-chan struct{}) error {
			started()
			<-ctx.Done()
			close(stopped)
			// A stopped role may fail as a consequence; only the cause counts.
			return fmt.Errorf("serve: %w", ctx.Err())
		},
		func(context.Context, func(), <-chan struct{}) error { return failure },
	})
	if err != failure { //nolint:errorlint // the error must be the failure itself, without the consequence.
		t.Errorf("runRoles() error = %v, want only the failure of the role", err)
	}
	if ctx.Err() != nil {
		t.Error("runRoles waited for the deadline instead of stopping the other role")
	}
	select {
	case <-stopped:
	default:
		t.Error("the other role was still running when runRoles returned")
	}
}

// A role waits for the others before a step that a failed start must not leave
// behind, such as a setup token.
func TestRunRoles_AllStartedOnlyOnceEveryRoleStarted(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	failure := errors.New("listener failed")
	var proceeded bool
	err := runRoles(ctx, []role{
		func(ctx context.Context, started func(), allStarted <-chan struct{}) error {
			started()
			select {
			case <-allStarted:
				proceeded = true
			case <-ctx.Done():
			}
			return nil
		},
		func(context.Context, func(), <-chan struct{}) error { return failure },
	})
	if !errors.Is(err, failure) || proceeded {
		t.Errorf("runRoles() = %v, proceeded = %v; want the failure, and the first role never to proceed", err, proceeded)
	}

	err = runRoles(ctx, []role{
		func(_ context.Context, started func(), allStarted <-chan struct{}) error {
			started()
			started()
			<-allStarted
			return nil
		},
		func(_ context.Context, started func(), allStarted <-chan struct{}) error {
			started()
			<-allStarted
			return nil
		},
	})
	if err != nil || ctx.Err() != nil {
		t.Errorf("runRoles() = %v, deadline %v; want both roles to proceed", err, ctx.Err())
	}
}

// The trigger connects with its own database role, refuses a role with more
// privileges outside development, and answers requests once it listens.
func TestRun_ServesTheTrigger(t *testing.T) {
	t.Parallel()

	ownerURL, triggerURL := schematest.Trigger(t)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	env := map[string]string{
		"NYKTUS_TRIGGER_ADDR":             addr,
		"NYKTUS_TRIGGER_DEFAULT_REDIRECT": "https://www.example.com/",
	}

	t.Run("refuses the owner", func(t *testing.T) {
		env := maps.Clone(env)
		env["NYKTUS_TRIGGER_DATABASE_URL"] = ownerURL
		// A trigger that starts anyway serves until the deadline, and the test
		// fails instead of hanging.
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		var stderr bytes.Buffer
		if code := run(ctx, []string{"serve", "--roles=trigger"}, source(env), &bytes.Buffer{}, &stderr); code != exitFailure {
			t.Fatalf("exit code = %d, want %d; stderr: %s", code, exitFailure, stderr.String())
		}
		if !strings.Contains(stderr.String(), "excessive privileges") {
			t.Errorf("stderr = %q, want the privilege check to fail", stderr.String())
		}
	})

	// A login with the privileges of the console would put the inventory
	// within reach of the internet-facing host.
	t.Run("refuses a login of the console", func(t *testing.T) {
		env := maps.Clone(env)
		_, consoleURL := dbtest.Role(t, ownerURL, "console", "IN ROLE "+pgx.Identifier{schematest.ConsoleRole}.Sanitize())
		env["NYKTUS_TRIGGER_DATABASE_URL"] = consoleURL
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		var stderr bytes.Buffer
		if code := run(ctx, []string{"serve", "--roles=trigger"}, source(env), &bytes.Buffer{}, &stderr); code != exitFailure {
			t.Fatalf("exit code = %d, want %d; stderr: %s", code, exitFailure, stderr.String())
		}
		if !strings.Contains(stderr.String(), "cannot execute public.record_honeytoken_request(") {
			t.Errorf("stderr = %q, want the privilege check of the trigger to fail", stderr.String())
		}
	})

	t.Run("serves with its role", func(t *testing.T) {
		env := maps.Clone(env)
		env["NYKTUS_TRIGGER_DATABASE_URL"] = triggerURL
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		logR, logW := io.Pipe()
		done := make(chan int, 1)
		go func() {
			done <- run(ctx, []string{"serve", "--roles=trigger"}, source(env), &bytes.Buffer{}, logW)
			_ = logW.Close()
		}()
		// The trigger accepts requests once it logs that it listens.
		lines := bufio.NewScanner(logR)
		for lines.Scan() {
			if strings.Contains(lines.Text(), `"msg":"trigger: listening"`) {
				break
			}
		}
		go func() { _, _ = io.Copy(io.Discard, logR) }()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/aaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
		if err != nil {
			t.Fatal(err)
		}
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "https://www.example.com/" {
			t.Errorf("GET = %d %s, want a redirect to the default target", res.StatusCode, res.Header.Get("Location"))
		}

		cancel()
		if code := <-done; code != exitOK {
			t.Errorf("exit code = %d, want %d", code, exitOK)
		}
	})
}

func TestRun_ServesTheDNSRole(t *testing.T) {
	t.Parallel()

	ownerURL, dnsURL := schematest.DNS(t)
	// UDP and TCP listen on the same port; a free TCP port is usually free for
	// UDP as well.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	env := map[string]string{
		"NYKTUS_DNS_ADDR":        addr,
		"NYKTUS_DNS_ZONES":       "d.example.com",
		"NYKTUS_DNS_NAMESERVERS": "ns1.example.net",
		"NYKTUS_DNS_ANSWER_IPV4": "203.0.113.7",
	}

	// A login with the privileges of the console would put the inventory
	// within reach of the internet-facing host.
	t.Run("refuses a login of the console", func(t *testing.T) {
		env := maps.Clone(env)
		_, consoleURL := dbtest.Role(t, ownerURL, "console", "IN ROLE "+pgx.Identifier{schematest.ConsoleRole}.Sanitize())
		env["NYKTUS_DNS_DATABASE_URL"] = consoleURL
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		var stderr bytes.Buffer
		if code := run(ctx, []string{"serve", "--roles=dns"}, source(env), &bytes.Buffer{}, &stderr); code != exitFailure {
			t.Fatalf("exit code = %d, want %d; stderr: %s", code, exitFailure, stderr.String())
		}
		if !strings.Contains(stderr.String(), "cannot execute public.record_dns_query(") {
			t.Errorf("stderr = %q, want the privilege check of the DNS role to fail", stderr.String())
		}
	})

	t.Run("serves with its role", func(t *testing.T) {
		env := maps.Clone(env)
		env["NYKTUS_DNS_DATABASE_URL"] = dnsURL
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		logR, logW := io.Pipe()
		done := make(chan int, 1)
		go func() {
			done <- run(ctx, []string{"serve", "--roles=dns"}, source(env), &bytes.Buffer{}, logW)
			_ = logW.Close()
		}()
		lines := bufio.NewScanner(logR)
		for lines.Scan() {
			if strings.Contains(lines.Text(), `"msg":"dns: listening"`) {
				break
			}
		}
		go func() { _, _ = io.Copy(io.Discard, logR) }()

		for _, network := range []string{"udp", "tcp"} {
			q := new(dns.Msg)
			q.SetQuestion("aaaaaaaaaaaaaaaaaaaaaaaaaa.d.example.com.", dns.TypeA)
			client := &dns.Client{Net: network, Timeout: 5 * time.Second}
			res, _, err := client.ExchangeContext(ctx, q, addr)
			if err != nil {
				t.Fatalf("%s: query: %v", network, err)
			}
			if res.Rcode != dns.RcodeSuccess || len(res.Answer) != 1 || res.Answer[0].(*dns.A).A.String() != "203.0.113.7" {
				t.Errorf("%s: answer = %v, want the configured address", network, res)
			}
		}

		cancel()
		if code := <-done; code != exitOK {
			t.Errorf("exit code = %d, want %d", code, exitOK)
		}
	})
}

// In a process with several roles, the console issues the setup token only once
// every role has started. Here another role never starts, so the console must
// stop without a token: with an early token, it either issues one or fails
// while issuing it when the process stops.
func TestServeConsole_IssuesNoSetupTokenBeforeEveryRoleStarted(t *testing.T) {
	t.Parallel()

	ownerURL, consoleURL := schematest.Console(t)
	env := map[string]string{
		"NYKTUS_CONSOLE_DATABASE_URL": consoleURL,
		"NYKTUS_TRIGGER_URL":          "https://t.example.com",
		"NYKTUS_CONSOLE_ADDR":         "127.0.0.1:0",
		"NYKTUS_CONSOLE_URL":          "https://nyktus.example.com",
		"NYKTUS_ENCRYPTION_KEYS":      testKeys(t),
	}
	cfg, err := config.LoadServe(source(env), []config.Role{config.RoleConsole})
	if err != nil {
		t.Fatalf("LoadServe() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	started := make(chan struct{})
	var stdout bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- serveConsole(ctx, cfg, slog.New(slog.DiscardHandler), &stdout, func() { close(started) }, make(chan struct{}))
	}()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("serveConsole() = %v before it started", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("serveConsole() = %v, want nil after the stop", err)
	}

	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want no setup URL", stdout.String())
	}
	var tokens int
	if err := schematest.Open(t, ownerURL).QueryRow(t.Context(), "SELECT count(*) FROM setup_tokens").Scan(&tokens); err != nil {
		t.Fatalf("count setup tokens: %v", err)
	}
	if tokens != 0 {
		t.Errorf("%d setup tokens issued, want none", tokens)
	}
}
