// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/platform/smtp"
)

func smtpEnv() map[string]string {
	env := workerEnv()
	env["NYKTUS_SMTP_HOST"] = "mail.example.com"
	env["NYKTUS_SMTP_FROM"] = "nyktus@example.com"
	env["NYKTUS_SMTP_USERNAME"] = "nyktus"
	env["NYKTUS_SMTP_PASSWORD"] = "smtp-password"
	return env
}

func TestLoadServe_SMTP(t *testing.T) {
	t.Parallel()

	cfg, err := LoadServe(fakeSource{env: smtpEnv()}.source(), []Role{RoleWorker})
	if err != nil {
		t.Fatalf("LoadServe() error = %v", err)
	}
	want := SMTP{
		Host: "mail.example.com", TLS: smtp.TLSStartTLS, Username: "nyktus", Password: "smtp-password",
		From: "nyktus@example.com",
	}
	if cfg.Worker.SMTP == nil || *cfg.Worker.SMTP != want {
		t.Errorf("SMTP = %+v, want %+v", cfg.Worker.SMTP, want)
	}

	env := smtpEnv()
	delete(env, "NYKTUS_SMTP_PASSWORD")
	env["NYKTUS_SMTP_PASSWORD_FILE"] = "/run/secrets/smtp"
	env["NYKTUS_SMTP_TLS"] = "tls"
	env["NYKTUS_SMTP_PORT"] = "2465"
	env["NYKTUS_SMTP_HELO_NAME"] = "worker.example.com"
	src := fakeSource{env: env, files: map[string]string{"/run/secrets/smtp": "from-file\n"}}
	cfg, err = LoadServe(src.source(), []Role{RoleWorker})
	if err != nil {
		t.Fatalf("LoadServe() error = %v", err)
	}
	want = SMTP{
		Host: "mail.example.com", Port: 2465, TLS: smtp.TLSImplicit, Username: "nyktus", Password: "from-file",
		From: "nyktus@example.com", HeloName: "worker.example.com",
	}
	if *cfg.Worker.SMTP != want {
		t.Errorf("SMTP = %+v, want %+v", *cfg.Worker.SMTP, want)
	}
}

// A relay that admits the worker by its address needs no credentials.
func TestLoadServe_SMTPWithoutAuthentication(t *testing.T) {
	t.Parallel()

	env := smtpEnv()
	delete(env, "NYKTUS_SMTP_USERNAME")
	delete(env, "NYKTUS_SMTP_PASSWORD")
	env["NYKTUS_SMTP_HOST"] = "relay"
	cfg, err := LoadServe(fakeSource{env: env}.source(), []Role{RoleWorker})
	if err != nil {
		t.Fatalf("LoadServe() error = %v", err)
	}
	if c := cfg.Worker.SMTP; c == nil || c.Host != "relay" || c.Username != "" || c.Password != "" {
		t.Errorf("SMTP = %+v", c)
	}
}

func TestLoadServe_SMTPIsReadByTheWorkerOnly(t *testing.T) {
	t.Parallel()

	env := smtpEnv()
	env["NYKTUS_SMTP_TLS"] = "plain"
	env["NYKTUS_TRIGGER_DATABASE_URL"] = "postgres://trigger@db/nyktus"
	env["NYKTUS_TRIGGER_DEFAULT_REDIRECT"] = "https://www.example.com"
	cfg, err := LoadServe(fakeSource{env: env}.source(), []Role{RoleTrigger})
	if err != nil {
		t.Fatalf("LoadServe() for the trigger error = %v, want the SMTP settings ignored", err)
	}
	if cfg.Worker.SMTP != nil {
		t.Errorf("SMTP = %+v, want nil", cfg.Worker.SMTP)
	}
	cfg, err = LoadServe(fakeSource{env: workerEnv()}.source(), []Role{RoleWorker})
	if err != nil || cfg.Worker.SMTP != nil {
		t.Errorf("worker without SMTP: %+v, %v", cfg.Worker.SMTP, err)
	}
}

func TestLoadServe_SMTPRejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		change func(env map[string]string)
		want   string
	}{
		{"plain text in production", func(env map[string]string) { env["NYKTUS_SMTP_TLS"] = "none" }, "NYKTUS_SMTP_TLS"},
		{"unknown mode", func(env map[string]string) { env["NYKTUS_SMTP_TLS"] = "ssl" }, "NYKTUS_SMTP_TLS"},
		{"port zero", func(env map[string]string) { env["NYKTUS_SMTP_PORT"] = "0" }, "NYKTUS_SMTP_PORT"},
		{"port too high", func(env map[string]string) { env["NYKTUS_SMTP_PORT"] = "65536" }, "NYKTUS_SMTP_PORT"},
		{"host with port", func(env map[string]string) { env["NYKTUS_SMTP_HOST"] = "mail.example.com:587" }, "NYKTUS_SMTP_HOST"},
		{"host as URL", func(env map[string]string) { env["NYKTUS_SMTP_HOST"] = "smtp://mail.example.com" }, "NYKTUS_SMTP_HOST"},
		{"no sender", func(env map[string]string) { delete(env, "NYKTUS_SMTP_FROM") }, "NYKTUS_SMTP_FROM"},
		{"sender with name", func(env map[string]string) { env["NYKTUS_SMTP_FROM"] = "Nyktus <nyktus@example.com>" }, "NYKTUS_SMTP_FROM"},
		{"sender with line break", func(env map[string]string) {
			env["NYKTUS_SMTP_FROM"] = "nyktus@example.com\r\nBcc: x@example.net"
		}, "NYKTUS_SMTP_FROM"},
		{"greeting with line break", func(env map[string]string) {
			env["NYKTUS_SMTP_HELO_NAME"] = "worker\r\nRCPT TO:<x@example.net>"
		}, "NYKTUS_SMTP_HELO_NAME"},
		{"username without password", func(env map[string]string) { delete(env, "NYKTUS_SMTP_PASSWORD") }, "NYKTUS_SMTP_PASSWORD"},
		{"password without username", func(env map[string]string) { delete(env, "NYKTUS_SMTP_USERNAME") }, "NYKTUS_SMTP_USERNAME"},
		{"settings without host", func(env map[string]string) { delete(env, "NYKTUS_SMTP_HOST") }, "NYKTUS_SMTP_HOST is not"},
	}
	for _, tt := range tests {
		env := smtpEnv()
		tt.change(env)
		_, err := LoadServe(fakeSource{env: env}.source(), []Role{RoleWorker})
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: LoadServe() error = %v, want it to name %s", tt.name, err, tt.want)
		}
		if err != nil && strings.Contains(err.Error(), "smtp-password") {
			t.Errorf("%s: error %q holds the password", tt.name, err)
		}
	}
}

// Plain SMTP is allowed in development, for a local mail catcher.
func TestLoadServe_SMTPInPlainTextInDevelopment(t *testing.T) {
	t.Parallel()

	env := smtpEnv()
	env["NYKTUS_ENV"] = "development"
	env["NYKTUS_SMTP_TLS"] = "none"
	cfg, err := LoadServe(fakeSource{env: env}.source(), []Role{RoleWorker})
	if err != nil || cfg.Worker.SMTP == nil || cfg.Worker.SMTP.TLS != smtp.TLSNone {
		t.Errorf("SMTP = %+v, %v", cfg.Worker.SMTP, err)
	}
}

func TestSMTP_PasswordNeverAppearsInOutput(t *testing.T) {
	t.Parallel()

	cfg, err := LoadServe(fakeSource{env: smtpEnv()}.source(), []Role{RoleWorker})
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.Worker.SMTP
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("test", slog.Any("smtp", c))
	if s := fmt.Sprintf("%v %+v %#v", c, *c, *c) + buf.String(); strings.Contains(s, "smtp-password") {
		t.Errorf("output contains the password: %s", s)
	}
}
