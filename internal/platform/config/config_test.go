// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"nyktus.org/nyktus/internal/platform/secretbox"
)

// testKeys is a valid keyring, generated for each run so that no key material
// is written into the source.
var testKeys = func() string {
	raw := make([]byte, secretbox.KeySize)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	return "1:" + base64.StdEncoding.EncodeToString(raw)
}()

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

	src := fakeSource{env: map[string]string{
		"NYKTUS_CONSOLE_DATABASE_URL": "postgres://console@db/nyktus",
		"NYKTUS_TRIGGER_URL":          "https://t.example.com",
		"NYKTUS_CONSOLE_URL":          "https://nyktus.example.com",
		"NYKTUS_ENCRYPTION_KEYS":      testKeys,
	}}
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
	for _, want := range []string{"NYKTUS_ENV", "NYKTUS_LOG_LEVEL", "NYKTUS_CONSOLE_ADDR", "NYKTUS_CONSOLE_URL", "NYKTUS_CONSOLE_DATABASE_URL", "NYKTUS_ENCRYPTION_KEYS", "NYKTUS_TRIGGER_URL"} {
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

func TestLoadServe_ConsoleURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		development bool
		addr        string
		value       string
		want        string
		err         string
	}{
		{name: "https", value: "https://nyktus.example.com", want: "https://nyktus.example.com"},
		{name: "trailing slash", value: "https://nyktus.example.com/", want: "https://nyktus.example.com"},
		{name: "port", value: "https://nyktus.example.com:8443", want: "https://nyktus.example.com:8443"},
		{name: "IPv6 host", value: "https://[2001:db8::1]:8443", want: "https://[2001:db8::1]:8443"},
		{name: "required in production", err: "NYKTUS_CONSOLE_URL is required"},
		{name: "http in production", value: "http://nyktus.example.com", err: "must start with https://"},
		{name: "http in development", development: true, value: "http://localhost:8080", want: "http://localhost:8080"},
		{name: "other scheme", development: true, value: "ftp://nyktus.example.com", err: "must start with https://"},
		{name: "no scheme", value: "nyktus.example.com", err: "must start with https://"},
		{name: "no host", value: "https://", err: "must name a host"},
		{name: "port without host", value: "https://:8443", err: "must name a host"},
		{name: "user information", value: "https://admin@nyktus.example.com", err: "scheme, host and port only"},
		{name: "path", value: "https://example.com/nyktus", err: "scheme, host and port only"},
		{name: "query", value: "https://nyktus.example.com?a=b", err: "scheme, host and port only"},
		{name: "empty query", value: "https://nyktus.example.com?", err: "scheme, host and port only"},
		{name: "fragment", value: "https://nyktus.example.com#token=x", err: "scheme, host and port only"},
		{name: "empty fragment", value: "https://nyktus.example.com#", err: "scheme, host and port only"},
		{name: "invalid port", value: "https://nyktus.example.com:https", err: "is not a URL"},
		{name: "development default", development: true, want: "http://127.0.0.1:8080"},
		{name: "development default on all interfaces", development: true, addr: ":9000", want: "http://localhost:9000"},
		{name: "development default on unspecified IPv6", development: true, addr: "[::]:9000", want: "http://localhost:9000"},
		{name: "development default on IPv6 loopback", development: true, addr: "[::1]:9000", want: "http://[::1]:9000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := map[string]string{
				"NYKTUS_CONSOLE_DATABASE_URL": "postgres://console@db/nyktus",
				"NYKTUS_TRIGGER_URL":          "https://t.example.com",
				"NYKTUS_CONSOLE_URL":          tt.value,
				"NYKTUS_ENCRYPTION_KEYS":      testKeys,
			}
			if tt.development {
				env["NYKTUS_ENV"] = "development"
			}
			if tt.addr != "" {
				env["NYKTUS_CONSOLE_ADDR"] = tt.addr
			}
			cfg, err := LoadServe(fakeSource{env: env}.source(), []Role{RoleConsole})
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Errorf("LoadServe() error = %v, want it to contain %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadServe() error = %v", err)
			}
			if cfg.Console.URL != tt.want {
				t.Errorf("Console.URL = %q, want %q", cfg.Console.URL, tt.want)
			}
		})
	}
}

func TestLoadServe_SessionDurations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		idle, maxAge string
		wantIdle     time.Duration
		wantMaxAge   time.Duration
		err          string
	}{
		{name: "defaults", wantIdle: time.Hour, wantMaxAge: 12 * time.Hour},
		{name: "custom", idle: "30m", maxAge: "8h", wantIdle: 30 * time.Minute, wantMaxAge: 8 * time.Hour},
		{name: "equal", idle: "2h", maxAge: "2h", wantIdle: 2 * time.Hour, wantMaxAge: 2 * time.Hour},
		{name: "idle too short", idle: "4m", err: "NYKTUS_SESSION_IDLE_TIMEOUT: must be between 5m0s and 24h0m0s"},
		{name: "idle too long", idle: "25h", err: "NYKTUS_SESSION_IDLE_TIMEOUT: must be between"},
		{name: "max age below idle", idle: "2h", maxAge: "1h", err: "NYKTUS_SESSION_MAX_AGE: must be between 2h0m0s and 720h0m0s"},
		{name: "max age too long", maxAge: "721h", err: "NYKTUS_SESSION_MAX_AGE: must be between"},
		{name: "no unit", idle: "60", err: "NYKTUS_SESSION_IDLE_TIMEOUT: \"60\" is not a duration"},
		{name: "negative", maxAge: "-1h", err: "NYKTUS_SESSION_MAX_AGE: must be between"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := map[string]string{
				"NYKTUS_CONSOLE_DATABASE_URL": "postgres://console@db/nyktus",
				"NYKTUS_TRIGGER_URL":          "https://t.example.com",
				"NYKTUS_CONSOLE_URL":          "https://nyktus.example.com",
				"NYKTUS_SESSION_IDLE_TIMEOUT": tt.idle,
				"NYKTUS_SESSION_MAX_AGE":      tt.maxAge,
				"NYKTUS_ENCRYPTION_KEYS":      testKeys,
			}
			cfg, err := LoadServe(fakeSource{env: env}.source(), []Role{RoleConsole})
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Errorf("LoadServe() error = %v, want it to contain %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadServe() error = %v", err)
			}
			if cfg.Console.SessionIdleTimeout != tt.wantIdle || cfg.Console.SessionMaxAge != tt.wantMaxAge {
				t.Errorf("durations = %v, %v; want %v, %v", cfg.Console.SessionIdleTimeout, cfg.Console.SessionMaxAge, tt.wantIdle, tt.wantMaxAge)
			}
		})
	}
}

func TestLoadServe_EncryptionKeys(t *testing.T) {
	t.Parallel()

	env := func(keys string) map[string]string {
		return map[string]string{
			"NYKTUS_ENV":                  "development",
			"NYKTUS_CONSOLE_DATABASE_URL": "postgres://console@db/nyktus",
			"NYKTUS_TRIGGER_URL":          "https://t.example.com",
			"NYKTUS_ENCRYPTION_KEYS":      keys,
		}
	}

	cfg, err := LoadServe(fakeSource{env: env(testKeys)}.source(), []Role{RoleConsole})
	if err != nil {
		t.Fatalf("LoadServe() error = %v", err)
	}
	if cfg.EncryptionKeys == nil || cfg.EncryptionKeys.CurrentKeyID() != 1 {
		t.Errorf("EncryptionKeys = %v, want the keyring with key 1", cfg.EncryptionKeys)
	}

	// Development needs the keys as well: a generated key would make the stored
	// secrets unreadable after a restart.
	_, err = LoadServe(fakeSource{env: env("")}.source(), []Role{RoleConsole})
	if err == nil || !strings.Contains(err.Error(), "NYKTUS_ENCRYPTION_KEYS or NYKTUS_ENCRYPTION_KEYS_FILE is required") {
		t.Errorf("LoadServe() without keys error = %v, want them required", err)
	}

	_, err = LoadServe(fakeSource{env: env("1:c2hvcnQ=")}.source(), []Role{RoleConsole})
	if err == nil || !strings.Contains(err.Error(), "NYKTUS_ENCRYPTION_KEYS: key 1: must be 32 bytes, got 5") {
		t.Errorf("LoadServe() with a short key error = %v", err)
	}

	src := fakeSource{
		env: map[string]string{
			"NYKTUS_ENV": "development", "NYKTUS_CONSOLE_DATABASE_URL": "postgres://console@db/nyktus",
			"NYKTUS_TRIGGER_URL": "http://localhost:8081", "NYKTUS_ENCRYPTION_KEYS_FILE": "/run/secrets/keys",
		},
		files: map[string]string{"/run/secrets/keys": testKeys + "\n"},
	}
	if _, err := LoadServe(src.source(), []Role{RoleConsole}); err != nil {
		t.Errorf("LoadServe() with keys from a file error = %v", err)
	}
	src.files["/run/secrets/keys"] = "1:c2hvcnQ="
	_, err = LoadServe(src.source(), []Role{RoleConsole})
	if err == nil || !strings.Contains(err.Error(), "NYKTUS_ENCRYPTION_KEYS_FILE: key 1: must be 32 bytes") {
		t.Errorf("LoadServe() with a short key from a file error = %v, want it to name the file variable", err)
	}
}

func TestLoadServe_TrustedProxies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value string
		want  []netip.Prefix
		err   string
	}{
		{value: "", want: nil},
		{
			value: "10.0.0.0/8, 192.0.2.7 ,2001:db8::/32",
			want: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("192.0.2.7/32"),
				netip.MustParsePrefix("2001:db8::/32"),
			},
		},
		{value: "10.0.0.1/8", err: `write "10.0.0.0/8"`},
		{value: "::ffff:10.0.0.0/104", err: "IPv4 range in IPv6 notation"},
		{value: "fe80::1%eth0", err: "not an address range"},
		{value: "10.0.0.0/8,", err: `"" is not an address range`},
		{value: "proxy.example.com", err: "not an address range"},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			t.Parallel()

			src := fakeSource{env: map[string]string{"NYKTUS_TRUSTED_PROXIES": tt.value}}
			cfg, err := LoadServe(src.source(), nil)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), "NYKTUS_TRUSTED_PROXIES") || !strings.Contains(err.Error(), tt.err) {
					t.Errorf("LoadServe() error = %v, want it to contain %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadServe() error = %v", err)
			}
			if !slices.Equal(cfg.TrustedProxies, tt.want) {
				t.Errorf("TrustedProxies = %v, want %v", cfg.TrustedProxies, tt.want)
			}
		})
	}
}

func TestLoadAdmin_ReadsTheSettingsOfTheConsole(t *testing.T) {
	t.Parallel()

	src := fakeSource{env: map[string]string{
		"NYKTUS_CONSOLE_DATABASE_URL": "postgres://console@db/nyktus",
		"NYKTUS_CONSOLE_URL":          "https://nyktus.example.com",
		"NYKTUS_DATABASE_URL":         "postgres://owner@db/nyktus",
	}}
	cfg, err := LoadAdmin(src.source())
	if err != nil {
		t.Fatalf("LoadAdmin() error = %v", err)
	}
	if cfg.DatabaseURL.Value() != "postgres://console@db/nyktus" || cfg.ConsoleURL != "https://nyktus.example.com" {
		t.Errorf("LoadAdmin() = %+v, want the database and address of the console", cfg)
	}

	_, err = LoadAdmin(fakeSource{env: map[string]string{"NYKTUS_DATABASE_URL": "postgres://owner@db/nyktus"}}.source())
	for _, want := range []string{"NYKTUS_CONSOLE_URL", "NYKTUS_CONSOLE_DATABASE_URL"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("LoadAdmin() without console settings: error = %v, want it to name %s", err, want)
		}
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

	roles, err := ParseRoles(" console , console")
	if err != nil || !slices.Equal(roles, []Role{RoleConsole}) {
		t.Errorf("ParseRoles() = %v, %v; want deduplicated console role", roles, err)
	}

	roles, err = ParseRoles("dns,trigger,worker")
	if err != nil || !slices.Equal(roles, []Role{RoleDNS, RoleTrigger, RoleWorker}) {
		t.Errorf("ParseRoles() = %v, %v; want dns, trigger and worker", roles, err)
	}

	if _, err := ParseRoles("console,unknown"); err == nil {
		t.Error("ParseRoles() accepted an unknown role")
	}
}

// A process never starts a role that nobody asked for, because some of them
// listen on the internet.
func TestParseRoles_RequiresAList(t *testing.T) {
	t.Parallel()

	for _, s := range []string{"", " ", ","} {
		roles, err := ParseRoles(s)
		if s == "," {
			// An explicit list without names is no request for a role either.
			if err == nil {
				t.Errorf("ParseRoles(%q) = %v, want an error", s, roles)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "console, trigger, dns, worker") {
			t.Errorf("ParseRoles(%q) = %v, %v; want an error that names the roles", s, roles, err)
		}
	}
}

func TestLoadServe_TriggerURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		development bool
		value       string
		want        string
		err         string
	}{
		{name: "https", value: "https://t.example.com", want: "https://t.example.com"},
		{name: "trailing slash", value: "https://t.example.com/", want: "https://t.example.com"},
		{name: "port", value: "https://t.example.com:8443", want: "https://t.example.com:8443"},
		{name: "required in production", err: "NYKTUS_TRIGGER_URL is required"},
		// The console shows the URLs of honeytokens in every environment.
		{name: "required in development", development: true, err: "NYKTUS_TRIGGER_URL is required"},
		{name: "http in production", value: "http://t.example.com", err: "NYKTUS_TRIGGER_URL: must start with https://"},
		{name: "http in development", development: true, value: "http://localhost:8081", want: "http://localhost:8081"},
		{name: "host of the console with another port in development", development: true, value: "https://nyktus.example.com:8443", want: "https://nyktus.example.com:8443"},
		{name: "path", value: "https://t.example.com/t", err: "NYKTUS_TRIGGER_URL: must consist of scheme, host and port only"},
		{name: "query", value: "https://t.example.com?a", err: "NYKTUS_TRIGGER_URL: must consist of scheme, host and port only"},
		{name: "user information", value: "https://u@t.example.com", err: "NYKTUS_TRIGGER_URL: must consist of scheme, host and port only"},
		{name: "address of the console", value: "https://nyktus.example.com/", err: "NYKTUS_TRIGGER_URL: must name another host than NYKTUS_CONSOLE_URL"},
		{name: "host of the console in other case", value: "https://NYKTUS.example.com", err: "must name another host than NYKTUS_CONSOLE_URL"},
		{name: "host of the console with a port", value: "https://nyktus.example.com:8443", err: "must name another host than NYKTUS_CONSOLE_URL"},
		{name: "host of the console with the default port", value: "https://nyktus.example.com:443", err: "must name another host than NYKTUS_CONSOLE_URL"},
		{name: "subdomain of the console", value: "https://t.nyktus.example.com", want: "https://t.nyktus.example.com"},
		{name: "address of the console in development", development: true, value: "https://nyktus.example.com", err: "must name another host than NYKTUS_CONSOLE_URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			env := map[string]string{
				"NYKTUS_CONSOLE_DATABASE_URL": "postgres://console@db/nyktus",
				"NYKTUS_CONSOLE_URL":          "https://nyktus.example.com",
				"NYKTUS_TRIGGER_URL":          tt.value,
				"NYKTUS_ENCRYPTION_KEYS":      testKeys,
			}
			if tt.development {
				env["NYKTUS_ENV"] = "development"
			}
			cfg, err := LoadServe(fakeSource{env: env}.source(), []Role{RoleConsole})
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Errorf("LoadServe() error = %v, want it to contain %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadServe() error = %v", err)
			}
			if cfg.Console.TriggerURL != tt.want {
				t.Errorf("Console.TriggerURL = %q, want %q", cfg.Console.TriggerURL, tt.want)
			}
		})
	}
}

func TestLoadServe_AlertingAllowedNetworks(t *testing.T) {
	t.Parallel()

	env := func(networks string) map[string]string {
		return map[string]string{
			"NYKTUS_ENV":                       "development",
			"NYKTUS_CONSOLE_DATABASE_URL":      "postgres://console@db/nyktus",
			"NYKTUS_TRIGGER_URL":               "https://t.example.com",
			"NYKTUS_ENCRYPTION_KEYS":           testKeys,
			"NYKTUS_ALERTING_ALLOWED_NETWORKS": networks,
		}
	}
	cfg, err := LoadServe(fakeSource{env: env("10.20.0.0/16, fd00:1::/64")}.source(), []Role{RoleConsole})
	if err != nil {
		t.Fatalf("LoadServe() error = %v", err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("fd00:1::/64")}
	if !slices.Equal(cfg.AlertingAllowedNetworks, want) {
		t.Errorf("AlertingAllowedNetworks = %v, want %v", cfg.AlertingAllowedNetworks, want)
	}
	cfg, err = LoadServe(fakeSource{env: env("")}.source(), []Role{RoleConsole})
	if err != nil || cfg.AlertingAllowedNetworks != nil {
		t.Errorf("without the setting: %v, %v; want no networks", cfg.AlertingAllowedNetworks, err)
	}
	_, err = LoadServe(fakeSource{env: env("10.20.0.1/16")}.source(), []Role{RoleConsole})
	if err == nil || !strings.Contains(err.Error(), "NYKTUS_ALERTING_ALLOWED_NETWORKS") {
		t.Errorf("LoadServe() with host bits set error = %v", err)
	}
}
