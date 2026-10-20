// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"nyktus.org/nyktus/sensor/internal/config"
)

const (
	secretOne = "Abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"
	secretTwo = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	idOne     = "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d"
	idTwo     = "11111111-2222-4333-8444-555555555555"
)

// valid is a configuration that passes; the cases below change one thing.
const valid = `
trigger_url: https://trigger.example.com/
honeypots:
  - id: ` + idOne + `
    service: telnet
    listen: ":2323"
    secret: ` + secretOne + `
`

func TestParse_ValidConfiguration_HasTheDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := config.Parse([]byte(valid))
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	if cfg.Environment != config.Production || cfg.LogLevel != "info" {
		t.Errorf("environment = %q, log level = %q; want production and info", cfg.Environment, cfg.LogLevel)
	}
	hp := cfg.Honeypots[0]
	if hp.ID != idOne || hp.Service != config.Telnet || hp.Listen != ":2323" || string(hp.Secret) != secretOne || hp.Banner != nil || hp.LoginPrompt != nil {
		t.Errorf("honeypot = %+v", hp)
	}
	if cfg.TriggerURL != "https://trigger.example.com/" {
		t.Errorf("TriggerURL = %q", cfg.TriggerURL)
	}
}

// Every case breaks one rule, and the error names that rule.
func TestParse_Invalid_NamesTheRule(t *testing.T) {
	t.Parallel()

	entry := func(extra string) string {
		return valid + extra
	}
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{name: "empty file", yaml: "", want: "empty"},
		{name: "a field that does not exist", yaml: valid + "bogus: 1\n", want: "field bogus not found"},
		{name: "a misspelled key of a honeypot", yaml: entry("    secrett: x\n"), want: "field secrett not found"},
		{name: "two documents", yaml: valid + "---\n" + valid, want: "more than one"},
		{name: "not YAML", yaml: "trigger_url: [", want: "decode configuration"},
		{name: "an unknown environment", yaml: "environment: staging\n" + valid, want: "environment: must be"},
		{name: "no is not an environment", yaml: "environment: no\n" + valid, want: "environment: must be"},
		{name: "an unknown log level", yaml: "log_level: trace\n" + valid, want: "log_level: must be"},
		{name: "no honeypot", yaml: "trigger_url: https://trigger.example.com/\nhoneypots: []\n", want: "at least one honeypot"},
		{name: "a missing trigger URL", yaml: strings.Replace(valid, "trigger_url: https://trigger.example.com/\n", "", 1), want: "trigger_url: required"},
		{name: "http outside development", yaml: strings.Replace(valid, "https://", "http://", 1), want: "https is required"},
		{name: "another scheme", yaml: strings.Replace(valid, "https://", "ftp://", 1), want: "must start with https://"},
		{name: "a URL without a host", yaml: strings.Replace(valid, "https://trigger.example.com/", "https:///", 1), want: "absolute URL"},
		{name: "user information in the URL", yaml: strings.Replace(valid, "https://", "https://user:pw@", 1), want: "no user information"},
		{name: "a query in the URL", yaml: strings.Replace(valid, "example.com/", "example.com/?a=b", 1), want: "no user information, query or fragment"},
		{name: "an empty query in the URL", yaml: strings.Replace(valid, "example.com/", "example.com/?", 1), want: "no user information, query or fragment"},
		{name: "a fragment in the URL", yaml: strings.Replace(valid, "example.com/", "example.com/#a", 1), want: "no user information, query or fragment"},
		{name: "a path in the URL", yaml: strings.Replace(valid, "example.com/", "example.com/nyktus/", 1), want: "reports at / only"},
		{name: "a space in the URL", yaml: strings.Replace(valid, "https://trigger.example.com/", `"https://trigger.example.com/ "`, 1), want: "printable ASCII"},
		{name: "a non-ASCII character in the URL", yaml: strings.Replace(valid, "trigger.example.com", "tr\u00e4gger.example.com", 1), want: "printable ASCII"},
		{name: "a URL that is too long", yaml: strings.Replace(valid, "trigger.example.com", strings.Repeat("a", 600)+".example.com", 1), want: "at most 512"},
		{name: "a missing id", yaml: strings.Replace(valid, "id: "+idOne+"\n    ", "", 1), want: "honeypots[0].id"},
		{name: "an id that is no UUID", yaml: strings.Replace(valid, idOne, "not-a-uuid", 1), want: "honeypots[0].id"},
		{name: "an upper case id", yaml: strings.Replace(valid, idOne, strings.ToUpper(idOne), 1), want: "honeypots[0].id"},
		{name: "a missing service", yaml: strings.Replace(valid, "service: telnet\n    ", "", 1), want: "service: required"},
		{name: "an unknown service", yaml: strings.Replace(valid, "service: telnet", "service: ftp", 1), want: `unknown service "ftp"`},
		{name: "a missing listen address", yaml: strings.Replace(valid, "listen: \":2323\"\n    ", "", 1), want: "listen: must be host:port"},
		{name: "a port without a host and colon", yaml: strings.Replace(valid, `":2323"`, "2323", 1), want: "listen: must be host:port"},
		{name: "a port of 0", yaml: strings.Replace(valid, `":2323"`, `":0"`, 1), want: "port must be a number from 1 to 65535"},
		{name: "a port of 65536", yaml: strings.Replace(valid, `":2323"`, `":65536"`, 1), want: "port must be a number from 1 to 65535"},
		{name: "a port that is a name", yaml: strings.Replace(valid, `":2323"`, `":telnet"`, 1), want: "port must be a number from 1 to 65535"},
		{name: "a host name", yaml: strings.Replace(valid, `":2323"`, `"honeypot.example.com:23"`, 1), want: "host must be an IP address"},
		{name: "no secret", yaml: strings.Replace(valid, "secret: "+secretOne+"\n", "", 1), want: "set secret or secret_file"},
		{name: "a secret and a secret file", yaml: entry("    secret_file: /x\n"), want: "not both"},
		{name: "a secret that is too short", yaml: strings.Replace(valid, secretOne, secretOne[:42], 1), want: "does not have the form of a secret"},
		{name: "a secret of standard base64", yaml: strings.Replace(valid, secretOne, secretOne[:42]+"+", 1), want: "does not have the form of a secret"},
		{name: "the same id twice", yaml: valid + twin(idOne, ":2324", secretTwo), want: "the same id as honeypots[0]"},
		{name: "the same secret twice", yaml: valid + twin(idTwo, ":2324", secretOne), want: "the same secret as honeypots[0]"},
		{name: "the same address twice", yaml: valid + twin(idTwo, ":2323", secretTwo), want: "conflicts with honeypots[0].listen"},
		{name: "a wildcard and an address on the same port", yaml: valid + twin(idTwo, "127.0.0.1:2323", secretTwo), want: "conflicts with honeypots[0].listen"},
		{name: "an address and a wildcard on the same port", yaml: strings.Replace(valid, `":2323"`, `"127.0.0.1:2323"`, 1) + twin(idTwo, "0.0.0.0:2323", secretTwo), want: "conflicts with honeypots[0].listen"},
		{name: "a banner that is too long", yaml: entry("    banner: " + strings.Repeat("a", 257) + "\n"), want: "banner: at most 256"},
		{name: "a banner with an escape", yaml: entry("    banner: \"a\\x1bb\"\n"), want: "banner: printable ASCII"},
		{name: "a banner with a Telnet command", yaml: entry("    banner: \"a\\xFFb\"\n"), want: "banner: printable ASCII"},
		{name: "a banner with DEL", yaml: entry("    banner: \"a\\x7fb\"\n"), want: "banner: printable ASCII"},
		{name: "a banner with NUL", yaml: entry("    banner: \"a\\0b\"\n"), want: "banner: printable ASCII"},
		{name: "a prompt that is too long", yaml: entry("    login_prompt: " + strings.Repeat("a", 65) + "\n"), want: "login_prompt: at most 64"},
		{name: "a prompt with a line break", yaml: entry("    login_prompt: \"a\\r\\nb\"\n"), want: "login_prompt: printable ASCII only"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("Parse() = %+v, want an error containing %q", cfg, tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Parse() error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

// twin is a second honeypot.
func twin(id, listen, secret string) string {
	return "  - id: " + id + "\n    service: telnet\n    listen: \"" + listen + "\"\n    secret: " + secret + "\n"
}

func TestParse_TooManyHoneypots_IsRefused(t *testing.T) {
	t.Parallel()

	var b strings.Builder
	b.WriteString("trigger_url: https://trigger.example.com/\nhoneypots:\n")
	for i := range 33 {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		// 43 characters, a different set for each honeypot.
		secret := strings.Repeat(string(rune('A'+i%26)), 42) + string(rune('a'+i/26))
		b.WriteString(twin(id, "127.0.0.1:"+strconv.Itoa(2000+i), secret))
	}
	if _, err := config.Parse([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "at most 32") {
		t.Errorf("Parse() = %v, want it to refuse 33 honeypots", err)
	}
}

func TestParse_TooLarge_IsRefused(t *testing.T) {
	t.Parallel()

	data := []byte(valid + "# " + strings.Repeat("a", 1<<20) + "\n")
	if _, err := config.Parse(data); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("Parse() = %v, want it to refuse a file beyond 1 MiB", err)
	}
}

func TestParse_Development_AllowsPlainHTTP(t *testing.T) {
	t.Parallel()

	data := "environment: development\n" + strings.Replace(valid, "https://trigger.example.com/", "http://127.0.0.1:8081", 1)
	cfg, err := config.Parse([]byte(data))
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	if cfg.TriggerURL != "http://127.0.0.1:8081/" {
		t.Errorf("TriggerURL = %q, want the address with the path /", cfg.TriggerURL)
	}
}

func TestParse_TriggerURL_IsNormalizedToThePathOfTheTrigger(t *testing.T) {
	t.Parallel()

	cfg, err := config.Parse([]byte(strings.Replace(valid, "https://trigger.example.com/", "https://trigger.example.com:8443", 1)))
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	if cfg.TriggerURL != "https://trigger.example.com:8443/" {
		t.Errorf("TriggerURL = %q, want the path /", cfg.TriggerURL)
	}
}

// YAML 1.1 reads no, yes and off as booleans, and numbers as numbers. The
// fields are text, so they stay what the operator wrote.
func TestParse_Text_StaysText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "no", value: "no", want: "no"},
		{name: "yes", value: "yes", want: "yes"},
		{name: "off", value: "off", want: "off"},
		{name: "a number", value: "123", want: "123"},
		{name: "null", value: "~", want: ""},
		{name: "a quoted line break", value: `"a\r\nb"`, want: "a\r\nb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Parse([]byte(valid + "    banner: " + tt.value + "\n"))
			if err != nil {
				t.Fatalf("Parse() = %v", err)
			}
			got := cfg.Honeypots[0].Banner
			if tt.value == "~" {
				if got != nil {
					t.Errorf("banner = %q, want none", *got)
				}
				return
			}
			if got == nil || *got != tt.want {
				t.Errorf("banner = %v, want %q", got, tt.want)
			}
		})
	}
}

func TestParse_EmptyBanner_IsNoBanner(t *testing.T) {
	t.Parallel()

	cfg, err := config.Parse([]byte(valid + "    banner: \"\"\n"))
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	if b := cfg.Honeypots[0].Banner; b == nil || *b != "" {
		t.Errorf("banner = %v, want an empty banner, which is not the default", b)
	}
}

// An error about a secret does not repeat it.
func TestParse_Error_DoesNotRepeatTheSecret(t *testing.T) {
	t.Parallel()

	bad := secretOne[:42] + "+"
	_, err := config.Parse([]byte(strings.Replace(valid, secretOne, bad, 1)))
	if err == nil || strings.Contains(err.Error(), bad) {
		t.Errorf("Parse() = %v, want an error without the secret", err)
	}
}

func TestParse_ReportsEveryProblem(t *testing.T) {
	t.Parallel()

	_, err := config.Parse([]byte("environment: x\nlog_level: y\n" + valid))
	if err == nil || !strings.Contains(err.Error(), "environment") || !strings.Contains(err.Error(), "log_level") {
		t.Errorf("Parse() = %v, want both problems", err)
	}
}

func write(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile is subject to the umask.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

const withSecretFile = `
trigger_url: https://trigger.example.com/
honeypots:
  - id: ` + idOne + `
    service: telnet
    listen: ":2323"
    secret_file: telnet.secret
`

func TestLoad_SecretFile_IsReadRelativeToTheConfiguration(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, dir, "telnet.secret", secretOne+"\n", 0o600)
	path := write(t, dir, "sensor.yaml", withSecretFile, 0o644)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if got := string(cfg.Honeypots[0].Secret); got != secretOne {
		t.Errorf("secret = %q, want the content of the file without its line break", got)
	}
}

func TestLoad_SecretFile_AbsolutePath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	secretPath := write(t, dir, "elsewhere.secret", secretOne, 0o400)
	path := write(t, dir, "sensor.yaml", strings.Replace(withSecretFile, "telnet.secret", secretPath, 1), 0o644)

	if _, err := config.Load(path); err != nil {
		t.Errorf("Load() = %v", err)
	}
}

func TestLoad_SecretFile_Invalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		mode    os.FileMode
		want    string
	}{
		{name: "readable by the group", content: secretOne, mode: 0o640, want: "other users can read the secret file"},
		{name: "readable by everyone", content: secretOne, mode: 0o644, want: "other users can read the secret file"},
		{name: "writable by the group", content: secretOne, mode: 0o620, want: "other users can read the secret file"},
		{name: "not a secret", content: "not a secret", mode: 0o600, want: "form of a secret"},
		{name: "empty", content: "", mode: 0o600, want: "form of a secret"},
		{name: "two secrets", content: secretOne + "\n" + secretTwo + "\n", mode: 0o600, want: "form of a secret"},
		{name: "far too long", content: strings.Repeat("a", 5000), mode: 0o600, want: "form of a secret"},
		{name: "a secret in a file full of white space", content: secretOne + strings.Repeat(" ", 300), mode: 0o600, want: "form of a secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			write(t, dir, "telnet.secret", tt.content, tt.mode)
			path := write(t, dir, "sensor.yaml", withSecretFile, 0o600)

			_, err := config.Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), "honeypots[0].secret_file") {
				t.Fatalf("Load() = %v, want an error about honeypots[0].secret_file containing %q", err, tt.want)
			}
			// The error does not repeat what the file holds.
			if strings.Contains(err.Error(), secretOne) {
				t.Errorf("Load() = %v, holds the secret", err)
			}
		})
	}
}

func TestLoad_SecretFile_MissingOrNotAFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := write(t, dir, "sensor.yaml", withSecretFile, 0o600)
	if _, err := config.Load(path); err == nil || !strings.Contains(err.Error(), "cannot open the secret file") {
		t.Errorf("Load() = %v, want an error about the missing file", err)
	}

	if err := os.Mkdir(filepath.Join(dir, "telnet.secret"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("Load() = %v, want an error about the directory", err)
	}
}

func TestLoad_ConfigurationWithASecret_IsNotReadableByOthers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode os.FileMode
		ok   bool
	}{
		{name: "owner only", mode: 0o600, ok: true},
		{name: "owner read only", mode: 0o400, ok: true},
		{name: "group", mode: 0o640},
		{name: "everyone", mode: 0o644},
		{name: "group write", mode: 0o620},
		{name: "everyone write", mode: 0o602},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := write(t, t.TempDir(), "sensor.yaml", valid, tt.mode)
			_, err := config.Load(path)
			if tt.ok && err != nil {
				t.Errorf("Load() = %v", err)
			}
			if !tt.ok && (err == nil || !strings.Contains(err.Error(), "other users can read it")) {
				t.Errorf("Load() = %v, want an error about the mode", err)
			}
		})
	}
}

// A configuration with secret files only holds nothing to protect.
func TestLoad_ConfigurationWithoutSecrets_MayBeReadByOthers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, dir, "telnet.secret", secretOne, 0o600)
	path := write(t, dir, "sensor.yaml", withSecretFile, 0o644)
	if _, err := config.Load(path); err != nil {
		t.Errorf("Load() = %v", err)
	}
}

func TestLoad_TwoFilesWithTheSameSecret_AreRefused(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, dir, "telnet.secret", secretOne, 0o600)
	write(t, dir, "other.secret", secretOne, 0o600)
	data := withSecretFile + "  - id: " + idTwo + "\n    service: telnet\n    listen: \":2324\"\n    secret_file: other.secret\n"
	path := write(t, dir, "sensor.yaml", data, 0o600)

	if _, err := config.Load(path); err == nil || !strings.Contains(err.Error(), "the same secret as honeypots[0]") {
		t.Errorf("Load() = %v, want an error about the shared secret", err)
	}
}

func TestLoad_ConfigurationThatIsNotAFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if _, err := config.Load(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("Load(directory) = %v, want an error", err)
	}
	if _, err := config.Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("Load(missing) = nil, want an error")
	}
}

// The file is read up to its limit only.
func TestLoad_FileBeyondTheLimit_IsRefused(t *testing.T) {
	t.Parallel()

	path := write(t, t.TempDir(), "sensor.yaml", valid+"# "+strings.Repeat("a", 2<<20)+"\n", 0o600)
	if _, err := config.Load(path); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("Load() = %v, want an error about the size", err)
	}
}

// The entry that the console shows when it creates a honeypot is a list item
// of this file. The console tests compare what it renders with this file, and
// this test reads the file with the decoder of the sensor.
func TestParse_ConsoleEntry_IsReadBySensor(t *testing.T) {
	t.Parallel()

	entry, err := os.ReadFile("testdata/console_entry.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte("trigger_url: https://trigger.example.com/\nhoneypots:\n" + string(entry)))
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	if len(cfg.Honeypots) != 1 {
		t.Fatalf("%d honeypots, want 1", len(cfg.Honeypots))
	}
	hp := cfg.Honeypots[0]
	if hp.ID != "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d" || hp.Service != config.Telnet || hp.Listen != ":23" ||
		string(hp.Secret) != strings.Repeat("A", 43) {
		t.Errorf("honeypot = %+v, want what the console wrote", hp)
	}
}
