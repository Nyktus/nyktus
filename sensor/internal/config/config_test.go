// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"

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
		{name: "a missing listen address", yaml: strings.Replace(valid, "listen: \":2323\"\n    ", "", 1), want: "listen: must be host:port or :port"},
		{name: "a port without a host and colon", yaml: strings.Replace(valid, `":2323"`, "2323", 1), want: "listen: must be host:port or :port"},
		{name: "a port of 0", yaml: strings.Replace(valid, `":2323"`, `":0"`, 1), want: "a port from 1 to 65535"},
		{name: "a port of 65536", yaml: strings.Replace(valid, `":2323"`, `":65536"`, 1), want: "a port from 1 to 65535"},
		{name: "a port that is a name", yaml: strings.Replace(valid, `":2323"`, `":telnet"`, 1), want: "a port from 1 to 65535"},
		{name: "a port with a sign", yaml: strings.Replace(valid, `":2323"`, `":+2323"`, 1), want: "a port from 1 to 65535"},
		{name: "a port with a leading zero", yaml: strings.Replace(valid, `":2323"`, `":02323"`, 1), want: "a port from 1 to 65535"},
		{name: "a port in hexadecimal", yaml: strings.Replace(valid, `":2323"`, `":0x913"`, 1), want: "a port from 1 to 65535"},
		{name: "a port with a space", yaml: strings.Replace(valid, `":2323"`, `": 2323"`, 1), want: "a port from 1 to 65535"},
		{name: "a host name", yaml: strings.Replace(valid, `":2323"`, `"honeypot.example.com:23"`, 1), want: "an IP address or no host"},
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
		{name: "a prompt for ssh", yaml: sshEntry("    login_prompt: x\n"), want: "login_prompt: only for telnet"},
		{name: "ssh without a host key file", yaml: strings.Replace(sshEntry(""), "    host_key_file: ssh_host_key\n", "", 1), want: "host_key_file: required for ssh"},
		{name: "a host key file for telnet", yaml: entry("    host_key_file: ssh_host_key\n"), want: "host_key_file: only for ssh"},
		{name: "an ssh banner that is no identification", yaml: sshEntry("    banner: OpenSSH_9.2\n"), want: "banner: must be an identification string"},
		{name: "an empty ssh banner", yaml: sshEntry("    banner: \"\"\n"), want: "banner: must be an identification string"},
		{name: "an ssh banner for protocol 1.5", yaml: sshEntry("    banner: SSH-1.5\n"), want: "banner: must be an identification string"},
		{name: "an ssh banner for protocol 1", yaml: sshEntry("    banner: SSH-1.99-OpenSSH_3.9\n"), want: "banner: must be an identification string"},
		{name: "an ssh banner without a software version", yaml: sshEntry("    banner: \"SSH-2.0-\"\n"), want: "banner: must be an identification string"},
		{name: "an ssh banner with a space in the software version", yaml: sshEntry("    banner: \"SSH-2.0- OpenSSH\"\n"), want: "banner: must be an identification string"},
		{name: "an ssh banner with a line break", yaml: sshEntry("    banner: \"SSH-2.0-a\\r\\n\"\n"), want: "banner: must be an identification string"},
		{name: "an ssh banner with a tab", yaml: sshEntry("    banner: \"SSH-2.0-a\\tb\"\n"), want: "banner: must be an identification string"},
		{name: "an ssh banner with a non-ASCII character", yaml: sshEntry("    banner: \"SSH-2.0-a\\u00e9\"\n"), want: "banner: must be an identification string"},
		{name: "an ssh banner that is too long", yaml: sshEntry("    banner: SSH-2.0-" + strings.Repeat("a", 246) + "\n"), want: "banner: must be an identification string"},
		{name: "a banner for postgres", yaml: strings.Replace(valid, "service: telnet", "service: postgres", 1) + "    banner: \"14.13\"\n", want: "banner: only for ssh and telnet"},
		{name: "a banner for ldap", yaml: strings.Replace(valid, "service: telnet", "service: ldap", 1) + "    banner: \"x\"\n", want: "banner: only for ssh and telnet"},
		{name: "an empty banner for ldap", yaml: strings.Replace(valid, "service: telnet", "service: ldap", 1) + "    banner: \"\"\n", want: "banner: only for ssh and telnet"},
		{name: "a prompt for postgres", yaml: strings.Replace(valid, "service: telnet", "service: postgres", 1) + "    login_prompt: x\n", want: "login_prompt: only for telnet"},
		{name: "a host key file for ldap", yaml: strings.Replace(valid, "service: telnet", "service: ldap", 1) + "    host_key_file: ssh_host_key\n", want: "host_key_file: only for ssh"},
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

// sshEntry is an SSH honeypot with the lines of extra added; it passes
// without them.
func sshEntry(extra string) string {
	return "trigger_url: https://trigger.example.com/\nhoneypots:\n  - id: " + idOne +
		"\n    service: ssh\n    listen: \":2222\"\n    secret: " + secretOne + "\n    host_key_file: ssh_host_key\n" + extra
}

// twin is a second honeypot.
func twin(id, listen, secret string) string {
	return "  - id: " + id + "\n    service: telnet\n    listen: \"" + listen + "\"\n    secret: " + secret + "\n"
}

// Two honeypots may share a port only on addresses that cannot meet.
func TestParse_Listen_Conflicts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a, b     string
		conflict bool
	}{
		{name: "the same address", a: "127.0.0.1:2323", b: "127.0.0.1:2323", conflict: true},
		{name: "the same wildcard", a: ":2323", b: ":2323", conflict: true},
		{name: "another port", a: ":2323", b: ":2324"},
		{name: "wildcard and address", a: ":2323", b: "127.0.0.1:2323", conflict: true},
		{name: "address and wildcard", a: "127.0.0.1:2323", b: ":2323", conflict: true},
		{name: "wildcard and IPv6 address", a: ":2323", b: "[::1]:2323", conflict: true},
		{name: "IPv6 wildcard and IPv4 address", a: "[::]:2323", b: "127.0.0.1:2323", conflict: true},
		{name: "IPv4 wildcard and IPv4 address", a: "0.0.0.0:2323", b: "127.0.0.1:2323", conflict: true},
		{name: "IPv4 address and IPv4 wildcard", a: "127.0.0.1:2323", b: "0.0.0.0:2323", conflict: true},
		{name: "IPv4 wildcard and IPv6 address", a: "0.0.0.0:2323", b: "[::1]:2323"},
		{name: "IPv6 address and IPv4 wildcard", a: "[::1]:2323", b: "0.0.0.0:2323"},
		{name: "IPv4 wildcard and IPv6 wildcard", a: "0.0.0.0:2323", b: "[::]:2323", conflict: true},
		{name: "two addresses", a: "127.0.0.1:2323", b: "127.0.0.2:2323"},
		{name: "one IPv6 address written twice", a: "[::1]:2323", b: "[0:0:0:0:0:0:0:1]:2323", conflict: true},
		{name: "IPv4 and the same address mapped into IPv6", a: "127.0.0.1:2323", b: "[::ffff:127.0.0.1]:2323", conflict: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := valid + twin(idTwo, tt.b, secretTwo)
			data = strings.Replace(data, `":2323"`, `"`+tt.a+`"`, 1)
			_, err := config.Parse([]byte(data))
			if got := err != nil && strings.Contains(err.Error(), "conflicts with honeypots[0].listen"); got != tt.conflict {
				t.Errorf("Parse() = %v, want a conflict = %v", err, tt.conflict)
			}
			if !tt.conflict && err != nil {
				t.Errorf("Parse() = %v, want the two honeypots to share the port", err)
			}
		})
	}
}

// The listener takes IPv4 and IPv6 only where the address says so. An IPv4
// address, also 0.0.0.0, is listened on with tcp4, because "tcp" would take IPv6
// for the wildcard too, and then two honeypots on 0.0.0.0 and ::1 could not
// both bind.
func TestHoneypot_Network(t *testing.T) {
	t.Parallel()

	tests := []struct {
		listen string
		want   string
	}{
		{listen: "0.0.0.0:23", want: "tcp4"},
		{listen: "127.0.0.1:23", want: "tcp4"},
		{listen: "[::ffff:127.0.0.1]:23", want: "tcp4"},
		{listen: ":23", want: "tcp"},
		{listen: "[::]:23", want: "tcp"},
		{listen: "[::1]:23", want: "tcp"},
		{listen: "[2001:db8::1]:23", want: "tcp"},
	}
	for _, tt := range tests {
		if got := (config.Honeypot{Listen: tt.listen}).Network(); got != tt.want {
			t.Errorf("Network(%s) = %q, want %q", tt.listen, got, tt.want)
		}
	}
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
		{name: "readable by the group", content: secretOne, mode: 0o640, want: "the group or other users can access the secret file"},
		{name: "readable by everyone", content: secretOne, mode: 0o644, want: "the group or other users can access the secret file"},
		{name: "writable by the group", content: secretOne, mode: 0o620, want: "the group or other users can access the secret file"},
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
			if !tt.ok && (err == nil || !strings.Contains(err.Error(), "group or other users can access it")) {
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

// Secrets that have not been read are not the same secret: two files that
// cannot be read are two problems with two files, not a shared secret.
func TestLoad_SecretFilesThatCannotBeRead_AreNotTakenForTheSameSecret(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	data := withSecretFile + "  - id: " + idTwo + "\n    service: telnet\n    listen: \":2324\"\n    secret_file: other.secret\n"
	path := write(t, dir, "sensor.yaml", data, 0o600)

	_, err := config.Load(path)
	if err == nil || strings.Contains(err.Error(), "the same secret") || !strings.Contains(err.Error(), "honeypots[1].secret_file") {
		t.Errorf("Load() = %v, want one error for each file and none about a shared secret", err)
	}
}

func TestParse_SecretFiles_AreNotTakenForTheSameSecret(t *testing.T) {
	t.Parallel()

	data := withSecretFile + "  - id: " + idTwo + "\n    service: telnet\n    listen: \":2324\"\n    secret_file: other.secret\n"
	if _, err := config.Parse([]byte(data)); err != nil {
		t.Errorf("Parse() = %v, want two honeypots whose secrets are still in their files", err)
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

// The entry that the console shows for the other services has the form of the
// one for Telnet, with the service and the usual port of its own.
func TestParse_ConsoleEntry_OfPostgresAndLDAP_IsReadBySensor(t *testing.T) {
	t.Parallel()

	golden, err := os.ReadFile("testdata/console_entry.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		service config.Service
		port    string
	}{{config.Postgres, ":5432"}, {config.LDAP, ":389"}} {
		entry := strings.NewReplacer(`"telnet"`, strconv.Quote(string(tt.service)), `":23"`, strconv.Quote(tt.port)).Replace(string(golden))
		cfg, err := config.Parse([]byte("trigger_url: https://trigger.example.com/\nhoneypots:\n" + entry))
		if err != nil {
			t.Errorf("%s: Parse() = %v", tt.service, err)
			continue
		}
		if hp := cfg.Honeypots[0]; hp.Service != tt.service || hp.Listen != tt.port || hp.Banner != nil {
			t.Errorf("%s: honeypot = %+v, want the service, its port and no banner", tt.service, hp)
		}
	}
}

func TestParse_SSH_IsValidWithAnyIdentificationString(t *testing.T) {
	t.Parallel()

	for _, banner := range []string{
		"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
		"SSH-2.0-dropbear_2022.83",
		"SSH-2.0-a",
		"SSH-2.0-a b-c d",
		"SSH-2.0-" + strings.Repeat("a", 245),
	} {
		cfg, err := config.Parse([]byte(sshEntry("    banner: " + strconv.Quote(banner) + "\n")))
		if err != nil {
			t.Errorf("Parse(%q) = %v", banner, err)
			continue
		}
		if hp := cfg.Honeypots[0]; hp.Service != config.SSH || hp.HostKeyFile != "ssh_host_key" || hp.Banner == nil || *hp.Banner != banner {
			t.Errorf("honeypot = %+v", hp)
		}
	}
	if _, err := config.Parse([]byte(sshEntry(""))); err != nil {
		t.Errorf("Parse() without a banner = %v, want the default", err)
	}
}

// writeKey writes a private key in the format of ssh-keygen.
func writeKey(t *testing.T, dir, name string, key crypto.PrivateKey, passphrase string, mode os.FileMode) string {
	t.Helper()
	var block *pem.Block
	var err error
	if passphrase == "" {
		block, err = cryptossh.MarshalPrivateKey(key, "")
	} else {
		block, err = cryptossh.MarshalPrivateKeyWithPassphrase(key, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	return write(t, dir, name, string(pem.EncodeToMemory(block)), mode)
}

func ed25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

const withHostKey = `
trigger_url: https://trigger.example.com/
honeypots:
  - id: ` + idOne + `
    service: ssh
    listen: ":2222"
    secret_file: ssh.secret
    host_key_file: ssh_host_key
`

// The key is read from the file, relative to the configuration, and the same
// file gives the same key on every start.
func TestLoad_HostKeyFile_IsReadRelativeToTheConfigurationAndStaysTheSame(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	priv := ed25519Key(t)
	writeKey(t, dir, "ssh_host_key", priv, "", 0o600)
	write(t, dir, "ssh.secret", secretOne, 0o600)
	path := write(t, dir, "sensor.yaml", withHostKey, 0o644)

	want, err := cryptossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("Load() = %v", err)
		}
		got := cfg.Honeypots[0].HostKey
		if got.Signer == nil || !bytes.Equal(got.PublicKey().Marshal(), want.PublicKey().Marshal()) {
			t.Fatalf("host key = %v, want the key of the file on every start", got)
		}
	}
}

func TestLoad_HostKeyFile_AbsolutePath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := writeKey(t, dir, "elsewhere", ed25519Key(t), "", 0o400)
	write(t, dir, "ssh.secret", secretOne, 0o600)
	path := write(t, dir, "sensor.yaml", strings.Replace(withHostKey, "ssh_host_key", keyPath, 1), 0o644)

	if _, err := config.Load(path); err != nil {
		t.Errorf("Load() = %v", err)
	}
}

func TestLoad_HostKeyFile_Invalid(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		write func(t *testing.T, dir string)
		want  string
	}{
		{name: "readable by the group", want: "the group or other users can access the host key file", write: func(t *testing.T, dir string) {
			t.Helper()
			writeKey(t, dir, "ssh_host_key", ed25519Key(t), "", 0o640)
		}},
		{name: "readable by everyone", want: "the group or other users can access the host key file", write: func(t *testing.T, dir string) {
			t.Helper()
			writeKey(t, dir, "ssh_host_key", ed25519Key(t), "", 0o644)
		}},
		{name: "writable by the group", want: "the group or other users can access the host key file", write: func(t *testing.T, dir string) {
			t.Helper()
			writeKey(t, dir, "ssh_host_key", ed25519Key(t), "", 0o620)
		}},
		{name: "missing", want: "cannot open the host key file", write: func(*testing.T, string) {}},
		{name: "a directory", want: "not a regular file", write: func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Mkdir(filepath.Join(dir, "ssh_host_key"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "not a key", want: "does not hold a private key", write: func(t *testing.T, dir string) {
			t.Helper()
			write(t, dir, "ssh_host_key", "not a key\n", 0o600)
		}},
		{name: "empty", want: "does not hold a private key", write: func(t *testing.T, dir string) {
			t.Helper()
			write(t, dir, "ssh_host_key", "", 0o600)
		}},
		{name: "a public key", want: "does not hold a private key", write: func(t *testing.T, dir string) {
			t.Helper()
			pub, err := cryptossh.NewPublicKey(ed25519Key(t).Public())
			if err != nil {
				t.Fatal(err)
			}
			write(t, dir, "ssh_host_key", string(cryptossh.MarshalAuthorizedKey(pub)), 0o600)
		}},
		{name: "a passphrase", want: "protected by a passphrase", write: func(t *testing.T, dir string) {
			t.Helper()
			writeKey(t, dir, "ssh_host_key", ed25519Key(t), "correct horse", 0o600)
		}},
		{name: "an RSA key", want: "the host key is of type ssh-rsa, want ssh-ed25519", write: func(t *testing.T, dir string) {
			t.Helper()
			writeKey(t, dir, "ssh_host_key", rsaKey, "", 0o600)
		}},
		{name: "an ECDSA key", want: "the host key is of type ecdsa-sha2-nistp256, want ssh-ed25519", write: func(t *testing.T, dir string) {
			t.Helper()
			writeKey(t, dir, "ssh_host_key", ecdsaKey, "", 0o600)
		}},
		{name: "far too large", want: "larger than 8192 bytes", write: func(t *testing.T, dir string) {
			t.Helper()
			write(t, dir, "ssh_host_key", strings.Repeat("a", 9000), 0o600)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			tt.write(t, dir)
			write(t, dir, "ssh.secret", secretOne, 0o600)
			path := write(t, dir, "sensor.yaml", withHostKey, 0o644)

			_, err := config.Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), "honeypots[0].host_key_file") {
				t.Fatalf("Load() = %v, want an error about honeypots[0].host_key_file containing %q", err, tt.want)
			}
		})
	}
}

// The error about a key does not repeat what the file holds.
func TestLoad_HostKeyFile_ErrorDoesNotRepeatTheFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, dir, "ssh_host_key", "-----BEGIN OPENSSH PRIVATE KEY-----\nTOPSECRETCONTENT\n-----END OPENSSH PRIVATE KEY-----\n", 0o600)
	write(t, dir, "ssh.secret", secretOne, 0o600)
	path := write(t, dir, "sensor.yaml", withHostKey, 0o644)

	_, err := config.Load(path)
	if err == nil || strings.Contains(err.Error(), "TOPSECRETCONTENT") {
		t.Errorf("Load() = %v, want an error without the content of the file", err)
	}
}

// Two honeypots that show one host key can be tied together by anyone who
// looks, so every SSH honeypot has a key of its own, as it has its own secret.
func TestLoad_TwoHoneypotsWithTheSameHostKey_AreRefused(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	priv := ed25519Key(t)
	writeKey(t, dir, "ssh_host_key", priv, "", 0o600)
	writeKey(t, dir, "copy_of_the_key", priv, "", 0o600)
	writeKey(t, dir, "other_key", ed25519Key(t), "", 0o600)
	write(t, dir, "ssh.secret", secretOne, 0o600)
	write(t, dir, "other.secret", secretTwo, 0o600)
	second := func(keyFile string) string {
		return withHostKey + "  - id: " + idTwo + "\n    service: ssh\n    listen: \":2223\"\n    secret_file: other.secret\n    host_key_file: " + keyFile + "\n"
	}

	// A copy of the file is the same key.
	path := write(t, dir, "sensor.yaml", second("copy_of_the_key"), 0o644)
	_, err := config.Load(path)
	if err == nil || !strings.Contains(err.Error(), "honeypots[1].host_key_file: the same host key as honeypots[0]") {
		t.Errorf("Load() = %v, want an error about the same host key", err)
	}

	path = write(t, dir, "sensor.yaml", second("other_key"), 0o644)
	if _, err := config.Load(path); err != nil {
		t.Errorf("Load() with two keys = %v", err)
	}
}

// Problems of the key and of the secret file are reported together.
func TestLoad_HostKeyFileAndSecretFile_ReportEveryProblem(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := write(t, dir, "sensor.yaml", withHostKey, 0o644)
	_, err := config.Load(path)
	if err == nil || !strings.Contains(err.Error(), "host_key_file") || !strings.Contains(err.Error(), "secret_file") {
		t.Errorf("Load() = %v, want both problems", err)
	}
}

func TestParse_SSHConsoleEntry_IsReadBySensor(t *testing.T) {
	t.Parallel()

	entry, err := os.ReadFile("testdata/console_entry_ssh.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte("trigger_url: https://trigger.example.com/\nhoneypots:\n" + string(entry)))
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	hp := cfg.Honeypots[0]
	if hp.Service != config.SSH || hp.Listen != ":22" || hp.HostKeyFile == "" || string(hp.Secret) != strings.Repeat("A", 43) {
		t.Errorf("honeypot = %+v, want what the console wrote", hp)
	}
}

// A host key file of a honeypot that is not SSH is an error of its own and
// nothing is opened for it.
func TestLoad_HostKeyFileOfAnotherService_IsRefusedWithoutBeingOpened(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	write(t, dir, "telnet.secret", secretOne, 0o600)
	// The file would be refused if it were opened: it is readable by everyone.
	writeKey(t, dir, "ssh_host_key", ed25519Key(t), "", 0o644)
	path := write(t, dir, "sensor.yaml", strings.Replace(withSecretFile, "    secret_file: telnet.secret\n", "    secret_file: telnet.secret\n    host_key_file: ssh_host_key\n", 1), 0o644)

	_, err := config.Load(path)
	if err == nil || !strings.Contains(err.Error(), "host_key_file: only for ssh") || strings.Contains(err.Error(), "can access the host key file") {
		t.Errorf("Load() = %v, want only the error that the field is for ssh", err)
	}
}
