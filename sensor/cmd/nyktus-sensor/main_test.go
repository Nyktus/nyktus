// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"
)

const (
	secretValue = "Abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"
	idValue     = "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d"
)

func configFile(t *testing.T, listen string, mode os.FileMode) string {
	t.Helper()
	data := "environment: development\ntrigger_url: http://127.0.0.1:1/\nhoneypots:\n  - id: " + idValue +
		"\n    service: telnet\n    listen: \"" + listen + "\"\n    secret: " + secretValue + "\n"
	path := filepath.Join(t.TempDir(), "sensor.yaml")
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func exec(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(t.Context(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRun_Usage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "no command", args: nil, want: exitUsage},
		{name: "an unknown command", args: []string{"serve"}, want: exitUsage},
		{name: "a command without the configuration", args: []string{"check"}, want: exitUsage},
		{name: "run without the configuration", args: []string{"run"}, want: exitUsage},
		{name: "an unknown flag", args: []string{"check", "-config", "x", "-bogus"}, want: exitUsage},
		{name: "an extra argument", args: []string{"check", "-config", "x", "extra"}, want: exitUsage},
		{name: "help", args: []string{"help"}, want: exitOK},
		{name: "help of a command", args: []string{"check", "-h"}, want: exitOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if code, _, _ := exec(t, tt.args...); code != tt.want {
				t.Errorf("exit code = %d, want %d", code, tt.want)
			}
		})
	}
}

func TestRun_Version(t *testing.T) {
	t.Parallel()

	code, stdout, _ := exec(t, "version")
	if code != exitOK || strings.TrimSpace(stdout) == "" {
		t.Errorf("version = %d, %q; want 0 and a version", code, stdout)
	}
}

func TestCheck_ValidConfiguration(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := exec(t, "check", "-config", configFile(t, ":2323", 0o600))
	if code != exitOK || !strings.Contains(stdout, "configuration ok: 1 honeypots") || stderr != "" {
		t.Errorf("check = %d, %q, %q; want 0 and the confirmation", code, stdout, stderr)
	}
}

func TestCheck_InvalidConfiguration_ListsEveryProblemAndFails(t *testing.T) {
	t.Parallel()

	path := configFile(t, "nowhere", 0o644)
	code, stdout, stderr := exec(t, "check", "-config", path)
	if code != exitFailure || stdout != "" {
		t.Errorf("check = %d, %q; want exit code 1 and nothing on standard output", code, stdout)
	}
	for _, want := range []string{"invalid configuration", "honeypots[0].listen", "group or other users can access it"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want it to contain %q", stderr, want)
		}
	}
	if strings.Contains(stderr, secretValue) {
		t.Errorf("stderr holds the secret: %q", stderr)
	}
}

func TestCheck_MissingFile(t *testing.T) {
	t.Parallel()

	if code, _, stderr := exec(t, "check", "-config", filepath.Join(t.TempDir(), "missing.yaml")); code != exitFailure || stderr == "" {
		t.Errorf("check = %d, %q; want exit code 1 and a message", code, stderr)
	}
}

// A sensor that cannot bind a port ends with a failure and says so, and
// nothing keeps running.
func TestRun_PortInUse_FailsLoudly(t *testing.T) {
	t.Parallel()

	busy, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = busy.Close() })

	code, _, stderr := exec(t, "run", "-config", configFile(t, busy.Addr().String(), 0o600))
	if code != exitFailure {
		t.Errorf("run = %d, want exit code 1", code)
	}
	for _, want := range []string{`"level":"ERROR"`, "sensor: failed", idValue, "the sensor did not start"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want it to contain %q", stderr, want)
		}
	}
	if strings.Contains(stderr, secretValue) {
		t.Errorf("stderr holds the secret: %q", stderr)
	}
}

// sshConfigFile writes the configuration of an SSH honeypot whose host key
// file holds key, or none if key is nil.
func sshConfigFile(t *testing.T, key []byte) string {
	t.Helper()
	dir := t.TempDir()
	if key != nil {
		if err := os.WriteFile(filepath.Join(dir, "ssh_host_key"), key, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	data := "environment: development\ntrigger_url: http://127.0.0.1:1/\nhoneypots:\n  - id: " + idValue +
		"\n    service: ssh\n    listen: \":2222\"\n    host_key_file: ssh_host_key\n    secret: " + secretValue + "\n"
	path := filepath.Join(dir, "sensor.yaml")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheck_SSH_ReadsTheHostKey(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := cryptossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := exec(t, "check", "-config", sshConfigFile(t, pem.EncodeToMemory(block)))
	if code != exitOK || !strings.Contains(stdout, "configuration ok: 1 honeypots") || stderr != "" {
		t.Errorf("check = %d, %q, %q; want 0 and the confirmation", code, stdout, stderr)
	}
}

// A host key that is missing or is no key stops the check, and the message
// names the field and not what the file holds.
func TestCheck_SSH_InvalidHostKey_Fails(t *testing.T) {
	t.Parallel()

	for name, key := range map[string][]byte{
		"missing": nil,
		"no key":  []byte("TOPSECRETCONTENT"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			code, _, stderr := exec(t, "check", "-config", sshConfigFile(t, key))
			if code != exitFailure || !strings.Contains(stderr, "honeypots[0].host_key_file") || strings.Contains(stderr, "TOPSECRETCONTENT") {
				t.Errorf("check = %d, %q; want exit code 1 and an error about host_key_file without the content", code, stderr)
			}
		})
	}
}
