// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sensor_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

// sshHoneypot returns the entry of an SSH honeypot whose key is in a file that
// the test writes, and the key.
func sshHoneypot(t *testing.T, extra string) (string, cryptossh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := cryptossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ssh_host_key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return "  - id: " + idOne + "\n    service: ssh\n    listen: \"127.0.0.1:2222\"\n    secret: " + secretOne +
		"\n    host_key_file: " + strconv.Quote(path) + "\n" + extra, signer
}

// sshLogin connects like an SSH client and returns the host key it was shown
// and the error of the login, which is always one.
func sshLogin(t *testing.T, addr, user, password string) (cryptossh.PublicKey, error) {
	t.Helper()
	var seen cryptossh.PublicKey
	conn, err := (&net.Dialer{Timeout: deadline}).DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck // nothing to do about a failed close in a test.
	_ = conn.SetDeadline(time.Now().Add(deadline))
	_, _, _, err = cryptossh.NewClientConn(conn, addr, &cryptossh.ClientConfig{
		User: user,
		Auth: []cryptossh.AuthMethod{cryptossh.Password(password)},
		HostKeyCallback: func(_ string, _ net.Addr, k cryptossh.PublicKey) error {
			seen = k
			return nil
		},
		ClientVersion: "SSH-2.0-OpenSSH_9.6",
	})
	return seen, err
}

func TestRun_SSHSession_IsReportedWithItsAttemptsAndTheVersionOfTheClient(t *testing.T) {
	t.Parallel()

	tr := newTrigger(t, false)
	entry, key := sshHoneypot(t, "")
	r := start(t, parse(t, tr.URL, entry), nil)
	tr.next(t) // the heartbeat

	seen, err := sshLogin(t, r.addr(idOne), "mallory-typed-this", "hunter2-typed-this")
	if err == nil {
		t.Fatal("the login succeeded, want it refused")
	}
	if seen == nil || !bytes.Equal(seen.Marshal(), key.PublicKey().Marshal()) {
		t.Errorf("host key = %v, want the key of the file", seen)
	}

	rc := tr.next(t)
	s := decodeSession(t, rc)
	_, port, _ := net.SplitHostPort(r.addr(idOne))
	if rc.authorization != "Bearer "+secretOne || s.Type != "session" || s.ClientIP != "127.0.0.1" || strconv.Itoa(s.Port) != port ||
		s.ClientVersion != "SSH-2.0-OpenSSH_9.6" || len(s.Attempts) != 1 || s.Attempts[0].Username != "mallory-typed-this" ||
		s.Attempts[0].PasswordLength == nil || *s.Attempts[0].PasswordLength != 18 {
		t.Errorf("report = %+v (%s), want the session with one login and the version of the client", s, rc.authorization)
	}
	if strings.Contains(string(rc.body), "hunter2") {
		t.Errorf("report %s holds the password", rc.body)
	}
	if err := r.stop(); err != nil {
		t.Errorf("Run() = %v", err)
	}
	logs := r.logs.String()
	for _, forbidden := range []string{secretOne, "mallory-typed-this", "hunter2", "OpenSSH_9.6"} {
		if strings.Contains(logs, forbidden) {
			t.Errorf("log holds %q: %s", forbidden, logs)
		}
	}
	for _, want := range []string{`"service":"ssh"`, `"event_type":"login_attempt"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %s: %s", want, logs)
		}
	}
}

func TestRun_SSHHostKey_IsTheSameAfterARestart(t *testing.T) {
	t.Parallel()

	tr := newTrigger(t, false)
	entry, _ := sshHoneypot(t, "")
	var keys [][]byte
	for range 2 {
		r := start(t, parse(t, tr.URL, entry), nil)
		seen, _ := sshLogin(t, r.addr(idOne), "root", "x")
		if seen == nil {
			t.Fatal("the honeypot showed no host key")
		}
		keys = append(keys, seen.Marshal())
		if err := r.stop(); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(keys[0], keys[1]) {
		t.Error("the host key changed with the restart: it would identify the honeypot")
	}
}

func TestRun_SSHBanner_IsTheVersionOfTheConfiguration(t *testing.T) {
	t.Parallel()

	tr := newTrigger(t, false)
	entry, _ := sshHoneypot(t, "    banner: \"SSH-2.0-dropbear_2022.83\"\n")
	r := start(t, parse(t, tr.URL, entry), nil)
	c := connect(t, r.addr(idOne))
	line, err := c.r.ReadString('\n')
	if err != nil || line != "SSH-2.0-dropbear_2022.83\r\n" {
		t.Errorf("first line = %q, %v, want the configured version", line, err)
	}
}

func TestRun_SSHDefaultBanner_IsAnOpenSSH(t *testing.T) {
	t.Parallel()

	tr := newTrigger(t, false)
	entry, _ := sshHoneypot(t, "")
	r := start(t, parse(t, tr.URL, entry), nil)
	c := connect(t, r.addr(idOne))
	line, err := c.r.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "SSH-2.0-OpenSSH_") {
		t.Errorf("first line = %q, %v, want the version of an OpenSSH", line, err)
	}
}
