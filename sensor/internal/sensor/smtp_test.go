// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sensor_test

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// smtpEntry is an SMTP honeypot with a certificate for its name in dir.
func smtpEntry(t *testing.T, dir string) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"mail.example.com"}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "smtp.crt"), filepath.Join(dir, "smtp.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600); err != nil {
		t.Fatal(err)
	}
	return honeypotOf("smtp") + "    hostname: mail.example.com\n    tls_mode: starttls\n    tls_cert_file: " + certFile + "\n    tls_key_file: " + keyFile + "\n"
}

// readReply reads a reply of SMTP of one or more lines and returns its last.
func readReply(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("reply: %v", err)
		}
		if len(line) < 4 || line[3] != '-' {
			return strings.TrimRight(line, "\r\n")
		}
	}
}

func TestRun_SMTPSession_IsReportedWithTheLoginInsideTLS(t *testing.T) {
	t.Parallel()

	tr := newTrigger(t, false)
	r := start(t, parse(t, tr.URL, smtpEntry(t, t.TempDir())), nil)
	tr.next(t) // the heartbeat

	c := connect(t, r.addr(idOne))
	say := func(w io.Writer, rd *bufio.Reader, line, want string) {
		t.Helper()
		if _, err := io.WriteString(w, line+"\r\n"); err != nil {
			t.Fatal(err)
		}
		if got := readReply(t, rd); !strings.HasPrefix(got, want) {
			t.Fatalf("%q: reply = %q, want %q", line, got, want)
		}
	}
	if got := readReply(t, c.r); got != "220 mail.example.com ESMTP" {
		t.Fatalf("greeting = %q", got)
	}
	say(c.conn, c.r, "EHLO mallory-host", "250 DSN")
	say(c.conn, c.r, "STARTTLS", "220 2.0.0")
	tc := tls.Client(c.conn, &tls.Config{ServerName: "mail.example.com", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // G402: the certificate of the test is its own.
	if err := tc.HandshakeContext(t.Context()); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	tr2 := bufio.NewReader(tc)
	say(tc, tr2, "EHLO mallory-host", "250 DSN")
	say(tc, tr2, "AUTH PLAIN "+base64.StdEncoding.EncodeToString([]byte("\x00mallory-typed-this\x00hunter2-typed-this")), "535 5.7.8")
	say(tc, tr2, "QUIT", "221")

	s := decodeSession(t, tr.next(t))
	if s.ClientVersion != "mallory-host" || len(s.Attempts) != 1 || s.Attempts[0].Username != "mallory-typed-this" ||
		s.Attempts[0].Password == nil || *s.Attempts[0].Password != "hunter2-typed-this" || s.Port == 0 {
		t.Errorf("report = %+v, want the login with its password and the name of the client", s)
	}
	if err := r.stop(); err != nil {
		t.Errorf("Run() = %v", err)
	}
	logs := r.logs.String()
	for _, forbidden := range []string{secretOne, "mallory", "hunter2"} {
		if strings.Contains(logs, forbidden) {
			t.Errorf("log holds %q: %s", forbidden, logs)
		}
	}
	for _, want := range []string{`"service":"smtp"`, `"event_type":"login_attempt"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %s: %s", want, logs)
		}
	}
}
