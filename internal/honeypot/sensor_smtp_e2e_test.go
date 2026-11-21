// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeypot_test

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
	"slices"
	"strings"
	"testing"
	"time"

	"nyktus.org/nyktus/internal/honeypot"
)

// writeMailCertificate writes the certificate of the server and its key, as
// the operator provides them, next to the configuration of the sensor, and
// returns the certificate.
func writeMailCertificate(t *testing.T, dir, name string) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{name}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "smtp.crt"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "smtp.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPEM
}

// An SMTP honeypot of the console and a sensor with its entry, filled in: a
// client that signs in after STARTTLS becomes one event of the login, with
// the password in the column of its attempt and the name that it gave in EHLO.
func TestSensor_SMTP_EndToEnd(t *testing.T) { //nolint:paralleltest // see above.
	pool := x509.NewCertPool()
	env := startEndToEnd(t, honeypot.ServiceSMTP, ":587", false, func(dir string, _ honeypot.Created) {
		pool.AppendCertsFromPEM(writeMailCertificate(t, dir, "mail.example.com"))
		path := filepath.Join(dir, "sensor.yaml")
		data, err := os.ReadFile(path) //nolint:gosec // G304: the path of the test.
		if err != nil {
			t.Fatal(err)
		}
		filled := strings.NewReplacer(`hostname: ""`, `hostname: "mail.example.com"`, `tls_mode: ""`, `tls_mode: "starttls"`,
			`tls_cert_file: ""`, `tls_cert_file: "smtp.crt"`, `tls_key_file: ""`, `tls_key_file: "smtp.key"`).Replace(string(data))
		if err := os.WriteFile(path, []byte(filled), 0o600); err != nil { //nolint:gosec // G703: the path of the test.
			t.Fatal(err)
		}
	})

	conn := dial(t, env.port)
	var (
		w io.Writer = conn
		r           = bufio.NewReader(conn)
	)
	// reply reads a reply of one or more lines and returns its last line.
	reply := func() string {
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
	say := func(line, want string) {
		t.Helper()
		if _, err := io.WriteString(w, line+"\r\n"); err != nil {
			t.Fatal(err)
		}
		if got := reply(); !strings.HasPrefix(got, want) {
			t.Fatalf("%q: reply = %q, want %q", line, got, want)
		}
	}
	if got := reply(); got != "220 mail.example.com ESMTP" {
		t.Fatalf("greeting = %q", got)
	}
	say("EHLO mallory-host", "250 DSN")
	say("STARTTLS", "220 2.0.0")
	tc := tls.Client(conn, &tls.Config{RootCAs: pool, ServerName: "mail.example.com", MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(t.Context()); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	w, r = tc, bufio.NewReader(tc)
	say("EHLO mallory-host", "250 DSN")
	say("AUTH PLAIN "+base64.StdEncoding.EncodeToString([]byte("\x00mallory-typed-this\x00hunter2-typed-this")), "535 5.7.8")
	say("QUIT", "221")
	_ = conn.Close()

	if err := env.process.stop(t); err != nil {
		t.Errorf("the sensor ended with %v, want a clean exit", err)
	}
	var eventID string
	eventually(t, "the event of the login", func() bool {
		return env.owner.QueryRow(t.Context(), `SELECT id FROM events WHERE resource_id = $1 AND sensor_event_type = 'login_attempt'`, env.created.ID).Scan(&eventID) == nil
	})
	var (
		service, client, user string
		password              *string
		techniques            []string
	)
	if err := env.owner.QueryRow(t.Context(), `SELECT sensor_service, sensor_client_version, techniques FROM events WHERE id = $1`, eventID).
		Scan(&service, &client, &techniques); err != nil {
		t.Fatal(err)
	}
	if service != "smtp" || client != "mallory-host" || !slices.Equal(techniques, []string{"T1110"}) {
		t.Errorf("event = %s %s %v, want a login at the smtp honeypot with T1110", service, client, techniques)
	}
	if err := env.owner.QueryRow(t.Context(), `SELECT username, password FROM event_attempts WHERE event_id = $1`, eventID).Scan(&user, &password); err != nil {
		t.Fatal(err)
	}
	if user != "mallory-typed-this" || password == nil || *password != "hunter2-typed-this" {
		t.Errorf("attempt = %q with the password %v, want the login of the attacker with its password", user, password)
	}
	logs := env.process.log()
	for _, forbidden := range []string{string(env.created.Secret), "mallory", "hunter2"} {
		if strings.Contains(logs, forbidden) {
			t.Errorf("the log of the sensor holds %q:\n%s", forbidden, logs)
		}
	}
}
