// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sensor_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ber encodes one element of BER whose content is shorter than 128 bytes.
func ber(tag byte, content ...[]byte) []byte {
	body := bytes.Join(content, nil)
	return append([]byte{tag, byte(len(body))}, body...) //nolint:gosec // G115: the test elements are short.
}

func message(id byte, op []byte) []byte { return ber(0x30, ber(0x02, []byte{id}), op) }

func honeypotOf(service string) string {
	return "  - id: " + idOne + "\n    service: " + service + "\n    listen: \"127.0.0.1:1\"\n    secret: " + secretOne + "\n"
}

func TestRun_PostgreSQLSession_IsReportedWithTheLoginAndTheDatabase(t *testing.T) {
	t.Parallel()

	tr := newTrigger(t, false)
	r := start(t, parse(t, tr.URL, honeypotOf("postgres")), nil)
	tr.next(t) // the heartbeat

	c := connect(t, r.addr(idOne))
	params := "user\x00mallory-typed-this\x00database\x00payroll\x00application_name\x00psql\x00\x00"
	startup := append([]byte{0, 0, 0, byte(8 + len(params)), 0, 3, 0, 0}, params...) //nolint:gosec // G115: the test message is short.
	if _, err := c.conn.Write(startup); err != nil {
		t.Fatal(err)
	}
	offer := make([]byte, 24)
	if _, err := io.ReadFull(c.r, offer); err != nil || !bytes.Contains(offer, []byte("SCRAM-SHA-256")) {
		t.Fatalf("offer = %q, %v, want SCRAM", offer, err)
	}
	const clientFirst = "n,,n=,r=abcdefgh"
	mech := "SCRAM-SHA-256\x00\x00\x00\x00" + string([]byte{byte(len(clientFirst))}) + clientFirst
	if _, err := c.conn.Write(append([]byte{'p', 0, 0, 0, byte(4 + len(mech))}, mech...)); err != nil { //nolint:gosec // G115: the test message is small
		t.Fatal(err)
	}
	head := make([]byte, 5)
	if _, err := io.ReadFull(c.r, head); err != nil || head[0] != 'R' {
		t.Fatalf("challenge = %q, %v", head, err)
	}
	if _, err := io.ReadFull(c.r, make([]byte, int(head[4])-4)); err != nil {
		t.Fatal(err)
	}
	final := "c=biws,r=abcdefghx,p=hunter2-typed-this"
	if _, err := c.conn.Write(append([]byte{'p', 0, 0, 0, byte(4 + len(final))}, final...)); err != nil { //nolint:gosec // G115: the test message is small
		t.Fatal(err)
	}
	if _, err := io.ReadAll(c.r); err != nil {
		t.Fatal(err)
	}

	rc := tr.next(t)
	s := decodeSession(t, rc)
	if s.Database != "payroll" || s.ApplicationName != "psql" || len(s.Attempts) != 1 || s.Attempts[0].Username != "mallory-typed-this" ||
		s.Attempts[0].PasswordLength != nil || s.Query != nil {
		t.Errorf("report = %+v, want the login with the database and the application", s)
	}
	if strings.Contains(string(rc.body), "hunter2") {
		t.Errorf("report %s holds the password", rc.body)
	}
	if err := r.stop(); err != nil {
		t.Errorf("Run() = %v", err)
	}
	logs := r.logs.String()
	for _, forbidden := range []string{secretOne, "mallory-typed-this", "hunter2", "payroll", "psql"} {
		if strings.Contains(logs, forbidden) {
			t.Errorf("log holds %q: %s", forbidden, logs)
		}
	}
	for _, want := range []string{`"service":"postgres"`, `"event_type":"login_attempt"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %s: %s", want, logs)
		}
	}
}

func TestRun_LDAPSession_IsReportedWithTheSearch(t *testing.T) {
	t.Parallel()

	tr := newTrigger(t, false)
	r := start(t, parse(t, tr.URL, honeypotOf("ldap")), nil)
	tr.next(t) // the heartbeat

	c := connect(t, r.addr(idOne))
	// An anonymous bind, a search of the root and the unbind.
	script := bytes.Join([][]byte{
		message(1, ber(0x60, ber(0x02, []byte{3}), ber(0x04), ber(0x80))),
		message(2, ber(0x63, ber(0x04), ber(0x0a, []byte{0}), ber(0x0a, []byte{0}), ber(0x02, []byte{0}), ber(0x02, []byte{0}),
			ber(0x01, []byte{0}), ber(0x87, []byte("cnx")), ber(0x30))),
		message(3, ber(0x42)),
	}, nil)
	if _, err := c.conn.Write(script); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(c.r); err != nil {
		t.Fatal(err)
	}

	rc := tr.next(t)
	s := decodeSession(t, rc)
	if s.Query == nil || s.Query.BaseDN != "" || s.Query.Filter != "(cnx=*)" || len(s.Attempts) != 0 {
		t.Errorf("report = %+v, want the search of the root", s)
	}
	if err := r.stop(); err != nil {
		t.Errorf("Run() = %v", err)
	}
	logs := r.logs.String()
	if strings.Contains(logs, "cnx") {
		t.Errorf("log holds the filter: %s", logs)
	}
	for _, want := range []string{`"service":"ldap"`, `"event_type":"directory_query"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %s: %s", want, logs)
		}
	}
}

// A session of an MCP honeypot is reported with its calls, and what the client
// wrote reaches neither the log nor the answer. It ends when the sensor stops.
func TestRun_MCPSession_IsReportedWithItsToolCalls(t *testing.T) {
	t.Parallel()

	tr := newTrigger(t, false)
	entry := honeypotOf("mcp") + `    mcp:
      path: /mcp
      server_name: acme-wiki
      server_version: "3.1"
      tools:
        - {name: get_status, description: Status., response: nominal}
`
	r := start(t, parse(t, tr.URL, entry), nil)
	tr.next(t) // the heartbeat

	const meta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"Agent","version":"2"},"io.modelcontextprotocol/clientCapabilities":{}}`
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_status","arguments":{"q":"mallory-typed-this"},` + meta + `}}`
	c := connect(t, r.addr(idOne))
	c.send(t, "POST /mcp HTTP/1.1\r\nHost: wiki\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: get_status\r\nConnection: close\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
	answer, err := io.ReadAll(c.r)
	if err != nil || !bytes.Contains(answer, []byte("nominal")) || bytes.Contains(answer, []byte("mallory")) {
		t.Fatalf("answer = %q, %v", answer, err)
	}
	if err := r.stop(); err != nil {
		t.Errorf("Run() = %v", err)
	}
	s := decodeSession(t, tr.next(t))
	if len(s.ToolCalls) != 1 || s.ToolCalls[0].ToolName != "get_status" || s.ToolCalls[0].Arguments != `{"q":"mallory-typed-this"}` || s.ClientVersion != "Agent/2" {
		t.Errorf("report = %+v", s)
	}
	for _, want := range []string{`"service":"mcp"`} {
		if !strings.Contains(r.logs.String(), want) {
			t.Errorf("log does not contain %s: %s", want, r.logs)
		}
	}
	if strings.Contains(r.logs.String(), "mallory") || strings.Contains(r.logs.String(), "get_status") {
		t.Errorf("log holds what the client wrote: %s", r.logs)
	}
}

// mcpEntry is an MCP honeypot of one tool, with extra lines for its entry.
func mcpEntry(extra string) string {
	return honeypotOf("mcp") + extra + `    mcp:
      path: /mcp
      server_name: acme-wiki
      server_version: "3.1"
      tools:
        - {name: get_status, description: Status., response: nominal}
`
}

// mcpRequest is a request of a tool list that ends the connection.
func mcpRequest() string {
	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"Probe","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`
	return "POST /mcp HTTP/1.1\r\nHost: wiki\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/list\r\nConnection: close\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

// A session that has gone quiet is reported while the sensor goes on running,
// and not before the minute of silence is over.
func TestRun_MCPSession_EndsWhenItHasGoneQuiet(t *testing.T) {
	t.Parallel()

	tr := newTrigger(t, false)
	r := start(t, parse(t, tr.URL, mcpEntry("")), nil)
	tr.next(t) // the heartbeat

	c := connect(t, r.addr(idOne))
	c.send(t, mcpRequest())
	if _, err := io.ReadAll(c.r); err != nil {
		t.Fatal(err)
	}
	for elapsed := 5 * time.Second; elapsed <= 200*time.Second; elapsed += 5 * time.Second {
		r.clock.Advance(5 * time.Second)
		select {
		case rc := <-tr.requests:
			if !bytes.Contains(rc.body, []byte(`"type":"session"`)) {
				continue
			}
			s := decodeSession(t, rc)
			if elapsed < time.Minute {
				t.Fatalf("reported after %v of silence: %+v", elapsed, s)
			}
			if s.Port == 0 || s.ClientVersion != "Probe/1" || len(s.ToolCalls) != 0 || s.DurationMS != 0 || s.AgeMS < 60_000 {
				t.Errorf("report = %+v, want the listing of a client named Probe/1, reported after a minute of silence that is no part of its duration", s)
			}
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("no session was reported while the sensor ran")
}

// The certificate of the file makes the port of an MCP honeypot speak TLS.
func TestRun_MCPWithACertificate_SpeaksTLS(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600); err != nil {
		t.Fatal(err)
	}
	tr := newTrigger(t, false)
	r := start(t, parse(t, tr.URL, mcpEntry("    tls_cert_file: "+certFile+"\n    tls_key_file: "+keyFile+"\n")), nil)
	tr.next(t) // the heartbeat

	c := connect(t, r.addr(idOne))
	tc := tls.Client(c.conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // G402: the certificate of the test is its own.
	if err := tc.HandshakeContext(t.Context()); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := io.WriteString(tc, mcpRequest()); err != nil {
		t.Fatal(err)
	}
	answer, err := io.ReadAll(tc)
	if err != nil || !bytes.Contains(answer, []byte("get_status")) {
		t.Fatalf("answer = %q, %v", answer, err)
	}
}
