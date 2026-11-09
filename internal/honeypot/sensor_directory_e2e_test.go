// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeypot_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"nyktus.org/nyktus/internal/honeypot"
)

// dial connects to the honeypot the way an attacker does.
func dial(t *testing.T, port int) net.Conn {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	return conn
}

// noPassword fails the test if the password reached the database.
func noPassword(t *testing.T, env *sensorEnv, password string) {
	t.Helper()
	var stored string
	if err := env.owner.QueryRow(t.Context(), `
SELECT coalesce(string_agg(row_to_json(e)::text, ' '), '') || coalesce((SELECT string_agg(row_to_json(a)::text, ' ') FROM event_attempts a), '')
FROM events e`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, password) {
		t.Errorf("the database holds the password: %s", stored)
	}
}

// A PostgreSQL honeypot of the console and a sensor with its entry: a client
// that asks for TLS, names a database and sends a password becomes an event with
// the login, the database and the name of the application, and one that cancels
// is a connection.
//
// It does not run in parallel with the other tests of the sensor: each takes a
// port that it finds free and gives back, which two at the same moment could both
// find.
func TestSensor_PostgreSQL_EndToEnd(t *testing.T) { //nolint:paralleltest // see above.
	env := startEndToEnd(t, honeypot.ServicePostgres, ":5432", false, nil)

	conn := dial(t, env.port)
	message := func(code uint32, body []byte) []byte {
		b := binary.BigEndian.AppendUint32(nil, uint32(8+len(body))) //nolint:gosec // G115: the test messages are small
		b = binary.BigEndian.AppendUint32(b, code)
		return append(b, body...)
	}
	read := func(n int) []byte {
		t.Helper()
		b := make([]byte, n)
		if _, err := io.ReadFull(conn, b); err != nil {
			t.Fatalf("read %d bytes: %v", n, err)
		}
		return b
	}
	if _, err := conn.Write(message(80877103, nil)); err != nil {
		t.Fatal(err)
	}
	if got := read(1); string(got) != "N" {
		t.Fatalf("answer to the request for TLS = %q, want N", got)
	}
	params := "user\x00mallory-typed-this\x00database\x00payroll\x00application_name\x00psql\x00\x00"
	if _, err := conn.Write(message(196608, []byte(params))); err != nil {
		t.Fatal(err)
	}
	if got := read(24); !bytes.Contains(got, []byte("SCRAM-SHA-256")) {
		t.Fatalf("offer = %q, want SCRAM", got)
	}
	sasl := func(body string) []byte {
		b := binary.BigEndian.AppendUint32([]byte{'p'}, uint32(4+len(body))) //nolint:gosec // G115: the test messages are small
		return append(b, body...)
	}
	const clientFirst = "n,,n=,r=abcdefghijklmnop"
	first := "SCRAM-SHA-256\x00" + string(binary.BigEndian.AppendUint32(nil, uint32(len(clientFirst)))) + clientFirst
	if _, err := conn.Write(sasl(first)); err != nil {
		t.Fatal(err)
	}
	challenge := read(5)
	if challenge[0] != 'R' {
		t.Fatalf("message type = %c, want the challenge", challenge[0])
	}
	read(int(binary.BigEndian.Uint32(challenge[1:])) - 4)
	const password = "hunter2-typed-this"
	if _, err := conn.Write(sasl("c=biws,r=abcdefghijklmnopx,p=" + password)); err != nil {
		t.Fatal(err)
	}
	head := read(5)
	if body := read(int(binary.BigEndian.Uint32(head[1:])) - 4); head[0] != 'E' || !bytes.Contains(body, []byte("C28P01\x00")) {
		t.Errorf("answer = %c %q, want the refusal 28P01", head[0], body)
	}

	var eventID string
	eventually(t, "the event of the login", func() bool {
		return env.owner.QueryRow(t.Context(), `SELECT id FROM events WHERE resource_id = $1 AND sensor_event_type = 'login_attempt'`, env.created.ID).Scan(&eventID) == nil
	})
	var (
		service, database, application string
		techniques                     []string
		user                           string
		length                         *int
	)
	if err := env.owner.QueryRow(t.Context(), `SELECT sensor_service, sensor_database, sensor_application_name, techniques FROM events WHERE id = $1`, eventID).
		Scan(&service, &database, &application, &techniques); err != nil {
		t.Fatal(err)
	}
	if service != "postgres" || database != "payroll" || application != "psql" || !slices.Equal(techniques, []string{"T1110"}) {
		t.Errorf("event = %s %q %q %v, want a login attempt at the PostgreSQL honeypot with the database and the application of the client", service, database, application, techniques)
	}
	if err := env.owner.QueryRow(t.Context(), `SELECT username, password_length FROM event_attempts WHERE event_id = $1`, eventID).Scan(&user, &length); err != nil {
		t.Fatal(err)
	}
	if user != "mallory-typed-this" || length != nil {
		t.Errorf("attempt = %q with a password of %v bytes, want the login of the attacker without a length", user, length)
	}

	// A client that cancels is a connection.
	cancel := dial(t, env.port)
	if _, err := cancel.Write(message(80877102, []byte{0, 0, 0, 1, 0, 0, 0, 2})); err != nil {
		t.Fatal(err)
	}
	_ = cancel.Close()
	eventually(t, "the event of the cancel request", func() bool {
		var n int
		err := env.owner.QueryRow(t.Context(), `SELECT count(*) FROM events WHERE resource_id = $1 AND sensor_event_type = 'connection'`, env.created.ID).Scan(&n)
		return err == nil && n == 1
	})
	noPassword(t, env, password)

	if err := env.process.stop(t); err != nil {
		t.Errorf("the sensor ended with %v, want a clean exit", err)
	}
	logs := env.process.log()
	for _, forbidden := range []string{string(env.created.Secret), "mallory-typed-this", password, "payroll"} {
		if strings.Contains(logs, forbidden) {
			t.Errorf("the log of the sensor holds %q:\n%s", forbidden, logs)
		}
	}
}

// ber encodes one element of BER whose content is shorter than 128 bytes.
func ber(tag byte, content ...[]byte) []byte {
	body := bytes.Join(content, nil)
	return append([]byte{tag, byte(len(body))}, body...) //nolint:gosec // G115: the test elements are short.
}

// An LDAP honeypot of the console and a sensor with its entry: a client that
// binds, and then searches, becomes an event of the search with the base and the
// filter and the failed bind as its attempt.
func TestSensor_LDAP_EndToEnd(t *testing.T) { //nolint:paralleltest // see above.
	env := startEndToEnd(t, honeypot.ServiceLDAP, ":389", false, nil)

	conn := dial(t, env.port)
	exchange := func(id byte, op []byte, wantReply []byte) {
		t.Helper()
		if _, err := conn.Write(ber(0x30, ber(0x02, []byte{id}), op)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(wantReply))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(got, wantReply) {
			t.Fatalf("answer = %x, want %x", got, wantReply)
		}
	}
	reply := func(id, op, code byte) []byte {
		return []byte{0x30, 0x0c, 0x02, 0x01, id, op, 0x07, 0x0a, 0x01, code, 0x04, 0x00, 0x04, 0x00}
	}
	password := "hunter2-typed-this"
	dn := "cn=mallory-typed-this,dc=corp,dc=local"
	exchange(1, ber(0x60, ber(0x02, []byte{3}), ber(0x04, []byte(dn)), ber(0x80, []byte(password))), reply(1, 0x61, 49))
	filter := ber(0xa0, ber(0xa3, ber(0x04, []byte("objectClass")), ber(0x04, []byte("user"))), ber(0xa2, ber(0x87, []byte("mail"))))
	search := ber(0x63, ber(0x04, []byte("dc=corp,dc=local")), ber(0x0a, []byte{2}), ber(0x0a, []byte{0}),
		ber(0x02, []byte{0}), ber(0x02, []byte{0}), ber(0x01, []byte{0}), filter, ber(0x30))
	exchange(2, search, reply(2, 0x65, 0))
	if _, err := conn.Write(ber(0x30, ber(0x02, []byte{3}), ber(0x42))); err != nil {
		t.Fatal(err)
	}

	var eventID string
	eventually(t, "the event of the search", func() bool {
		return env.owner.QueryRow(t.Context(), `SELECT id FROM events WHERE resource_id = $1 AND sensor_event_type = 'directory_query'`, env.created.ID).Scan(&eventID) == nil
	})
	var (
		service, base, filterText string
		techniques                []string
		user                      string
		length                    *int
	)
	if err := env.owner.QueryRow(t.Context(), `SELECT sensor_service, sensor_base_dn, sensor_filter, techniques FROM events WHERE id = $1`, eventID).
		Scan(&service, &base, &filterText, &techniques); err != nil {
		t.Fatal(err)
	}
	if service != "ldap" || base != "dc=corp,dc=local" || filterText != "(&(objectClass=user)(!(mail=*)))" || !slices.Equal(techniques, []string{"T1087.002"}) {
		t.Errorf("event = %s %q %q %v, want a directory query at the LDAP honeypot with the base and the filter", service, base, filterText, techniques)
	}
	if err := env.owner.QueryRow(t.Context(), `SELECT username, password_length FROM event_attempts WHERE event_id = $1`, eventID).Scan(&user, &length); err != nil {
		t.Fatal(err)
	}
	if user != dn || length == nil || *length != len(password) {
		t.Errorf("attempt = %q with a password of %v bytes, want the failed bind", user, length)
	}
	noPassword(t, env, password)

	if err := env.process.stop(t); err != nil {
		t.Errorf("the sensor ended with %v, want a clean exit", err)
	}
	logs := env.process.log()
	for _, forbidden := range []string{string(env.created.Secret), "mallory-typed-this", password, "corp"} {
		if strings.Contains(logs, forbidden) {
			t.Errorf("the log of the sensor holds %q:\n%s", forbidden, logs)
		}
	}
}

// An MCP honeypot of the console and a sensor with its entry, filled in: a client
// that lists the tools and calls one becomes one event of the call, with its
// arguments and the technique of the kind of event.
func TestSensor_MCP_EndToEnd(t *testing.T) { //nolint:paralleltest // see above.
	env := startEndToEnd(t, honeypot.ServiceMCP, ":8080", false, func(dir string, _ honeypot.Created) {
		path := filepath.Join(dir, "sensor.yaml")
		data, err := os.ReadFile(path) //nolint:gosec // G304: the path of the test.
		if err != nil {
			t.Fatal(err)
		}
		filled := strings.NewReplacer(`path: ""`, `path: "/mcp"`, `server_name: ""`, `server_name: "acme-wiki"`, `server_version: ""`, `server_version: "3.1"`,
			`- name: ""`, `- name: "get_page"`, `description: ""`, `description: "Read a page."`, `response: ""`, `response: "fixed text"`).Replace(string(data))
		if err := os.WriteFile(path, []byte(filled), 0o600); err != nil { //nolint:gosec // G703: the path of the test.
			t.Fatal(err)
		}
	})

	conn := dial(t, env.port)
	const meta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"Agent","version":"2"},"io.modelcontextprotocol/clientCapabilities":{}}`
	exchange := func(method, name, params, want string) {
		t.Helper()
		body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{` + params + meta + `}}`
		head := "POST /mcp HTTP/1.1\r\nHost: wiki\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: " + method + "\r\n"
		if name != "" {
			head += "Mcp-Name: " + name + "\r\n"
		}
		if _, err := fmt.Fprintf(conn, "%sContent-Length: %d\r\n\r\n%s", head, len(body), body); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil || !bytes.Contains(buf[:n], []byte(want)) {
			t.Fatalf("%s: answer = %q, %v; want %q", method, buf[:n], err, want)
		}
	}
	exchange("tools/list", "", "", "Read a page.")
	exchange("tools/call", "get_page", `"name":"get_page","arguments":{"id":"mallory-typed-this"},`, "fixed text")
	_ = conn.Close()

	if err := env.process.stop(t); err != nil {
		t.Errorf("the sensor ended with %v, want a clean exit", err)
	}
	var eventID string
	eventually(t, "the event of the call", func() bool {
		return env.owner.QueryRow(t.Context(), `SELECT id FROM events WHERE resource_id = $1 AND sensor_event_type = 'tool_call'`, env.created.ID).Scan(&eventID) == nil
	})
	var (
		service, client, severity, tool, args string
		techniques                            []string
	)
	if err := env.owner.QueryRow(t.Context(), `SELECT sensor_service, sensor_client_version, severity, techniques FROM events WHERE id = $1`, eventID).
		Scan(&service, &client, &severity, &techniques); err != nil {
		t.Fatal(err)
	}
	if service != "mcp" || client != "Agent/2" || severity != "medium" || !slices.Equal(techniques, []string{"T1213"}) {
		t.Errorf("event = %s %s %s %v, want a tool call of medium severity with T1213", service, client, severity, techniques)
	}
	if err := env.owner.QueryRow(t.Context(), `SELECT tool_name, arguments_excerpt FROM event_tool_calls WHERE event_id = $1`, eventID).Scan(&tool, &args); err != nil {
		t.Fatal(err)
	}
	if tool != "get_page" || args != `{"id":"mallory-typed-this"}` {
		t.Errorf("tool call = %s %s", tool, args)
	}
	var events int
	if err := env.owner.QueryRow(t.Context(), `SELECT count(*) FROM events WHERE resource_id = $1`, env.created.ID).Scan(&events); err != nil || events != 1 {
		t.Errorf("%d events, %v; want one for the whole session", events, err)
	}
	logs := env.process.log()
	for _, forbidden := range []string{string(env.created.Secret), "mallory-typed-this", "get_page"} {
		if strings.Contains(logs, forbidden) {
			t.Errorf("the log of the sensor holds %q:\n%s", forbidden, logs)
		}
	}
}
