// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sensor_test

import (
	"bytes"
	"io"
	"strings"
	"testing"
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
	got := make([]byte, 9)
	if _, err := io.ReadFull(c.r, got); err != nil || !bytes.Equal(got, []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}) {
		t.Fatalf("request = %q, %v, want the request for a password", got, err)
	}
	password := "hunter2-typed-this"
	pw := append([]byte{'p', 0, 0, 0, byte(5 + len(password))}, password...) //nolint:gosec // G115: the test password is short.
	if _, err := c.conn.Write(append(pw, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(c.r); err != nil {
		t.Fatal(err)
	}

	rc := tr.next(t)
	s := decodeSession(t, rc)
	if s.Database != "payroll" || s.ApplicationName != "psql" || len(s.Attempts) != 1 || s.Attempts[0].Username != "mallory-typed-this" ||
		s.Attempts[0].PasswordLength == nil || *s.Attempts[0].PasswordLength != len(password) || s.Query != nil {
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
