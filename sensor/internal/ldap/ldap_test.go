// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ldap_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"nyktus.org/nyktus/sensor/internal/clock/clocktest"
	"nyktus.org/nyktus/sensor/internal/ldap"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/session"
)

// scriptConn is a connection whose client has sent everything in advance: the
// server reads the script and then finds the end of the stream. It records
// what the server writes and the deadlines it sets.
type scriptConn struct {
	mu             sync.Mutex
	input          *bytes.Reader
	read           int
	output         bytes.Buffer
	readDeadlines  []time.Time
	writeDeadlines []time.Time
	failWrites     bool
}

func newScriptConn(script []byte) *scriptConn {
	return &scriptConn{input: bytes.NewReader(script)}
}

func (c *scriptConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.input.Read(p)
	c.read += n
	return n, err
}

func (c *scriptConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failWrites {
		return 0, errors.New("write failed")
	}
	return c.output.Write(p)
}

func (c *scriptConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadlines = append(c.readDeadlines, t)
	return nil
}

func (c *scriptConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadlines = append(c.writeDeadlines, t)
	return nil
}

func (c *scriptConn) SetDeadline(time.Time) error { return nil }
func (c *scriptConn) Close() error                { return nil }
func (c *scriptConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *scriptConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }

func (c *scriptConn) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.output.Bytes()...)
}

const secretValue = "Abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"

// tlv encodes one element of BER with a definite length.
func tlv(tag byte, content ...[]byte) []byte {
	body := bytes.Join(content, nil)
	out := []byte{tag}
	switch n := len(body); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82)
		out = binary.BigEndian.AppendUint16(out, uint16(n)) //nolint:gosec // G115: the test elements are shorter than 64 KiB.
	}
	return append(out, body...)
}

func str(s string) []byte   { return tlv(0x04, []byte(s)) }
func integer(v byte) []byte { return tlv(0x02, []byte{v}) }

// message wraps an operation in an LDAPMessage with the given identifier.
func message(id byte, op []byte) []byte { return tlv(0x30, integer(id), op) }

func bindRequest(name, password string) []byte {
	return tlv(0x60, integer(3), str(name), tlv(0x80, []byte(password)))
}

func saslBind(name, mechanism string) []byte {
	return tlv(0x60, integer(3), str(name), tlv(0xa3, str(mechanism)))
}

func searchRequest(base string, filter []byte) []byte {
	return tlv(0x63, str(base), tlv(0x0a, []byte{2}), tlv(0x0a, []byte{0}), integer(0), integer(0),
		tlv(0x01, []byte{0}), filter, tlv(0x30))
}

func unbind(id byte) []byte { return message(id, tlv(0x42)) }

func equality(attr, value string) []byte { return tlv(0xa3, str(attr), str(value)) }
func present(attr string) []byte         { return tlv(0x87, []byte(attr)) }
func and(f ...[]byte) []byte             { return tlv(0xa0, f...) }
func or(f ...[]byte) []byte              { return tlv(0xa1, f...) }
func not(f []byte) []byte                { return tlv(0xa2, f) }

func substring(attr string, parts ...[]byte) []byte {
	return tlv(0xa4, str(attr), tlv(0x30, parts...))
}

func join(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// reply is the answer of a server to the message with the given identifier: op
// is 0x61 for a bind and 0x65 for a search.
func reply(id byte, op byte, code byte) []byte {
	return []byte{0x30, 0x0c, 0x02, 0x01, id, op, 0x07, 0x0a, 0x01, code, 0x04, 0x00, 0x04, 0x00}
}

var (
	remote = netip.MustParseAddrPort("203.0.113.9:51000")
	local  = netip.MustParseAddrPort("10.0.0.5:389")
)

func start(t *testing.T, clk *clocktest.Fake) *session.Session {
	t.Helper()
	hp := &session.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: "ldap", Secret: secretValue}
	s, err := session.Start(clk, hp, remote, local)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// play runs the honeypot against a client that sends script and returns the
// finished session and the connection.
func play(t *testing.T, script []byte) (*session.Session, *scriptConn) {
	t.Helper()
	clk := clocktest.New()
	conn := newScriptConn(script)
	s := start(t, clk)
	ldap.New(clk).Serve(t.Context(), conn, s)
	s.End()
	return s, conn
}

func sessionReport(t *testing.T, s *session.Session) report.Session {
	t.Helper()
	rep, ok := s.Report(0)
	if !ok {
		t.Fatal("Report() = not ok")
	}
	return rep
}

// login is one attempt of a report: the name and the length of the password.
type login struct {
	user string
	pass int
}

func logins(rep report.Session) []login {
	var out []login
	for _, a := range rep.Attempts {
		n := -1
		if a.PasswordLength != nil {
			n = *a.PasswordLength
		}
		out = append(out, login{a.Username, n})
	}
	return out
}

func TestServe_ScannerDialog_AnonymousBindThenSearchOfTheRoot(t *testing.T) {
	t.Parallel()

	s, conn := play(t, join(
		message(1, bindRequest("", "")),
		message(2, searchRequest("", present("objectClass"))),
		unbind(3)))

	if want := join(reply(1, 0x61, 0), reply(2, 0x65, 0)); !bytes.Equal(conn.written(), want) {
		t.Errorf("written = %x, want the success of the bind and an empty result %x", conn.written(), want)
	}
	rep := sessionReport(t, s)
	if len(rep.Attempts) != 0 {
		t.Errorf("attempts = %+v, want none: an anonymous bind carries no credentials", rep.Attempts)
	}
	if rep.Query == nil || *rep.Query != (report.Query{BaseDN: "", Filter: "(objectClass=*)"}) {
		t.Errorf("query = %+v, want the root with its filter", rep.Query)
	}
	if got := s.EventType(); got != "directory_query" {
		t.Errorf("EventType() = %q, want directory_query", got)
	}
}

func TestServe_Bind_RecordsTheNameAndTheLengthOfThePasswordAndFails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		bind     []byte
		want     []login
		wantCode byte
	}{
		{name: "name and password", bind: bindRequest("cn=admin,dc=example,dc=com", "hunter2"), want: []login{{"cn=admin,dc=example,dc=com", 7}}, wantCode: 49},
		{name: "name without a password", bind: bindRequest("cn=admin,dc=example,dc=com", ""), want: []login{{"cn=admin,dc=example,dc=com", 0}}, wantCode: 49},
		{name: "password without a name", bind: bindRequest("", "secret"), want: []login{{"", 6}}, wantCode: 49},
		{name: "anonymous", bind: bindRequest("", ""), want: nil, wantCode: 0},
		{name: "sasl", bind: saslBind("cn=admin", "GSS-SPNEGO"), want: nil, wantCode: 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, conn := play(t, join(message(1, tt.bind), unbind(2)))
			if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("logins = %+v, want %+v", got, tt.want)
			}
			if want := reply(1, 0x61, tt.wantCode); !bytes.Equal(conn.written(), want) {
				t.Errorf("written = %x, want %x", conn.written(), want)
			}
		})
	}
}

func TestServe_Password_IsNeverKeptOrSentBack(t *testing.T) {
	t.Parallel()

	const pw = "S3cr3t-Passw0rd!"
	s, conn := play(t, join(message(1, bindRequest("cn=admin", pw)), message(2, searchRequest("dc=x", present("cn")))))

	body, err := json.Marshal(sessionReport(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(pw)) || strings.Contains(s.Attr().Value.String(), pw) || bytes.Contains(conn.written(), []byte(pw)) {
		t.Errorf("the password is in the report, the log or the answer")
	}
	if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"cn=admin", len(pw)}}) {
		t.Errorf("logins = %+v, want the length of the password", got)
	}
}

func TestServe_Search_KeepsTheFirstAndAnswersEveryOne(t *testing.T) {
	t.Parallel()

	s, conn := play(t, join(
		message(1, searchRequest("", present("objectClass"))),
		message(2, searchRequest("dc=example,dc=com", equality("sAMAccountName", "admin"))),
		unbind(3)))

	rep := sessionReport(t, s)
	if rep.Query == nil || *rep.Query != (report.Query{BaseDN: "", Filter: "(objectClass=*)"}) {
		t.Errorf("query = %+v, want the first search", rep.Query)
	}
	if want := join(reply(1, 0x65, 0), reply(2, 0x65, 0)); !bytes.Equal(conn.written(), want) {
		t.Errorf("written = %x, want an empty result for each search", conn.written())
	}
}

func TestServe_MoreThanSixBinds_KeepsSixAndAnswersAll(t *testing.T) {
	t.Parallel()

	var script []byte
	var want []byte
	for i := range 8 {
		script = append(script, message(byte(i+1), bindRequest("u"+strconv.Itoa(i), "pw"))...)
		want = append(want, reply(byte(i+1), 0x61, 49)...)
	}
	s, conn := play(t, script)
	if got := len(sessionReport(t, s).Attempts); got != 6 {
		t.Errorf("attempts = %d, want the 6 that a session keeps", got)
	}
	if !bytes.Equal(conn.written(), want) {
		t.Errorf("written = %x, want a failure for each of the eight binds", conn.written())
	}
}

func TestServe_Filters_AreWrittenAsText(t *testing.T) {
	t.Parallel()

	long := make([][]byte, 0, 400)
	for range 400 {
		long = append(long, equality("cn", "abcdefgh"))
	}
	tests := []struct {
		name   string
		filter []byte
		want   string
	}{
		{name: "equality", filter: equality("cn", "admin"), want: "(cn=admin)"},
		{name: "present", filter: present("objectClass"), want: "(objectClass=*)"},
		{name: "and", filter: and(equality("objectClass", "user"), equality("sAMAccountName", "x")), want: "(&(objectClass=user)(sAMAccountName=x))"},
		{name: "or and not", filter: and(equality("a", "b"), or(equality("c", "d"), not(present("e")))), want: "(&(a=b)(|(c=d)(!(e=*))))"},
		{name: "greater", filter: tlv(0xa5, str("uSNChanged"), str("100")), want: "(uSNChanged>=100)"},
		{name: "less", filter: tlv(0xa6, str("uSNChanged"), str("100")), want: "(uSNChanged<=100)"},
		{name: "approximate", filter: tlv(0xa8, str("cn"), str("jon")), want: "(cn~=jon)"},
		{name: "substring with all parts", filter: substring("cn", tlv(0x80, []byte("a")), tlv(0x81, []byte("b")), tlv(0x82, []byte("c"))), want: "(cn=a*b*c)"},
		{name: "substring initial", filter: substring("cn", tlv(0x80, []byte("adm"))), want: "(cn=adm*)"},
		{name: "substring any", filter: substring("cn", tlv(0x81, []byte("dm"))), want: "(cn=*dm*)"},
		{name: "substring final", filter: substring("cn", tlv(0x82, []byte("min"))), want: "(cn=*min)"},
		{name: "extensible match", filter: tlv(0xa9, tlv(0x81, []byte("1.2.840.113556.1.4.803")), tlv(0x82, []byte("userAccountControl")), tlv(0x83, []byte("2"))), want: "(?)"},
		{name: "special characters", filter: equality("cn", "a*b(c)d\\e\x00f\x1f g\x7f"), want: `(cn=a\2ab\28c\29d\5ce\00f\1f g\7f)`},
		{name: "limit reached exactly", filter: and(append(append(long[:3:3], repeat(equality("c", "x"), 43)...), tlv(0xaf))...), want: "(&" + strings.Repeat("(cn=abcdefgh)", 3) + strings.Repeat("(c=x)", 43)},
		{name: "substring beyond the limit is not read", filter: substring("cn", append(repeat(tlv(0x81, []byte("abcdefgh")), 40), tlv(0x83))...), want: ("(cn=" + strings.Repeat("*abcdefgh", 40) + "*)")[:256]},
		{name: "text beyond the limit is not read", filter: and(append(long[:300:300], tlv(0xaf))...), want: ("(&" + strings.Repeat("(cn=abcdefgh)", 300) + ")")[:256]},
		{name: "text that is not ascii", filter: equality("cn", "J\u00fcrgen"), want: "(cn=J\u00fcrgen)"},
		{name: "eight levels", filter: nest(8), want: strings.Repeat("(&", 8) + "(a=b)" + strings.Repeat(")", 8)},
		{name: "cut at the limit of the report", filter: and(long...), want: ("(&" + strings.Repeat("(cn=abcdefgh)", 400) + ")")[:256]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, _ := play(t, message(1, searchRequest("", tt.filter)))
			rep := sessionReport(t, s)
			if rep.Query == nil || rep.Query.Filter != tt.want {
				t.Errorf("filter = %+v, want %q", rep.Query, tt.want)
			}
		})
	}
}

// repeat returns n copies of an element.
func repeat(e []byte, n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = e
	}
	return out
}

// nest builds a filter of n nested conjunctions around an equality.
func nest(n int) []byte {
	f := equality("a", "b")
	for range n {
		f = and(f)
	}
	return f
}

func TestServe_FilterNestedDeeperThanEightLevels_EndsTheSession(t *testing.T) {
	t.Parallel()

	s, conn := play(t, join(message(1, searchRequest("", nest(9))), message(2, searchRequest("", present("x")))))
	if len(conn.written()) != 0 || sessionReport(t, s).Query != nil {
		t.Errorf("written = %x, query = %+v, want the session to end without an answer", conn.written(), sessionReport(t, s).Query)
	}
}

func TestServe_Texts_AreKeptWithinTheLimitsOfTheReport(t *testing.T) {
	t.Parallel()

	s, _ := play(t, join(
		message(1, bindRequest(strings.Repeat("u", 300), "pw")),
		message(2, searchRequest(strings.Repeat("d", 300)+"\xff", present("cn")))))
	if again, _ := play(t, message(1, bindRequest(strings.Repeat("v", 200), "pw"))); logins(sessionReport(t, again))[0].user != strings.Repeat("v", 200) {
		t.Error("a name of 200 bytes, whose length takes two octets, was not read")
	}
	rep := sessionReport(t, s)
	if got := rep.Attempts[0].Username; got != strings.Repeat("u", 256) {
		t.Errorf("username has %d bytes, want 256", len(got))
	}
	if rep.Query.BaseDN != strings.Repeat("d", 256) {
		t.Errorf("base has %d bytes, want 256", len(rep.Query.BaseDN))
	}
}

func TestServe_OperationsThatAreNotOffered_EndTheSessionWithoutAnswer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		op   []byte
	}{
		{name: "start of TLS", op: tlv(0x77, tlv(0x80, []byte("1.3.6.1.4.1.1466.20037")))},
		{name: "modify", op: tlv(0x66, str("cn=x"), tlv(0x30))},
		{name: "add", op: tlv(0x68, str("cn=x"), tlv(0x30))},
		{name: "delete", op: tlv(0x4a, []byte("cn=x"))},
		{name: "compare", op: tlv(0x6e, str("cn=x"), tlv(0x30, str("a"), str("b")))},
		{name: "abandon", op: tlv(0x50, []byte{1})},
		{name: "a response", op: tlv(0x61, tlv(0x0a, []byte{0}))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, conn := play(t, join(message(1, bindRequest("cn=a", "pw")), message(2, tt.op), message(3, bindRequest("cn=b", "pw"))))
			if want := reply(1, 0x61, 49); !bytes.Equal(conn.written(), want) {
				t.Errorf("written = %x, want only the answer to the bind %x", conn.written(), want)
			}
			if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"cn=a", 2}}) {
				t.Errorf("logins = %+v, want what came before", got)
			}
		})
	}
}

func TestServe_Unbind_EndsTheSession(t *testing.T) {
	t.Parallel()

	s, conn := play(t, join(unbind(1), message(2, bindRequest("cn=a", "pw"))))
	if len(conn.written()) != 0 || s.Attempts() != 0 {
		t.Errorf("written = %x, attempts = %d, want nothing after the unbind", conn.written(), s.Attempts())
	}
}

func TestServe_MalformedMessages_EndTheSessionWithoutAnswer(t *testing.T) {
	t.Parallel()

	validBind := message(1, bindRequest("cn=a", "pw"))
	tests := []struct {
		name   string
		script []byte
	}{
		{name: "not a sequence", script: []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")},
		{name: "indefinite length", script: join([]byte{0x30, 0x80}, integer(1), tlv(0x42), []byte{0, 0})},
		{name: "length of three octets", script: join([]byte{0x30, 0x83, 0, 0, 20}, integer(1), tlv(0x42))},
		{name: "length of four octets", script: join([]byte{0x30, 0x84, 0, 0, 0, 20}, integer(1), tlv(0x42))},
		{name: "length beyond the limit", script: join([]byte{0x30, 0x82, 0x20, 0x01}, make([]byte, 9<<10))},
		{name: "huge length", script: join([]byte{0x30, 0x82, 0xff, 0xff}, make([]byte, 9<<10))},
		{name: "identifier without a value", script: tlv(0x30, tlv(0x02), bindRequest("", ""))},
		{name: "identifier of five octets", script: tlv(0x30, tlv(0x02, []byte{1, 2, 3, 4, 5}), bindRequest("", ""))},
		{name: "no operation", script: tlv(0x30, integer(1))},
		{name: "operation longer than the message", script: []byte{0x30, 0x05, 0x02, 0x01, 0x01, 0x60, 0x7f}},
		{name: "indefinite length inside", script: tlv(0x30, integer(1), tlv(0x60, integer(3), str(""), []byte{0x80, 0x80}))},
		{name: "indefinite length outside", script: join([]byte{0x30, 0x80}, integer(1), bindRequest(strings.Repeat("a", 116), ""))},
		{name: "indefinite length inside that could be 128", script: tlv(0x30, integer(1), tlv(0x60, integer(3), join([]byte{0x04, 0x80}, bytes.Repeat([]byte("a"), 128)), tlv(0x80)))},
		{name: "a set instead of a sequence", script: tlv(0x31, integer(1), bindRequest("", ""))},
		{name: "length of three octets inside", script: tlv(0x30, integer(1), []byte{0x60, 0x83, 0x00, 0x09}, integer(3), str("ab"), tlv(0x80))},
		{name: "search with a scope that is no enumeration", script: message(1, tlv(0x63, str(""), str("x"), tlv(0x0a, []byte{0}), integer(0), integer(0), tlv(0x01, []byte{0}), present("a"), tlv(0x30)))},
		{name: "search with a limit that is no integer", script: message(1, tlv(0x63, str(""), tlv(0x0a, []byte{0}), tlv(0x0a, []byte{0}), str("x"), integer(0), tlv(0x01, []byte{0}), present("a"), tlv(0x30)))},
		{name: "search with a type flag that is no boolean", script: message(1, tlv(0x63, str(""), tlv(0x0a, []byte{0}), tlv(0x0a, []byte{0}), integer(0), integer(0), str("x"), present("a"), tlv(0x30)))},
		{name: "search with a base that is no string", script: message(1, tlv(0x63, integer(1), tlv(0x0a, []byte{0}), tlv(0x0a, []byte{0}), integer(0), integer(0), tlv(0x01, []byte{0}), present("a"), tlv(0x30)))},
		{name: "bind with a name that is no string", script: message(1, tlv(0x60, integer(3), integer(1), tlv(0x80, []byte("pw"))))},
		{name: "a message that is no sequence of integer and operation", script: tlv(0x30, str("1"), tlv(0x42))},
		{name: "high tag number", script: tlv(0x30, integer(1), []byte{0x7f, 0x01, 0x00})},
		{name: "bind with a version that is no integer", script: message(1, tlv(0x60, str("x"), str("cn=a"), tlv(0x80, []byte("pw"))))},
		{name: "bind without a version", script: message(1, tlv(0x60, str("cn=a"), tlv(0x80, []byte("pw"))))},
		{name: "bind with other credentials", script: message(1, tlv(0x60, integer(3), str("cn=a"), tlv(0x81, []byte("pw"))))},
		{name: "bind cut short", script: message(1, tlv(0x60, integer(3), str("cn=a")))},
		{name: "search without a filter", script: message(1, tlv(0x63, str(""), tlv(0x0a, []byte{0}), tlv(0x0a, []byte{0}), integer(0), integer(0), tlv(0x01, []byte{0})))},
		{name: "search with a filter of an unknown kind", script: message(1, searchRequest("", tlv(0xaf, str("a"))))},
		{name: "filter with a high tag number", script: message(1, searchRequest("", []byte{0x7f, 0x01, 0x00}))},
		{name: "not with two filters", script: message(1, searchRequest("", tlv(0xa2, present("a"), present("b"))))},
		{name: "equality without a value", script: message(1, searchRequest("", tlv(0xa3, str("a"))))},
		{name: "substring of an unknown kind", script: message(1, searchRequest("", substring("cn", tlv(0x83, []byte("a")))))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, conn := play(t, join(tt.script, validBind))
			if len(conn.written()) != 0 {
				t.Errorf("written = %x, want nothing", conn.written())
			}
			if s.Attempts() != 0 || sessionReport(t, s).Query != nil {
				t.Errorf("recorded something from a message that cannot be read")
			}
		})
	}
}

func TestServe_MessageOfTheLongestSize_IsReadAndOneByteMoreIsNot(t *testing.T) {
	t.Parallel()

	// A search whose base fills the message up to the limit.
	build := func(total int) []byte {
		f := present("cn")
		for pad := 0; ; pad++ {
			m := message(1, searchRequest(strings.Repeat("d", pad), f))
			if len(m) >= total+4 { // the header of the outer sequence has four octets
				return m
			}
		}
	}
	exact := build(8 << 10)
	if got := len(exact) - 4; got != 8<<10 {
		t.Fatalf("the test message has %d bytes of content, want exactly 8192", got)
	}
	s, _ := play(t, exact)
	if sessionReport(t, s).Query == nil {
		t.Error("a message of 8192 bytes was refused")
	}
	over := build(8<<10 + 1)
	s, conn := play(t, over)
	if sessionReport(t, s).Query != nil {
		t.Error("a message of 8193 bytes was read")
	}
	if conn.read > 4096 {
		t.Errorf("read %d bytes of a message that is refused by its header, want no more than the one buffer", conn.read)
	}
}

func TestServe_EveryPrefixOfADialog_EndsWithoutPanicAndKeepsWhatWasRead(t *testing.T) {
	t.Parallel()

	script := join(
		message(1, bindRequest("cn=admin,dc=example,dc=com", "hunter2")),
		message(2, searchRequest("dc=example,dc=com", and(equality("objectClass", "user"), not(present("mail"))))),
		unbind(3))
	for n := range script {
		s, conn := play(t, script[:n])
		rep := sessionReport(t, s)
		if _, err := json.Marshal(rep); err != nil {
			t.Fatalf("prefix %d: %v", n, err)
		}
		if conn.read > n {
			t.Errorf("prefix %d: read %d bytes", n, conn.read)
		}
	}
}

func TestServe_MoreThan16KiB_EndsTheSession(t *testing.T) {
	t.Parallel()

	var script []byte
	for range 2000 {
		script = append(script, message(1, bindRequest("", ""))...)
	}
	_, conn := play(t, script)
	if conn.read != 16<<10 {
		t.Errorf("read %d bytes, want exactly the 16 KiB that a connection may send", conn.read)
	}
	if len(conn.written()) == 0 || len(conn.written()) > conn.read {
		t.Errorf("wrote %d bytes for %d read, want an answer of the same order of size", len(conn.written()), conn.read)
	}
}

func TestServe_BindRecorded_WhenTheAnswerCannotBeWritten(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := newScriptConn(message(1, bindRequest("cn=admin", "pw")))
	conn.failWrites = true
	s := start(t, clk)
	ldap.New(clk).Serve(t.Context(), conn, s)
	s.End()
	if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"cn=admin", 2}}) {
		t.Errorf("logins = %+v, want the bind", got)
	}
}

func TestServe_AnswerThatCannotBeWritten_EndsTheSession(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := newScriptConn(join(message(1, bindRequest("cn=a", "pw")), message(2, bindRequest("cn=b", "pw"))))
	conn.failWrites = true
	s := start(t, clk)
	ldap.New(clk).Serve(t.Context(), conn, s)
	s.End()
	if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"cn=a", 2}}) {
		t.Errorf("logins = %+v, want only the bind whose answer failed", got)
	}
}

func TestServe_CanceledContext_ReadsAndWritesNothing(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := newScriptConn(message(1, bindRequest("cn=admin", "pw")))
	s := start(t, clk)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	ldap.New(clk).Serve(ctx, conn, s)
	s.End()
	if conn.read != 0 || len(conn.written()) != 0 || s.Attempts() != 0 {
		t.Errorf("read %d bytes, wrote %x, recorded %d logins, want none", conn.read, conn.written(), s.Attempts())
	}
}

func TestServe_Deadlines_AreThirtySecondsToReadAndTenToWrite(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := newScriptConn(join(message(1, bindRequest("cn=a", "pw")), unbind(2)))
	s := start(t, clk)
	ldap.New(clk).Serve(t.Context(), conn, s)

	if len(conn.readDeadlines) == 0 || len(conn.writeDeadlines) == 0 {
		t.Fatalf("deadlines set: %d for reads, %d for writes", len(conn.readDeadlines), len(conn.writeDeadlines))
	}
	for _, d := range conn.readDeadlines {
		if want := clk.Deadline(30 * time.Second); !d.Equal(want) {
			t.Errorf("read deadline = %v, want %v", d, want)
		}
	}
	for _, d := range conn.writeDeadlines {
		if want := clk.Deadline(10 * time.Second); !d.Equal(want) {
			t.Errorf("write deadline = %v, want %v", d, want)
		}
	}
}

// The report of a dialog has the form of the file that the server decodes.
func TestServe_Report_HasTheFormOfTheGoldenFile(t *testing.T) {
	t.Parallel()

	golden, err := fs.ReadFile(os.DirFS("../report/testdata"), "session_ldap.json")
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(golden, &want); err != nil {
		t.Fatal(err)
	}

	clk := clocktest.New()
	hp := &session.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: "ldap", Secret: secretValue}
	s, err := session.Start(clk, hp, netip.MustParseAddrPort("198.51.100.23:51000"), netip.MustParseAddrPort("10.0.0.5:389"))
	if err != nil {
		t.Fatal(err)
	}
	ldap.New(clk).Serve(t.Context(), newScriptConn(join(
		message(1, bindRequest("cn=admin,dc=example,dc=com", "")),
		message(2, searchRequest("dc=example,dc=com", present("objectClass"))))), s)
	s.End()

	body, err := json.Marshal(sessionReport(t, s))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	// The identifier is random and the times are measured.
	for _, k := range []string{"session_id", "age_ms", "duration_ms"} {
		got[k] = want[k]
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("report = %s\nwant the form of %s", body, golden)
	}
}

// A client that waits for each answer gets the dialog of a server on a real
// connection, and the answers are framed so that it can read them.
func TestServe_Dialog_WithAClientThatWaitsForTheAnswers(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	client, server := net.Pipe()
	s := start(t, clk)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = server.Close() }()
		ldap.New(clk).Serve(t.Context(), server, s)
	}()

	exchange := func(request, want []byte) {
		t.Helper()
		if _, err := client.Write(request); err != nil {
			t.Fatalf("write: %v", err)
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(client, got); err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("answer = %x, want %x", got, want)
		}
	}
	exchange(message(1, bindRequest("cn=admin", "hunter2")), reply(1, 0x61, 49))
	exchange(message(2, bindRequest("", "")), reply(2, 0x61, 0))
	exchange(message(3, searchRequest("dc=x", present("cn"))), reply(3, 0x65, 0))
	if _, err := client.Write(unbind(4)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Error("the server still answers after the unbind")
	}
	_ = client.Close()
	<-done
	if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"cn=admin", 7}}) {
		t.Errorf("logins = %+v, want the failed bind", got)
	}
}

func TestNew_WithoutAClock_Panics(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("New(nil) did not panic")
		}
	}()
	ldap.New(nil)
}

// FuzzServe feeds the honeypot with bytes of a client. It must never panic,
// never read more than a connection may send, never answer more than it was
// asked, and only record texts that the server accepts.
func FuzzServe(f *testing.F) {
	f.Add(join(message(1, bindRequest("cn=admin,dc=example,dc=com", "pw")), message(2, searchRequest("dc=example,dc=com", and(equality("a", "b"), or(present("c"), not(substring("d", tlv(0x80, []byte("e")))))))), unbind(3)))
	f.Add(join(message(1, bindRequest("", "")), message(2, searchRequest("", present("objectClass")))))
	f.Add(message(1, saslBind("cn=a", "GSS-SPNEGO")))
	f.Add(message(1, searchRequest("", tlv(0xa9, tlv(0x82, []byte("userAccountControl"))))))
	f.Add(message(1, searchRequest("", nest(9))))
	f.Add([]byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x42, 0x00, 0x00, 0x00})
	f.Add([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))

	f.Fuzz(func(t *testing.T, script []byte) {
		clk := clocktest.New()
		conn := newScriptConn(script)
		s := start(t, clk)
		ldap.New(clk).Serve(t.Context(), conn, s)
		s.End()

		if conn.read > 16<<10 {
			t.Fatalf("read %d bytes", conn.read)
		}
		if len(conn.written()) > conn.read {
			t.Fatalf("wrote %d bytes for %d read", len(conn.written()), conn.read)
		}
		rep := sessionReport(t, s)
		if _, err := json.Marshal(rep); err != nil {
			t.Fatal(err)
		}
		if len(rep.Attempts) > 6 {
			t.Fatalf("%d attempts", len(rep.Attempts))
		}
		for _, a := range rep.Attempts {
			if len(a.Username) > report.MaxUsername || !utf8.ValidString(a.Username) {
				t.Fatalf("username %q", a.Username)
			}
		}
		if q := rep.Query; q != nil {
			if len(q.BaseDN) > report.MaxBaseDN || len(q.Filter) > report.MaxFilter || !utf8.ValidString(q.BaseDN) || !utf8.ValidString(q.Filter) {
				t.Fatalf("query %q %q", q.BaseDN, q.Filter)
			}
		}
	})
}
