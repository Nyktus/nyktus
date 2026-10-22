// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres_test

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
	"nyktus.org/nyktus/sensor/internal/postgres"
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

// What the client sends, as libpq sends it.
const protocol30 = 196608

func packet(code uint32, body ...byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(8+len(body))) //nolint:gosec // G115: the test messages are small
	b = binary.BigEndian.AppendUint32(b, code)
	return append(b, body...)
}

var (
	sslRequest    = packet(80877103)
	gssRequest    = packet(80877104)
	cancelRequest = packet(80877102, 0, 0, 0, 1, 0, 0, 0, 2)
)

// startupMessage builds a startup message of protocol 3.0 from names and
// values.
func startupMessage(params ...string) []byte {
	var body []byte
	for _, p := range params {
		body = append(body, p...)
		body = append(body, 0)
	}
	body = append(body, 0)
	return packet(protocol30, body...)
}

// passwordMessage builds the message with a password.
func passwordMessage(pw string) []byte {
	b := []byte{'p'}
	b = binary.BigEndian.AppendUint32(b, uint32(5+len(pw))) //nolint:gosec // G115: the test passwords are small
	b = append(b, pw...)
	return append(b, 0)
}

func join(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

var (
	authRequest = []byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}
	remote      = netip.MustParseAddrPort("203.0.113.9:51000")
	local       = netip.MustParseAddrPort("10.0.0.5:5432")
)

func start(t *testing.T, clk *clocktest.Fake) *session.Session {
	t.Helper()
	hp := &session.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: "postgres", Secret: secretValue}
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
	postgres.New(clk).Serve(t.Context(), conn, s)
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

// login is one attempt of a report: the name and the length of the password,
// with -1 for none.
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

// refusal is what a server sends for a wrong password.
func refusal(user string) []byte {
	var fields []byte
	for _, f := range []string{"SFATAL", "VFATAL", "C28P01", `Mpassword authentication failed for user "` + user + `"`} {
		fields = append(fields, f...)
		fields = append(fields, 0)
	}
	fields = append(fields, 0)
	b := []byte{'E'}
	b = binary.BigEndian.AppendUint32(b, uint32(4+len(fields))) //nolint:gosec // G115: the test message is small
	return append(b, fields...)
}

func TestServe_Login_RecordsTheUserTheDatabaseAndThePasswordLength(t *testing.T) {
	t.Parallel()

	s, conn := play(t, join(
		startupMessage("user", "postgres", "database", "app", "application_name", "psql", "client_encoding", "UTF8"),
		passwordMessage("hunter2")))

	rep := sessionReport(t, s)
	if got := logins(rep); !reflect.DeepEqual(got, []login{{"postgres", 7}}) {
		t.Errorf("logins = %+v, want postgres with a password of 7 bytes", got)
	}
	if rep.Database != "app" || rep.ApplicationName != "psql" {
		t.Errorf("database = %q, application name = %q, want app and psql", rep.Database, rep.ApplicationName)
	}
	if want := join(authRequest, refusal("postgres")); !bytes.Equal(conn.written(), want) {
		t.Errorf("written = %q, want the request for a password and the refusal %q", conn.written(), want)
	}
	if got := s.EventType(); got != "login_attempt" {
		t.Errorf("EventType() = %q, want login_attempt", got)
	}
}

func TestServe_Password_IsNeverKeptOrSentBack(t *testing.T) {
	t.Parallel()

	const pw = "S3cr3t-Passw0rd!"
	s, conn := play(t, join(startupMessage("user", "root"), passwordMessage(pw)))

	body, err := json.Marshal(sessionReport(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(pw)) || strings.Contains(s.Attr().Value.String(), pw) || bytes.Contains(conn.written(), []byte(pw)) {
		t.Errorf("the password is in the report, the log or the answer")
	}
	if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"root", len(pw)}}) {
		t.Errorf("logins = %+v, want the length of the password", got)
	}
}

func TestServe_PasswordLengths(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, 1, 63, 4000} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			t.Parallel()
			s, _ := play(t, join(startupMessage("user", "u"), passwordMessage(strings.Repeat("p", n))))
			if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"u", n}}) {
				t.Errorf("logins = %+v, want a password of %d bytes", got, n)
			}
		})
	}
}

func TestServe_RequestsForEncryption_AreRefusedAndTheClientGoesOnInClearText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prefix  []byte
		refused string
	}{
		{name: "none"},
		{name: "ssl", prefix: sslRequest, refused: "N"},
		{name: "gssapi", prefix: gssRequest, refused: "N"},
		{name: "gssapi and ssl", prefix: join(gssRequest, sslRequest), refused: "NN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, conn := play(t, join(tt.prefix, startupMessage("user", "u"), passwordMessage("pw")))
			if want := tt.refused + string(join(authRequest, refusal("u"))); string(conn.written()) != want {
				t.Errorf("written = %q, want %q", conn.written(), want)
			}
			if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"u", 2}}) {
				t.Errorf("logins = %+v, want the login after the request", got)
			}
		})
	}
}

func TestServe_ThreeRequestsForEncryption_EndTheSession(t *testing.T) {
	t.Parallel()

	s, conn := play(t, join(sslRequest, gssRequest, sslRequest, startupMessage("user", "u"), passwordMessage("pw")))
	if got := string(conn.written()); got != "NNN" {
		t.Errorf("written = %q, want a refusal for each of the three requests and nothing more", got)
	}
	if got := logins(sessionReport(t, s)); len(got) != 0 {
		t.Errorf("logins = %+v, want none", got)
	}
}

func TestServe_PacketsThatAreNoStartup_EndTheSessionWithoutAnswer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		script []byte
	}{
		{name: "cancel request", script: cancelRequest},
		{name: "protocol 2.0", script: packet(2<<16, []byte("user\x00u\x00\x00")...)},
		{name: "protocol 4.0", script: packet(4<<16, []byte("user\x00u\x00\x00")...)},
		{name: "code below the versions", script: packet(1, []byte("user\x00u\x00\x00")...)},
		{name: "http", script: []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")},
		{name: "nothing", script: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, conn := play(t, join(tt.script, passwordMessage("pw")))
			if len(conn.written()) != 0 {
				t.Errorf("written = %q, want nothing", conn.written())
			}
			if got := s.EventType(); got != "connection" {
				t.Errorf("EventType() = %q, want connection", got)
			}
		})
	}
}

func TestServe_StartupWithoutUser_IsNoLogin(t *testing.T) {
	t.Parallel()

	for _, params := range [][]string{nil, {"database", "app"}, {"user", ""}} {
		s, conn := play(t, join(startupMessage(params...), passwordMessage("pw")))
		if len(conn.written()) != 0 {
			t.Errorf("%v: written = %q, want nothing", params, conn.written())
		}
		if got := logins(sessionReport(t, s)); len(got) != 0 {
			t.Errorf("%v: logins = %+v, want none", params, got)
		}
	}
}

func TestServe_StartupWithoutUser_StillReportsTheDatabase(t *testing.T) {
	t.Parallel()

	s, _ := play(t, startupMessage("database", "app", "application_name", "scanner"))
	rep := sessionReport(t, s)
	if rep.Database != "app" || rep.ApplicationName != "scanner" {
		t.Errorf("database = %q, application name = %q, want what the client said", rep.Database, rep.ApplicationName)
	}
}

func TestServe_EndOfTheStream(t *testing.T) {
	t.Parallel()

	long := make([]byte, 0, 40)
	long = append(long, 'p', 0, 0, 0, 100)
	long = append(long, "only a part"...)
	tests := []struct {
		name   string
		script []byte
		want   []login
	}{
		{name: "only the startup", script: startupMessage("user", "u"), want: []login{{"u", -1}}},
		{name: "a message that is no password", script: join(startupMessage("user", "u"), []byte{'Q', 0, 0, 0, 5, 0}), want: []login{{"u", -1}}},
		{name: "terminate", script: join(startupMessage("user", "u"), []byte{'X', 0, 0, 0, 4}), want: []login{{"u", -1}}},
		{name: "the type of the password message only", script: join(startupMessage("user", "u"), []byte{'p'}), want: []login{{"u", -1}}},
		{name: "a length that cannot hold a password", script: join(startupMessage("user", "u"), []byte{'p', 0, 0, 0, 4}), want: []login{{"u", -1}}},
		{name: "a password that was not finished", script: join(startupMessage("user", "u"), long), want: []login{{"u", -1}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, conn := play(t, tt.script)
			if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("logins = %+v, want %+v", got, tt.want)
			}
			if !bytes.HasPrefix(conn.written(), authRequest) || bytes.Contains(conn.written(), []byte("28P01")) {
				t.Errorf("written = %q, want the request for a password and no refusal of a password that never came", conn.written())
			}
		})
	}
}

func TestServe_StartupPacket_IsReadOnlyWithinTheLimitOfTheServer(t *testing.T) {
	t.Parallel()

	// A startup message of exactly the longest length, filled by a parameter that
	// is ignored.
	fill := func(total int) []byte {
		base := startupMessage("user", "u", "options", "")
		pad := total - len(base)
		return startupMessage("user", "u", "options", strings.Repeat("o", pad))
	}
	tests := []struct {
		name    string
		script  []byte
		logged  bool
		maxRead int
	}{
		{name: "10000 bytes", script: join(fill(10000), passwordMessage("pw")), logged: true},
		{name: "10001 bytes", script: join(fill(10001), passwordMessage("pw"))},
		{name: "a length of 4 GiB", script: join([]byte{0xff, 0xff, 0xff, 0xff}, make([]byte, 20<<10)), maxRead: 4096},
		{name: "a length below the smallest packet", script: join([]byte{0, 0, 0, 7}, make([]byte, 20<<10)), maxRead: 4096},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, conn := play(t, tt.script)
			if got := len(logins(sessionReport(t, s))) == 1; got != tt.logged {
				t.Errorf("login recorded = %t, want %t", got, tt.logged)
			}
			if tt.maxRead > 0 && conn.read > tt.maxRead {
				t.Errorf("read %d bytes of a packet that is refused by its header, want no more than the one buffer of %d", conn.read, tt.maxRead)
			}
		})
	}
}

func TestServe_MalformedStartup_EndsTheSession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "no end", body: "user\x00u\x00"},
		{name: "a name without a value", body: "user\x00u\x00database"},
		{name: "a value without its end", body: "user\x00u\x00database\x00app"},
		{name: "empty", body: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, conn := play(t, join(packet(protocol30, []byte(tt.body)...), passwordMessage("pw")))
			if len(conn.written()) != 0 {
				t.Errorf("written = %q, want nothing", conn.written())
			}
			if got := logins(sessionReport(t, s)); len(got) != 0 {
				t.Errorf("logins = %+v, want none", got)
			}
		})
	}
}

func TestServe_Texts_AreKeptWithinTheLimitsOfTheReport(t *testing.T) {
	t.Parallel()

	s, _ := play(t, join(startupMessage(
		"user", strings.Repeat("u", 300),
		"database", strings.Repeat("d", 100)+"\xff",
		"application_name", strings.Repeat("a", 100)), passwordMessage("pw")))
	rep := sessionReport(t, s)
	if got := rep.Attempts[0].Username; got != strings.Repeat("u", 256) {
		t.Errorf("username has %d bytes, want 256", len(got))
	}
	if rep.Database != strings.Repeat("d", 64) || rep.ApplicationName != strings.Repeat("a", 64) {
		t.Errorf("database has %d bytes and application name %d, want 64 each", len(rep.Database), len(rep.ApplicationName))
	}
}

func TestServe_Refusal_NamesTheUserInPrintableASCIIOnly(t *testing.T) {
	t.Parallel()

	_, conn := play(t, join(startupMessage("user", "r\x01\xffo\x1b[0mo\x1f\x7f\u00e9t"), passwordMessage("pw")))
	if want := join(authRequest, refusal("ro[0mot")); !bytes.Equal(conn.written(), want) {
		t.Errorf("written = %q, want %q", conn.written(), want)
	}
}

func TestServe_MoreThan16KiB_EndsTheSession(t *testing.T) {
	t.Parallel()

	// A password message whose header promises 2 GiB.
	script := join(startupMessage("user", "u"), []byte{'p', 0x7f, 0xff, 0xff, 0xff}, bytes.Repeat([]byte("a"), 64<<10))
	s, conn := play(t, script)
	if conn.read != 16<<10 {
		t.Errorf("read %d bytes, want exactly the 16 KiB that a connection may send", conn.read)
	}
	if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"u", -1}}) {
		t.Errorf("logins = %+v, want the login without a password", got)
	}
}

func TestServe_NameEntered_IsRecordedWhenTheRequestCannotBeWritten(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := newScriptConn(startupMessage("user", "root"))
	conn.failWrites = true
	s := start(t, clk)
	postgres.New(clk).Serve(t.Context(), conn, s)
	s.End()

	if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"root", -1}}) {
		t.Errorf("logins = %+v, want the name without a password", got)
	}
}

func TestServe_RefusalThatCannotBeWritten_KeepsThePassword(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := &failingAfter{scriptConn: newScriptConn(join(startupMessage("user", "root"), passwordMessage("pw"))), okWrites: 1}
	s := start(t, clk)
	postgres.New(clk).Serve(t.Context(), conn, s)
	s.End()

	if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"root", 2}}) {
		t.Errorf("logins = %+v, want the login with the length of the password", got)
	}
}

// failingAfter lets a number of writes through and fails the rest.
type failingAfter struct {
	*scriptConn
	okWrites int
}

func (c *failingAfter) Write(p []byte) (int, error) {
	if c.okWrites == 0 {
		return 0, errors.New("write failed")
	}
	c.okWrites--
	return c.scriptConn.Write(p)
}

func TestServe_CanceledContext_ReadsAndWritesNothing(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := newScriptConn(join(startupMessage("user", "root"), passwordMessage("pw")))
	s := start(t, clk)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	postgres.New(clk).Serve(ctx, conn, s)
	s.End()

	if conn.read != 0 || len(conn.written()) != 0 || s.Attempts() != 0 {
		t.Errorf("read %d bytes, wrote %q, recorded %d logins, want none", conn.read, conn.written(), s.Attempts())
	}
}

func TestServe_Deadlines_AreThirtySecondsToReadAndTenToWrite(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := newScriptConn(join(startupMessage("user", "u"), passwordMessage("pw")))
	s := start(t, clk)
	postgres.New(clk).Serve(t.Context(), conn, s)

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

	golden, err := fs.ReadFile(os.DirFS("../report/testdata"), "session_postgres.json")
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(golden, &want); err != nil {
		t.Fatal(err)
	}

	clk := clocktest.New()
	hp := &session.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: "postgres", Secret: secretValue}
	s, err := session.Start(clk, hp, netip.MustParseAddrPort("[2001:db8::7]:51000"), netip.MustParseAddrPort("10.0.0.5:5432"))
	if err != nil {
		t.Fatal(err)
	}
	postgres.New(clk).Serve(t.Context(), newScriptConn(join(sslRequest,
		startupMessage("user", "postgres", "database", "postgres", "application_name", "psql"),
		passwordMessage("123456789012"))), s)
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

// A client that waits for each answer, as libpq does, gets the dialog of a
// server on a real connection.
func TestServe_Dialog_WithAClientThatWaitsForTheAnswers(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	client, server := net.Pipe()
	s := start(t, clk)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = server.Close() }()
		postgres.New(clk).Serve(t.Context(), server, s)
	}()

	read := func(n int) []byte {
		t.Helper()
		b := make([]byte, n)
		if _, err := io.ReadFull(client, b); err != nil {
			t.Fatalf("read %d bytes: %v", n, err)
		}
		return b
	}
	send := func(b []byte) {
		t.Helper()
		if _, err := client.Write(b); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	send(sslRequest)
	if got := read(1); string(got) != "N" {
		t.Fatalf("answer to the request for TLS = %q, want N", got)
	}
	send(startupMessage("user", "postgres", "database", "app"))
	if got := read(len(authRequest)); !bytes.Equal(got, authRequest) {
		t.Fatalf("request = %q, want the request for a password in clear text", got)
	}
	send(passwordMessage("hunter2"))
	head := read(5)
	if head[0] != 'E' {
		t.Fatalf("message type = %q, want E", head[0])
	}
	body := read(int(binary.BigEndian.Uint32(head[1:])) - 4)
	if !bytes.Contains(body, []byte("C28P01\x00")) {
		t.Errorf("error = %q, want the code 28P01", body)
	}
	// The server ends the session after the refusal.
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Error("the server still reads after the refusal")
	}
	_ = client.Close()
	<-done
	if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"postgres", 7}}) {
		t.Errorf("logins = %+v, want the login", got)
	}
}

func TestNew_WithoutAClock_Panics(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("New(nil) did not panic")
		}
	}()
	postgres.New(nil)
}

// FuzzServe feeds the honeypot with bytes of a client. It must never panic,
// never read more than a connection may send, never answer more than a refusal
// and the replies to the requests for encryption, and only record texts that
// the server accepts.
func FuzzServe(f *testing.F) {
	f.Add(join(sslRequest, startupMessage("user", "postgres", "database", "app", "application_name", "psql"), passwordMessage("pw")))
	f.Add(join(gssRequest, sslRequest, startupMessage("user", "u"), passwordMessage("")))
	f.Add(cancelRequest)
	f.Add(startupMessage())
	f.Add(join(startupMessage("user", "u"), []byte{'p', 0x7f, 0xff, 0xff, 0xff}))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))

	f.Fuzz(func(t *testing.T, script []byte) {
		clk := clocktest.New()
		conn := newScriptConn(script)
		s := start(t, clk)
		postgres.New(clk).Serve(t.Context(), conn, s)
		s.End()

		if conn.read > 16<<10 {
			t.Fatalf("read %d bytes", conn.read)
		}
		if len(conn.written()) > 3+len(authRequest)+400 {
			t.Fatalf("wrote %d bytes", len(conn.written()))
		}
		rep := sessionReport(t, s)
		if _, err := json.Marshal(rep); err != nil {
			t.Fatal(err)
		}
		if len(rep.Attempts) > 1 || len(rep.Database) > 64 || len(rep.ApplicationName) > 64 || !utf8.ValidString(rep.Database) || !utf8.ValidString(rep.ApplicationName) {
			t.Fatalf("report = %+v", rep)
		}
		for _, a := range rep.Attempts {
			if len(a.Username) > report.MaxUsername || !utf8.ValidString(a.Username) {
				t.Fatalf("username %q", a.Username)
			}
		}
	})
}
