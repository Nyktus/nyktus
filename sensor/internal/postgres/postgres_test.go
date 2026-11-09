// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"nyktus.org/nyktus/sensor/internal/clock/clocktest"
	"nyktus.org/nyktus/sensor/internal/conntest"
	"nyktus.org/nyktus/sensor/internal/postgres"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/session"
)

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

const clientNonce = "rOprNGfwEbeRWgbNEkqO"

// proof is the part of the last message of the client that a password decides.
const proof = "dHpI4RFPwZ2vjPxnXyqxGkvVv6cpbjT7RYhBHyyhkPU="

func saslMessage(body string) []byte {
	b := []byte{'p'}
	b = binary.BigEndian.AppendUint32(b, uint32(4+len(body))) //nolint:gosec // G115: the test messages are small
	return append(b, body...)
}

// clientFirst is the first message of a SCRAM exchange with the given nonce.
func clientFirst(nonce string) []byte {
	data := "n,,n=,r=" + nonce
	body := "SCRAM-SHA-256\x00" + string(binary.BigEndian.AppendUint32(nil, uint32(len(data)))) + data //nolint:gosec // G115: the test messages are small
	return saslMessage(body)
}

// clientMessages is what a client sends for the whole exchange.
func clientMessages() []byte {
	return join(clientFirst(clientNonce), saslMessage("c=biws,r="+clientNonce+"server,p="+proof))
}

func join(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

var (
	authRequest = []byte("R\x00\x00\x00\x17\x00\x00\x00\nSCRAM-SHA-256\x00\x00")
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
func play(t *testing.T, script []byte) (*session.Session, *conntest.Conn) {
	t.Helper()
	clk := clocktest.New()
	conn := conntest.New(script)
	s := start(t, clk)
	postgres.New(postgres.Config{}, clk).Serve(t.Context(), conn, s)
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
	for _, f := range []string{"SFATAL", "VFATAL", "C28P01", `Mpassword authentication failed for user "` + user + `"`, "Fauth.c", "L331", "Rauth_failed"} {
		fields = append(fields, f...)
		fields = append(fields, 0)
	}
	fields = append(fields, 0)
	b := []byte{'E'}
	b = binary.BigEndian.AppendUint32(b, uint32(4+len(fields))) //nolint:gosec // G115: the test message is small
	return append(b, fields...)
}

// splitAnswer checks an answer of a whole exchange and returns the text of its
// challenge.
func splitAnswer(t *testing.T, written, refused []byte) string {
	t.Helper()
	rest, ok := bytes.CutPrefix(written, refused)
	if !ok {
		t.Fatalf("written = %q, want it to start with %q", written, refused)
	}
	if !bytes.HasPrefix(rest, []byte{'R'}) || len(rest) < 9 {
		t.Fatalf("written = %q, want the challenge", rest)
	}
	n := int(binary.BigEndian.Uint32(rest[1:]))
	if binary.BigEndian.Uint32(rest[5:]) != 11 || len(rest) < 1+n {
		t.Fatalf("written = %q, want a message of type 11", rest)
	}
	return string(rest[9 : 1+n])
}

func TestServe_Login_RecordsTheUserAndTheDatabase(t *testing.T) {
	t.Parallel()

	s, conn := play(t, join(
		startupMessage("user", "postgres", "database", "app", "application_name", "psql", "client_encoding", "UTF8"),
		clientMessages()))

	rep := sessionReport(t, s)
	if got := logins(rep); !reflect.DeepEqual(got, []login{{"postgres", -1}}) {
		t.Errorf("logins = %+v, want postgres without the length of a password", got)
	}
	if rep.Database != "app" || rep.ApplicationName != "psql" {
		t.Errorf("database = %q, application name = %q, want app and psql", rep.Database, rep.ApplicationName)
	}
	challenge := splitAnswer(t, conn.Written(), authRequest)
	if !strings.HasPrefix(challenge, "r="+clientNonce) || !strings.HasSuffix(challenge, ",i=4096") || !strings.Contains(challenge, ",s=") {
		t.Errorf("challenge = %q, want the nonce of the client, a salt and 4096 iterations", challenge)
	}
	if !bytes.HasSuffix(conn.Written(), refusal("postgres")) {
		t.Errorf("written = %q, want the refusal %q at the end", conn.Written(), refusal("postgres"))
	}
	if got := s.EventType(); got != "login_attempt" {
		t.Errorf("EventType() = %q, want login_attempt", got)
	}
}

func TestServe_Proof_IsNeverKeptOrSentBack(t *testing.T) {
	t.Parallel()

	s, conn := play(t, join(startupMessage("user", "root"), clientMessages()))

	body, err := json.Marshal(sessionReport(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(proof)) || strings.Contains(s.Attr().Value.String(), proof) || bytes.Contains(conn.Written(), []byte(proof)) {
		t.Errorf("the proof is in the report, the log or the answer")
	}
}

func TestServe_Salt_IsTheSameForAUserAndDiffersBetweenUsers(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	svc := postgres.New(postgres.Config{}, clk)
	challenge := func(user string) (nonce, salt string) {
		conn := conntest.New(join(startupMessage("user", user), clientMessages()))
		s := start(t, clk)
		svc.Serve(t.Context(), conn, s)
		s.End()
		fields := strings.Split(splitAnswer(t, conn.Written(), authRequest), ",")
		return fields[0], fields[1]
	}
	n1, s1 := challenge("root")
	n2, s2 := challenge("root")
	_, s3 := challenge("admin")
	if s1 != s2 {
		t.Errorf("salts of one user = %q and %q, want them equal, as on a server", s1, s2)
	}
	if s1 == s3 {
		t.Errorf("salt of two users = %q, want them to differ", s1)
	}
	if n1 == n2 {
		t.Errorf("nonce = %q twice, want a new one for every exchange", n1)
	}
}

func TestServe_ClientFirst_ThatIsNotUsable_EndsTheExchange(t *testing.T) {
	t.Parallel()

	tests := map[string][]byte{
		"a nonce with a control character": clientFirst("abc\x01def"),
		"a nonce with a space":             clientFirst("abc def"),
		"a nonce that is too long":         clientFirst(strings.Repeat("a", 257)),
		"an empty nonce":                   clientFirst(""),
		"another mechanism":                saslMessage("PLAIN\x00\x00\x00\x00\x03abc"),
		"a wrong length":                   saslMessage("SCRAM-SHA-256\x00\x00\x00\x00\x63n,,n=,r=abc"),
		"too few fields":                   saslMessage("SCRAM-SHA-256\x00\x00\x00\x00\x02n,"),
	}
	for name, first := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s, conn := play(t, join(startupMessage("user", "u"), first, saslMessage("c=biws")))
			if !bytes.Equal(conn.Written(), authRequest) {
				t.Errorf("written = %q, want only the offer of the mechanism", conn.Written())
			}
			if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"u", -1}}) {
				t.Errorf("logins = %+v, want the login", got)
			}
		})
	}
}

func TestServe_WithoutACertificate_RequestsForEncryptionAreRefused(t *testing.T) {
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
			s, conn := play(t, join(tt.prefix, startupMessage("user", "u"), clientMessages()))
			splitAnswer(t, conn.Written(), join([]byte(tt.refused), authRequest))
			if !bytes.HasSuffix(conn.Written(), refusal("u")) {
				t.Errorf("written = %q, want the refusal at the end", conn.Written())
			}
			if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"u", -1}}) {
				t.Errorf("logins = %+v, want the login after the request", got)
			}
		})
	}
}

func TestServe_ThreeRequestsForEncryption_EndTheSession(t *testing.T) {
	t.Parallel()

	s, conn := play(t, join(sslRequest, gssRequest, sslRequest, startupMessage("user", "u"), clientMessages()))
	if got := string(conn.Written()); got != "NNN" {
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
			s, conn := play(t, join(tt.script, clientMessages()))
			if len(conn.Written()) != 0 {
				t.Errorf("written = %q, want nothing", conn.Written())
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
		s, conn := play(t, join(startupMessage(params...), clientMessages()))
		if len(conn.Written()) != 0 {
			t.Errorf("%v: written = %q, want nothing", params, conn.Written())
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
		{name: "a message that is no answer", script: join(startupMessage("user", "u"), []byte{'Q', 0, 0, 0, 5, 0}), want: []login{{"u", -1}}},
		{name: "terminate", script: join(startupMessage("user", "u"), []byte{'X', 0, 0, 0, 4}), want: []login{{"u", -1}}},
		{name: "the type of the message only", script: join(startupMessage("user", "u"), []byte{'p'}), want: []login{{"u", -1}}},
		{name: "a length that holds nothing", script: join(startupMessage("user", "u"), []byte{'p', 0, 0, 0, 4}), want: []login{{"u", -1}}},
		{name: "a message that was not finished", script: join(startupMessage("user", "u"), long), want: []login{{"u", -1}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, conn := play(t, tt.script)
			if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("logins = %+v, want %+v", got, tt.want)
			}
			if !bytes.HasPrefix(conn.Written(), authRequest) || bytes.Contains(conn.Written(), []byte("28P01")) {
				t.Errorf("written = %q, want the offer and no refusal of a proof that never came", conn.Written())
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
		{name: "10000 bytes", script: join(fill(10000), clientMessages()), logged: true},
		{name: "10001 bytes", script: join(fill(10001), clientMessages())},
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
			if tt.maxRead > 0 && conn.BytesRead() > tt.maxRead {
				t.Errorf("read %d bytes of a packet that is refused by its header, want no more than the one buffer of %d", conn.BytesRead(), tt.maxRead)
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
			s, conn := play(t, join(packet(protocol30, []byte(tt.body)...), clientMessages()))
			if len(conn.Written()) != 0 {
				t.Errorf("written = %q, want nothing", conn.Written())
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
		"application_name", strings.Repeat("a", 100)), clientMessages()))
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

	_, conn := play(t, join(startupMessage("user", "r\x01\xffo\x1b[0mo\x1f\x7f\u00e9t"), clientMessages()))
	if !bytes.HasSuffix(conn.Written(), refusal("ro[0mot")) {
		t.Errorf("written = %q, want the refusal for ro[0mot", conn.Written())
	}
}

func TestServe_MessageThatPromisesTooMuch_IsNotRead(t *testing.T) {
	t.Parallel()

	script := join(startupMessage("user", "u"), []byte{'p', 0x7f, 0xff, 0xff, 0xff}, bytes.Repeat([]byte("a"), 64<<10))
	s, conn := play(t, script)
	if conn.BytesRead() > 4096+len(script)-64<<10 {
		t.Errorf("read %d bytes, want the message refused by its header", conn.BytesRead())
	}
	if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"u", -1}}) {
		t.Errorf("logins = %+v, want the login", got)
	}
}

func TestServe_NameEntered_IsRecordedWhenTheRequestCannotBeWritten(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := conntest.New(startupMessage("user", "root"))
	conn.FailAfter(0)
	s := start(t, clk)
	postgres.New(postgres.Config{}, clk).Serve(t.Context(), conn, s)
	s.End()

	if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"root", -1}}) {
		t.Errorf("logins = %+v, want the name without a password", got)
	}
	if len(conn.Written()) != 0 {
		t.Errorf("written = %q, want nothing: the writes failed", conn.Written())
	}
}

func TestServe_RefusalThatCannotBeWritten_KeepsTheLogin(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := conntest.New(join(startupMessage("user", "root"), clientMessages()))
	conn.FailAfter(2)
	s := start(t, clk)
	postgres.New(postgres.Config{}, clk).Serve(t.Context(), conn, s)
	s.End()

	if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"root", -1}}) {
		t.Errorf("logins = %+v, want the login", got)
	}
}

func TestServe_CanceledContext_ReadsAndWritesNothing(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := conntest.New(join(startupMessage("user", "root"), clientMessages()))
	s := start(t, clk)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	postgres.New(postgres.Config{}, clk).Serve(ctx, conn, s)
	s.End()

	if conn.BytesRead() != 0 || len(conn.Written()) != 0 || s.Attempts() != 0 {
		t.Errorf("read %d bytes, wrote %q, recorded %d logins, want none", conn.BytesRead(), conn.Written(), s.Attempts())
	}
}

func TestServe_Deadlines_AreThirtySecondsToReadAndTenToWrite(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := conntest.New(join(startupMessage("user", "u"), clientMessages()))
	s := start(t, clk)
	postgres.New(postgres.Config{}, clk).Serve(t.Context(), conn, s)

	if len(conn.ReadDeadlines()) == 0 || len(conn.WriteDeadlines()) == 0 {
		t.Fatalf("deadlines set: %d for reads, %d for writes", len(conn.ReadDeadlines()), len(conn.WriteDeadlines()))
	}
	for _, d := range conn.ReadDeadlines() {
		if want := clk.Deadline(30 * time.Second); !d.Equal(want) {
			t.Errorf("read deadline = %v, want %v", d, want)
		}
	}
	for _, d := range conn.WriteDeadlines() {
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
	postgres.New(postgres.Config{}, clk).Serve(t.Context(), conntest.New(join(sslRequest,
		startupMessage("user", "postgres", "database", "postgres", "application_name", "psql"),
		clientMessages())), s)
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
		postgres.New(postgres.Config{}, clk).Serve(t.Context(), server, s)
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
		t.Fatalf("request = %q, want the offer of SCRAM", got)
	}
	send(clientFirst(clientNonce))
	challengeHead := read(5)
	if challengeHead[0] != 'R' {
		t.Fatalf("message type = %q, want R", challengeHead[0])
	}
	_ = read(int(binary.BigEndian.Uint32(challengeHead[1:])) - 4)
	send(saslMessage("c=biws,r=" + clientNonce + "x,p=" + proof))
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
	if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"postgres", -1}}) {
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
	postgres.New(postgres.Config{}, nil)
}

// FuzzServe feeds the honeypot with bytes of a client. It must never panic,
// never read more than a connection may send, never answer more than a refusal
// and the replies to the requests for encryption, and only record texts that
// the server accepts.
func FuzzServe(f *testing.F) {
	f.Add(join(sslRequest, startupMessage("user", "postgres", "database", "app", "application_name", "psql"), clientMessages()))
	f.Add(join(gssRequest, sslRequest, startupMessage("user", "u"), clientMessages()))
	f.Add(cancelRequest)
	f.Add(startupMessage())
	f.Add(join(startupMessage("user", "u"), []byte{'p', 0x7f, 0xff, 0xff, 0xff}))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))

	f.Fuzz(func(t *testing.T, script []byte) {
		clk := clocktest.New()
		conn := conntest.New(script)
		s := start(t, clk)
		postgres.New(postgres.Config{}, clk).Serve(t.Context(), conn, s)
		s.End()

		if conn.BytesRead() > 16<<10 {
			t.Fatalf("read %d bytes", conn.BytesRead())
		}
		if len(conn.Written()) > 3+len(authRequest)+700 {
			t.Fatalf("wrote %d bytes", len(conn.Written()))
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

func testCertificate(t *testing.T) *postgres.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "db"}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return &postgres.Certificate{Certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}}
}

// A client that insists on TLS gets it, is offered channel binding, and the
// login is recorded like any other.
func TestServe_WithACertificate_TheLoginRunsInsideTLS(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	client, server := net.Pipe()
	s := start(t, clk)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = server.Close() }()
		postgres.New(postgres.Config{Certificate: testCertificate(t)}, clk).Serve(t.Context(), server, s)
	}()
	if _, err := client.Write(sslRequest); err != nil {
		t.Fatal(err)
	}
	answer := make([]byte, 1)
	if _, err := io.ReadFull(client, answer); err != nil || answer[0] != 'S' {
		t.Fatalf("answer = %q, %v, want S", answer, err)
	}
	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // G402: the test does not check the certificate.
	if err := tc.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := tc.Write(startupMessage("user", "postgres")); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 5)
	if _, err := io.ReadFull(tc, head); err != nil {
		t.Fatal(err)
	}
	offer := make([]byte, int(binary.BigEndian.Uint32(head[1:]))-4)
	if _, err := io.ReadFull(tc, offer); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(offer, []byte("SCRAM-SHA-256-PLUS\x00SCRAM-SHA-256\x00\x00")) {
		t.Errorf("offer = %q, want channel binding and SCRAM", offer)
	}
	_ = tc.Close()
	_ = client.Close()
	<-done
	if got := logins(sessionReport(t, s)); !reflect.DeepEqual(got, []login{{"postgres", -1}}) {
		t.Errorf("logins = %+v, want the login", got)
	}
}

// Bytes that arrive with the request for TLS were sent before it, in clear text,
// and must not be taken for what the client says inside it.
func TestServe_BytesAfterTheRequestForTLS_EndTheSession(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := conntest.New(join(sslRequest, startupMessage("user", "injected")))
	s := start(t, clk)
	postgres.New(postgres.Config{Certificate: testCertificate(t)}, clk).Serve(t.Context(), conn, s)
	s.End()
	if got := logins(sessionReport(t, s)); len(got) != 0 {
		t.Errorf("logins = %+v, want none", got)
	}
	if string(conn.Written()) != "S" {
		t.Errorf("written = %q, want only the answer to the request", conn.Written())
	}
}

func TestCertificate_NeverPrintsTheKey(t *testing.T) {
	t.Parallel()

	cert := testCertificate(t)
	for _, got := range []string{fmt.Sprint(*cert), fmt.Sprintf("%+v", *cert), fmt.Sprintf("%#v", *cert)} {
		if got != "[redacted]" {
			t.Errorf("printed = %q, want the placeholder", got)
		}
	}
}
