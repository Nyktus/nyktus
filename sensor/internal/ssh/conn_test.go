// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	cryptossh "golang.org/x/crypto/ssh"

	"nyktus.org/nyktus/sensor/internal/clock/clocktest"
	"nyktus.org/nyktus/sensor/internal/guard"
	"nyktus.org/nyktus/sensor/internal/session"
)

// fakeConn records the deadlines and serves a script.
type fakeConn struct {
	net.Conn
	mu             sync.Mutex
	input          *strings.Reader
	readDeadlines  []time.Time
	writeDeadlines []time.Time
	written        int
}

func newFakeConn(input string) *fakeConn {
	return &fakeConn{input: strings.NewReader(input)}
}

func (c *fakeConn) Read(p []byte) (int, error) { return c.input.Read(p) }
func (c *fakeConn) Write(p []byte) (int, error) {
	c.written += len(p)
	return len(p), nil
}

func (c *fakeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadlines = append(c.readDeadlines, t)
	return nil
}

func (c *fakeConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadlines = append(c.writeDeadlines, t)
	return nil
}

func TestGuardedConn_AppliesTheLimitsOfTheGuard(t *testing.T) {
	t.Parallel()

	conn := newFakeConn(strings.Repeat("a", 20<<10))
	g := newGuardedConn(conn, clocktest.New())
	if _, err := g.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	total := 0
	var err error
	for err == nil {
		var n int
		n, err = g.Read(make([]byte, 5000))
		total += n
	}
	if total != 16<<10 || !errors.Is(err, guard.ErrTooMuch) {
		t.Errorf("read %d bytes and then %v, want exactly 16 KiB and the error for too much", total, err)
	}
	if len(conn.readDeadlines) == 0 || len(conn.writeDeadlines) != 1 {
		t.Errorf("deadlines set: %d for reads, %d for writes, want some for reads and one for the write", len(conn.readDeadlines), len(conn.writeDeadlines))
	}
}

func TestGuardedConn_ClientVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		chunks []string
		want   string
	}{
		{name: "crlf", chunks: []string{"SSH-2.0-OpenSSH_9.6\r\nrest"}, want: "SSH-2.0-OpenSSH_9.6"},
		{name: "lf only", chunks: []string{"SSH-2.0-Go\nrest"}, want: "SSH-2.0-Go"},
		{name: "one byte at a time", chunks: strings.Split("SSH-2.0-libssh\r\n", ""), want: "SSH-2.0-libssh"},
		{name: "split inside the line", chunks: []string{"SSH-2.0-li", "bssh\r", "\n"}, want: "SSH-2.0-libssh"},
		{name: "lines before it are skipped", chunks: []string{"hi\r\nx\nSSH-2.0-a\r\n"}, want: "SSH-2.0-a"},
		{name: "a line that only holds the prefix later is no version", chunks: []string{"xSSH-2.0-a\r\n"}, want: ""},
		{name: "no line ending", chunks: []string{"SSH-2.0-a"}, want: ""},
		{name: "a line of 254 bytes", chunks: []string{"SSH-" + strings.Repeat("a", 250) + "\n"}, want: "SSH-" + strings.Repeat("a", 250)},
		{name: "a line of 255 bytes gives up", chunks: []string{"SSH-" + strings.Repeat("a", 251) + "\nSSH-2.0-b\n"}, want: ""},
		{name: "1023 lines before it", chunks: []string{strings.Repeat("x\n", 1023) + "SSH-2.0-a\n"}, want: "SSH-2.0-a"},
		{name: "1024 lines before it give up", chunks: []string{strings.Repeat("x\n", 1024) + "SSH-2.0-a\n"}, want: ""},
		{name: "a line over 255 bytes gives up", chunks: []string{"SSH-" + strings.Repeat("a", 300) + "\nSSH-2.0-b\n"}, want: ""},
		{name: "the first line with the prefix is the version, also of another protocol", chunks: []string{"SSH-1.5-a\nSSH-2.0-b\n"}, want: "SSH-1.5-a"},
		{name: "the first version stays", chunks: []string{"SSH-2.0-a\nSSH-2.0-b\n"}, want: "SSH-2.0-a"},
		{name: "the first version stays in later reads", chunks: []string{"SSH-2.0-a\n", "SSH-2.0-b\n", "c\n"}, want: "SSH-2.0-a"},
		{name: "http", chunks: []string{"GET / HTTP/1.1\r\n\r\n"}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			g := newGuardedConn(newFakeConn(strings.Join(tt.chunks, "")), clocktest.New())
			for _, c := range tt.chunks {
				buf := make([]byte, len(c))
				if _, err := io.ReadFull(g, buf); err != nil {
					t.Fatal(err)
				}
			}
			if got := g.clientVersion(); got != tt.want {
				t.Errorf("clientVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

// The library reads from a goroutine of its own, and the version is read when
// the session ends.
func TestGuardedConn_ReadAndClientVersion_AreSafeTogether(t *testing.T) {
	t.Parallel()

	g := newGuardedConn(newFakeConn("SSH-2.0-a\r\n"+strings.Repeat("b", 1000)), clocktest.New())
	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 7)
		for {
			if _, err := g.Read(buf); err != nil {
				return
			}
		}
	})
	for range 100 {
		_ = g.clientVersion()
	}
	wg.Wait()
	if got := g.clientVersion(); got != "SSH-2.0-a" {
		t.Errorf("clientVersion() = %q", got)
	}
}

func TestClean(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{name: "short", in: "root", max: 8, want: "root"},
		{name: "exact", in: "12345678", max: 8, want: "12345678"},
		{name: "cut", in: "123456789", max: 8, want: "12345678"},
		{name: "invalid bytes", in: "ro\xff\xfeot", max: 16, want: "ro\uFFFDot"},
		{name: "cut in the middle of a character", in: "1234567\u00e9", max: 8, want: "1234567"},
		{name: "cut after a character", in: "123456\u00e9x", max: 8, want: "123456\u00e9"},
		{name: "empty", in: "", max: 8, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := clean(tt.in, tt.max)
			if got != tt.want || !utf8.ValidString(got) {
				t.Errorf("clean(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
			}
		})
	}
}

// prefixedConn writes lines before the first bytes of the client, as a client
// may before its version.
type prefixedConn struct {
	net.Conn
	prefix string
	sent   bool
}

func (c *prefixedConn) Write(p []byte) (int, error) {
	if !c.sent {
		c.sent = true
		if _, err := c.Conn.Write([]byte(c.prefix)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(p)
}

// The honeypot reads the version of the client itself, because the library
// shows it only after the key exchange. This ties the two readings together:
// where the library accepts a version, the honeypot has the same one.
func TestGuardedConn_ClientVersion_IsTheOneOfTheLibrary(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct{ prefix, version string }{
		"plain":        {"", "SSH-2.0-OpenSSH_9.6"},
		"lines before": {"hello\r\nworld\r\n", "SSH-2.0-Go"},
		"a comment":    {"", "SSH-2.0-libssh_0.9.6 some comment"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// A pipe would deadlock: both sides write their version first.
			ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close() //nolint:errcheck // nothing to do about a failed close in a test.
			client, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(t.Context(), "tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close() //nolint:errcheck // nothing to do about a failed close in a test.
			server, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close() //nolint:errcheck // nothing to do about a failed close in a test.
			gc := newGuardedConn(server, clocktest.New())
			var library string
			cfg := &cryptossh.ServerConfig{
				PasswordCallback: func(m cryptossh.ConnMetadata, _ []byte) (*cryptossh.Permissions, error) {
					library = string(m.ClientVersion())
					return nil, errRefused
				},
			}
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := cryptossh.NewSignerFromKey(priv)
			if err != nil {
				t.Fatal(err)
			}
			cfg.AddHostKey(signer)
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _, _, _ = cryptossh.NewServerConn(gc, cfg)
			}()
			_ = client.SetDeadline(time.Now().Add(10 * time.Second))
			_, _, _, _ = cryptossh.NewClientConn(&prefixedConn{Conn: client, prefix: tt.prefix}, "x", &cryptossh.ClientConfig{
				User:            "root",
				Auth:            []cryptossh.AuthMethod{cryptossh.Password("x")},
				HostKeyCallback: cryptossh.FixedHostKey(signer.PublicKey()),
				ClientVersion:   tt.version,
			})
			_ = client.Close()
			<-done
			// Where the library gives up, the honeypot has no version either.
			want := tt.version
			if len(tt.version) > 254 || strings.Count(tt.prefix, "\n") >= maxLinesBefore {
				want = ""
			}
			if library != want || gc.clientVersion() != library {
				t.Errorf("library version = %q, honeypot version = %q, want both %q", library, gc.clientVersion(), want)
			}
		})
	}
}

// fakeMeta is what the library tells about a connection.
type fakeMeta struct {
	cryptossh.ConnMetadata
	user string
}

func (m fakeMeta) User() string { return m.user }

// A client can try a method that the honeypot does not offer, and the library
// counts it as a failure. A real client of the library asks only for the
// methods that the server lists, so the callback is tried directly.
func TestRecorder_Other_RecordsAMethodThatIsNotOfferedAsALoginWithoutAPassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method string
		want   int
	}{
		{"keyboard-interactive", 1},
		{"gssapi-with-mic", 1},
		{"hostbased", 1},
		{"something-else", 1},
		{"password", 0},
		{"publickey", 0},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			t.Parallel()
			clk := clocktest.New()
			s, err := session.Start(clk, &session.Honeypot{ID: honeypotID, Service: "ssh"}, netip.MustParseAddrPort("203.0.113.9:1"), netip.MustParseAddrPort("10.0.0.5:22"))
			if err != nil {
				t.Fatal(err)
			}
			(&recorder{sess: s}).other(fakeMeta{user: "root"}, tt.method, errRefused)
			if s.Attempts() != tt.want {
				t.Errorf("attempts = %d, want %d", s.Attempts(), tt.want)
			}
			if tt.want == 1 {
				rep, _ := s.Report(0)
				if a := rep.Attempts[0]; a.Username != "root" || a.PasswordLength != nil || a.KeyFingerprint != "" {
					t.Errorf("attempt = %+v, want the user name only", a)
				}
			}
		})
	}
}

const honeypotID = "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d"

// The first "none" of a client asks for the methods and costs nothing; the
// library counts every later one as a failure.
func TestRecorder_Other_FirstNoneIsFreeAndEveryLaterOneIsALogin(t *testing.T) {
	t.Parallel()

	s, err := session.Start(clocktest.New(), &session.Honeypot{ID: honeypotID, Service: "ssh"}, netip.MustParseAddrPort("203.0.113.9:1"), netip.MustParseAddrPort("10.0.0.5:22"))
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{sess: s}
	for i, want := range []int{0, 1, 2, 3} {
		r.other(fakeMeta{user: "root"}, "none", errRefused)
		if s.Attempts() != want {
			t.Errorf("attempts after %d requests for the methods = %d, want %d", i+1, s.Attempts(), want)
		}
	}
}
