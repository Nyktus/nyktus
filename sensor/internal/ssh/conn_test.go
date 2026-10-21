// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ssh

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"nyktus.org/nyktus/sensor/internal/clock/clocktest"
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

func TestGuardedConn_Deadlines_AreThirtySecondsToReadAndTenToWriteFromTheClock(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := newFakeConn("abc")
	g := newGuardedConn(conn, clk)
	if _, err := g.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Second)
	if _, err := g.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if len(conn.readDeadlines) != 2 || len(conn.writeDeadlines) != 1 {
		t.Fatalf("deadlines set: %d for reads, %d for writes, want one for every call", len(conn.readDeadlines), len(conn.writeDeadlines))
	}
	// The idle time starts again with every read, from the clock of the sensor.
	if want := clk.Deadline(30 * time.Second); !conn.readDeadlines[1].Equal(want) {
		t.Errorf("read deadline = %v, want %v", conn.readDeadlines[1], want)
	}
	if !conn.readDeadlines[1].After(conn.readDeadlines[0]) {
		t.Errorf("read deadlines %v, %v: the second does not follow the clock", conn.readDeadlines[0], conn.readDeadlines[1])
	}
	if want := clk.Deadline(10 * time.Second); !conn.writeDeadlines[0].Equal(want) {
		t.Errorf("write deadline = %v, want %v", conn.writeDeadlines[0], want)
	}
}

func TestGuardedConn_Read_StopsAfter16KiBInAll(t *testing.T) {
	t.Parallel()

	g := newGuardedConn(newFakeConn(strings.Repeat("a", 20<<10)), clocktest.New())
	// A read that would pass the limit is cut at it.
	buf := make([]byte, 5000)
	total := 0
	var err error
	for err == nil {
		var n int
		n, err = g.Read(buf)
		total += n
	}
	if total != 16<<10 || !errors.Is(err, errTooMuch) {
		t.Errorf("read %d bytes and then %v, want exactly 16 KiB and the error for too much", total, err)
	}
}

func TestGuardedConn_Read_PassesTheEndOfTheStream(t *testing.T) {
	t.Parallel()

	g := newGuardedConn(newFakeConn("ab"), clocktest.New())
	buf := make([]byte, 8)
	if n, err := g.Read(buf); n != 2 || err != nil {
		t.Fatalf("Read() = %d, %v, want 2, nil", n, err)
	}
	if _, err := g.Read(buf); !errors.Is(err, io.EOF) {
		t.Errorf("Read() = %v, want the end of the stream", err)
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
		{name: "a line of 255 bytes", chunks: []string{"SSH-" + strings.Repeat("a", 251) + "\n"}, want: "SSH-" + strings.Repeat("a", 251)},
		{name: "a line of 256 bytes gives up", chunks: []string{"SSH-" + strings.Repeat("a", 252) + "\nSSH-2.0-b\n"}, want: ""},
		{name: "a line over 255 bytes gives up", chunks: []string{"SSH-" + strings.Repeat("a", 300) + "\nSSH-2.0-b\n"}, want: ""},
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
