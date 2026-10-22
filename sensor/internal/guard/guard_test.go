// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package guard

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestConn_Deadlines_AreThirtySecondsToReadAndTenToWriteFromTheClock(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	conn := newFakeConn("abc")
	g := New(conn, clk)
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

func TestConn_Read_StopsAfter16KiBInAll(t *testing.T) {
	t.Parallel()

	g := New(newFakeConn(strings.Repeat("a", 20<<10)), clocktest.New())
	// A read that would pass the limit is cut at it.
	buf := make([]byte, 5000)
	total := 0
	var err error
	for err == nil {
		var n int
		n, err = g.Read(buf)
		total += n
	}
	if total != 16<<10 || !errors.Is(err, ErrTooMuch) {
		t.Errorf("read %d bytes and then %v, want exactly 16 KiB and the error for too much", total, err)
	}
}

func TestConn_Read_AfterTheLimit_SetsNoDeadline(t *testing.T) {
	t.Parallel()

	conn := newFakeConn(strings.Repeat("a", MaxReadBytes))
	g := New(conn, clocktest.New())
	if _, err := io.ReadFull(g, make([]byte, MaxReadBytes)); err != nil {
		t.Fatal(err)
	}
	before := len(conn.readDeadlines)
	if _, err := g.Read(make([]byte, 1)); !errors.Is(err, ErrTooMuch) {
		t.Fatalf("Read() = %v, want the error for too much", err)
	}
	if len(conn.readDeadlines) != before {
		t.Errorf("a read that is refused set a deadline")
	}
}

func TestConn_Read_PassesTheEndOfTheStream(t *testing.T) {
	t.Parallel()

	g := New(newFakeConn("ab"), clocktest.New())
	buf := make([]byte, 8)
	if n, err := g.Read(buf); n != 2 || err != nil {
		t.Fatalf("Read() = %d, %v, want 2, nil", n, err)
	}
	if _, err := g.Read(buf); !errors.Is(err, io.EOF) {
		t.Errorf("Read() = %v, want the end of the stream", err)
	}
}

func TestConn_ReadAndWrite_AreSafeTogether(t *testing.T) {
	t.Parallel()

	g := New(newFakeConn(strings.Repeat("a", 4096)), clocktest.New())
	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 64)
		for {
			if _, err := g.Read(buf); err != nil {
				return
			}
		}
	})
	wg.Go(func() {
		for range 100 {
			if _, err := g.Write([]byte("x")); err != nil {
				return
			}
		}
	})
	wg.Wait()
}

func TestNew_WithoutAClock_Panics(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("New(conn, nil) did not panic")
		}
	}()
	New(newFakeConn(""), nil)
}
