// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package telnet

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
)

func readAll(in []byte, keep int) (lines []line, err error) {
	l := &lineReader{r: bufio.NewReader(bytes.NewReader(in))}
	for {
		ln, err := l.read(keep, nil)
		if !ln.complete {
			return lines, err
		}
		lines = append(lines, ln)
	}
}

func TestParser_Feed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []byte
		want  []byte
	}{
		{name: "plain data", input: []byte("abc"), want: []byte("abc")},
		{name: "a negotiation of three bytes", input: []byte{'a', iac, will, 1, 'b'}, want: []byte("ab")},
		{name: "each negotiation", input: []byte{iac, do, 1, iac, dont, 1, iac, wont, 1, 'x'}, want: []byte("x")},
		{name: "a command of two bytes", input: []byte{'a', iac, 241, 'b'}, want: []byte("ab")},
		{name: "an escaped IAC is data", input: []byte{'a', iac, iac, 'b'}, want: []byte{'a', iac, 'b'}},
		{name: "a subnegotiation", input: []byte{'a', iac, sb, 24, 0, 'x', iac, se, 'b'}, want: []byte("ab")},
		{name: "an escaped IAC inside a subnegotiation", input: []byte{iac, sb, 24, iac, iac, iac, se, 'b'}, want: []byte("b")},
		{name: "a data byte that looks like a command number", input: []byte{250, 240}, want: []byte{250, 240}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var p parser
			var got []byte
			for _, b := range tt.input {
				out, data, err := p.feed(b)
				if err != nil {
					t.Fatalf("feed(%d) = %v", b, err)
				}
				if data {
					got = append(got, out)
				}
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("data = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParser_Subnegotiation_TooLong_Fails(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		length  int
		wantErr bool
	}{
		{name: "at the limit", length: maxSubnegotiation},
		{name: "one more", length: maxSubnegotiation + 1, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var p parser
			var err error
			for _, b := range append([]byte{iac, sb}, bytes.Repeat([]byte{'x'}, tt.length)...) {
				if _, _, err = p.feed(b); err != nil {
					break
				}
			}
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Errorf("error = %v, want an error = %v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, errSubnegotiationTooLong) {
				t.Errorf("error = %v, want errSubnegotiationTooLong", err)
			}
		})
	}
}

// Escaped bytes and bytes that do not belong in a subnegotiation count as
// well, or a client could make the parser skip without end.
func TestParser_Subnegotiation_CountsEveryByte(t *testing.T) {
	t.Parallel()

	var p parser
	var err error
	for _, b := range append([]byte{iac, sb}, bytes.Repeat([]byte{iac, iac}, maxSubnegotiation+1)...) {
		if _, _, err = p.feed(b); err != nil {
			break
		}
	}
	if !errors.Is(err, errSubnegotiationTooLong) {
		t.Errorf("error = %v, want errSubnegotiationTooLong for escaped bytes", err)
	}

	p, err = parser{}, nil
	for _, b := range append([]byte{iac, sb}, bytes.Repeat([]byte{iac, 1}, maxSubnegotiation+1)...) {
		if _, _, err = p.feed(b); err != nil {
			break
		}
	}
	if !errors.Is(err, errSubnegotiationTooLong) {
		t.Errorf("error = %v, want errSubnegotiationTooLong for commands inside it", err)
	}
}

func TestLineReader_Lines(t *testing.T) {
	t.Parallel()

	got, err := readAll([]byte("one\r\ntwo\r\x00three\nfour\rfive"), 100)
	if err == nil {
		t.Fatal("error = nil, want the end of the stream")
	}
	var texts []string
	for _, ln := range got {
		texts = append(texts, string(ln.text))
	}
	want := []string{"one", "two", "three", "four"}
	if !slices.Equal(texts, want) {
		t.Errorf("lines = %q, want %q", texts, want)
	}
}

func TestLineReader_KeepsTheStartAndCountsAll(t *testing.T) {
	t.Parallel()

	got, _ := readAll([]byte("abcdefghij\r\n"), 4)
	if len(got) != 1 || string(got[0].text) != "abcd" || got[0].n != 10 {
		t.Errorf("lines = %+v, want the text abcd and a count of 10", got)
	}
}

func TestLineReader_Echo_ReceivesPrintableBytesInOrder(t *testing.T) {
	t.Parallel()

	var echoed []byte
	l := &lineReader{r: bufio.NewReader(bytes.NewReader([]byte("a\x01 b\xff\xffc\r\n")))}
	if _, err := l.read(10, func(b []byte) error { echoed = append(echoed, b...); return nil }); err != nil {
		t.Fatal(err)
	}
	if string(echoed) != "a bc" {
		t.Errorf("echoed = %q, want %q", echoed, "a bc")
	}
}

func TestLineReader_FailingEcho_StopsTheRead(t *testing.T) {
	t.Parallel()

	l := &lineReader{r: bufio.NewReader(bytes.NewReader([]byte("abc\r\n")))}
	want := errors.New("echo failed")
	ln, err := l.read(10, func([]byte) error { return want })
	if !errors.Is(err, want) || ln.complete {
		t.Errorf("read() = %+v, %v; want the error of the echo and an incomplete line", ln, err)
	}
}

// What one read of the connection brought is shown in one piece, and what
// arrives byte by byte is shown byte by byte.
func TestLineReader_Echo_FollowsTheReadsOfTheConnection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		reads []string
		want  []string
	}{
		{name: "a name in one piece", reads: []string{"root\r\n"}, want: []string{"root"}},
		{name: "a name typed by hand", reads: []string{"r", "o", "o", "t", "\r\n"}, want: []string{"r", "o", "o", "t"}},
		{name: "two pieces", reads: []string{"ro", "ot\r\n"}, want: []string{"ro", "ot"}},
		{name: "a name that is cut", reads: []string{strings.Repeat("a", 300) + "\r\n"}, want: []string{strings.Repeat("a", 256)}},
		{name: "a name that is cut and typed on", reads: []string{strings.Repeat("a", 255), "bcd", "\r\n"}, want: []string{strings.Repeat("a", 255), "b"}},
		{name: "control bytes only", reads: []string{"\x01\x02\r\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			l := &lineReader{r: bufio.NewReader(&pieces{reads: tt.reads})}
			var shown []string
			if _, err := l.read(256, func(b []byte) error { shown = append(shown, string(b)); return nil }); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(shown, tt.want) {
				t.Errorf("echoed %q, want %q", shown, tt.want)
			}
		})
	}
}

// pieces is a connection that delivers one piece for each read.
type pieces struct{ reads []string }

func (p *pieces) Read(b []byte) (int, error) {
	if len(p.reads) == 0 {
		return 0, io.EOF
	}
	n := copy(b, p.reads[0])
	p.reads[0] = p.reads[0][n:]
	if p.reads[0] == "" {
		p.reads = p.reads[1:]
	}
	return n, nil
}

func FuzzParser(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		[]byte("root\r\n"),
		{iac, will, 1, iac, do, 3},
		{iac, sb, 24, 0, 'x', iac, se},
		{iac, iac, iac, sb, iac, iac, iac, se},
		bytes.Repeat([]byte{iac, sb}, 10),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		var p parser
		var data int
		for _, b := range in {
			_, isData, err := p.feed(b)
			if err != nil {
				if !errors.Is(err, errSubnegotiationTooLong) {
					t.Fatalf("feed() = %v, want only errSubnegotiationTooLong", err)
				}
				return
			}
			if isData {
				data++
			}
			if p.subLen > maxSubnegotiation {
				t.Fatalf("subLen = %d, beyond the limit", p.subLen)
			}
		}
		if data > len(in) {
			t.Fatalf("%d data bytes from %d bytes", data, len(in))
		}
	})
}

func FuzzLineReader(f *testing.F) {
	for _, seed := range []string{"", "root\r\nsecret\r\n", "a\r\x00b\n\rc", "\xff\xfa\x18xterm\xff\xf0ok\r\n", strings.Repeat("\xff", 9)} {
		f.Add([]byte(seed), 8)
	}
	f.Fuzz(func(t *testing.T, in []byte, keep int) {
		keep = min(max(keep, 0), 256)
		l := &lineReader{r: bufio.NewReader(bytes.NewReader(in))}
		var total int
		for {
			ln, err := l.read(keep, nil)
			if len(ln.text) > keep {
				t.Fatalf("kept %d bytes, limit %d", len(ln.text), keep)
			}
			if ln.n < len(ln.text) {
				t.Fatalf("counted %d bytes but kept %d", ln.n, len(ln.text))
			}
			if bytes.ContainsAny(ln.text, "\r\n\x00") {
				t.Fatalf("text %q holds a line end", ln.text)
			}
			total += ln.n
			if total > len(in) {
				t.Fatalf("%d data bytes from %d bytes", total, len(in))
			}
			if !ln.complete {
				if err == nil {
					t.Fatal("incomplete line without an error")
				}
				return
			}
		}
	})
}
