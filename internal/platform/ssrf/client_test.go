// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ssrf

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// dialRecorder replaces the dialer of a guard: it records the addresses that
// the guard dials and connects every one of them to a test server instead.
type dialRecorder struct {
	mu     sync.Mutex
	dialed []string
	server string
}

func (d *dialRecorder) connect(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, address)
	d.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, d.server)
}

func (d *dialRecorder) addresses() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialed...)
}

// newTestGuard returns a guard in development mode whose names resolve
// through names and whose connections reach srv.
func newTestGuard(srv *httptest.Server, names map[string][]string) (*Guard, *dialRecorder) {
	g := New(Options{AllowHTTP: true})
	g.lookup = fakeLookup(names)
	d := &dialRecorder{server: srv.Listener.Addr().String()}
	g.connect = d.connect
	return g, d
}

// send sends a request with the context of the test.
func send(t *testing.T, c *http.Client, method, url string, body io.Reader) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, body)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, url, err)
	}
	return c.Do(req)
}

func TestClient_DialsTheCheckedAddress(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	g, d := newTestGuard(srv, map[string][]string{"hooks.example.com": {"93.184.215.14"}})

	resp, err := send(t, g.Client(), http.MethodGet, "http://hooks.example.com:8080/x", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if got := d.addresses(); len(got) != 1 || got[0] != "93.184.215.14:8080" {
		t.Errorf("dialed %v, want [93.184.215.14:8080]", got)
	}
}

// A name that resolved to a public address when it was saved and resolves to
// an internal one when the request is sent never reaches the internal address.
func TestClient_DNSRebindingBetweenCheckAndConnect_IsBlocked(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the request reached the server")
	}))
	t.Cleanup(srv.Close)
	g, d := newTestGuard(srv, nil)
	var lookups atomic.Int32
	g.lookup = func(context.Context, string) ([]netip.Addr, error) {
		if lookups.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("93.184.215.14")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}

	if _, err := g.CheckURL(t.Context(), "http://rebind.example.com/"); err != nil {
		t.Fatalf("CheckURL: %v", err)
	}
	resp, err := send(t, g.Client(), http.MethodGet, "http://rebind.example.com/", nil)
	if err == nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, ErrBlocked) {
		t.Errorf("Get error = %v, want ErrBlocked", err)
	}
	if got := d.addresses(); len(got) != 0 {
		t.Errorf("dialed %v, want nothing", got)
	}
}

func TestClient_NameWithAnInternalAddress_IsBlocked(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the request reached the server")
	}))
	t.Cleanup(srv.Close)
	g, d := newTestGuard(srv, map[string][]string{"mixed.example.com": {"93.184.215.14", "10.0.0.1"}})

	resp, err := send(t, g.Client(), http.MethodGet, "http://mixed.example.com/", nil)
	if err == nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, ErrBlocked) {
		t.Errorf("Get error = %v, want ErrBlocked", err)
	}
	if got := d.addresses(); len(got) != 0 {
		t.Errorf("dialed %v, want nothing", got)
	}
}

func TestClient_ChecksEveryRequest(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the request reached the server")
	}))
	t.Cleanup(srv.Close)
	names := map[string][]string{"hooks.example.com": {"93.184.215.14"}, "soar.internal": {"93.184.215.14"}}

	strict, d := newTestGuard(srv, names)
	strict.allowHTTP = false
	for _, u := range []string{
		"http://hooks.example.com/", "https://127.0.0.1/", "https://localhost/", "https://soar.internal/",
		"https://user:pass@hooks.example.com/",
	} {
		resp, err := send(t, strict.Client(), http.MethodGet, u, nil)
		if err == nil {
			_ = resp.Body.Close()
			t.Errorf("Get(%q) succeeded, want an error", u)
		}
	}
	if got := d.addresses(); len(got) != 0 {
		t.Errorf("dialed %v, want nothing", got)
	}
}

func TestClient_DoesNotFollowRedirects(t *testing.T) {
	t.Parallel()

	var followed atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "http://hooks.example.com/target")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/target", func(http.ResponseWriter, *http.Request) { followed.Store(true) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	g, _ := newTestGuard(srv, map[string][]string{"hooks.example.com": {"93.184.215.14"}})

	resp, err := send(t, g.Client(), http.MethodPost, "http://hooks.example.com/start", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want the redirect itself (%d)", resp.StatusCode, http.StatusFound)
	}
	if followed.Load() {
		t.Error("the client followed the redirect")
	}
}

func TestClient_LimitsTheResponseBody(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/limit", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, MaxResponseBody))
	})
	mux.HandleFunc("/over", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, MaxResponseBody+1))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	g, _ := newTestGuard(srv, map[string][]string{"hooks.example.com": {"93.184.215.14"}})
	c := g.Client()

	read := func(path string) (int, error) {
		resp, err := send(t, c, http.MethodGet, "http://hooks.example.com"+path, nil)
		if err != nil {
			t.Fatalf("Get(%s): %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		return len(b), err
	}
	if n, err := read("/limit"); err != nil || n != MaxResponseBody {
		t.Errorf("body at the limit: read %d bytes, error %v; want %d bytes", n, err, MaxResponseBody)
	}
	if n, err := read("/over"); !errors.Is(err, ErrResponseTooLarge) || n > MaxResponseBody {
		t.Errorf("body over the limit: read %d bytes, error %v; want at most %d bytes and ErrResponseTooLarge",
			n, err, MaxResponseBody)
	}
}

func TestClient_IgnoresTheProxyOfTheEnvironment(t *testing.T) {
	t.Parallel()

	c := New(Options{}).Client()
	tr, ok := c.Transport.(*transport)
	if !ok {
		t.Fatalf("transport = %T", c.Transport)
	}
	if next, ok := tr.next.(*http.Transport); !ok || next.Proxy != nil {
		t.Error("the transport takes a proxy, whose address the guard would not check")
	}
	if c.Timeout != RequestTimeout {
		t.Errorf("timeout = %v, want %v", c.Timeout, RequestTimeout)
	}
}

// The dialer of a guard checks the address it actually connects to, also for
// a connection that does not pass through dial.
func TestDialer_ControlRejectsBlockedAddresses(t *testing.T) {
	t.Parallel()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	g := New(Options{AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}})
	conn, err := g.connect(t.Context(), "tcp", ln.Addr().String())
	if err == nil {
		_ = conn.Close()
	}
	if !errors.Is(err, ErrBlocked) {
		t.Errorf("connect to %s: error = %v, want ErrBlocked", ln.Addr(), err)
	}
}

func TestControl(t *testing.T) {
	t.Parallel()

	g := New(Options{})
	tests := []struct {
		network, address string
		want             error
	}{
		{"tcp4", "93.184.215.14:443", nil},
		{"tcp6", "[2606:4700:4700::1111]:443", nil},
		{"tcp4", "127.0.0.1:443", ErrBlocked},
		{"tcp6", "[::1]:443", ErrBlocked},
		{"tcp6", "[::ffff:169.254.169.254]:80", ErrBlocked},
		{"tcp6", "[fe80::1%eth0]:80", ErrBlocked},
		{"udp4", "93.184.215.14:53", ErrBlocked},
		{"tcp4", "not an address", ErrBlocked},
	}
	for _, tt := range tests {
		if err := g.control(tt.network, tt.address, nil); !errors.Is(err, tt.want) || (tt.want == nil && err != nil) {
			t.Errorf("control(%s, %s) = %v, want %v", tt.network, tt.address, err, tt.want)
		}
	}
}
