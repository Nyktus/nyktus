// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ssrf

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

const (
	dialTimeout = 5 * time.Second
	tlsTimeout  = 5 * time.Second
	keepAlive   = 30 * time.Second
	// RequestTimeout bounds a request of the client, from resolving the name
	// to reading the body.
	RequestTimeout = 10 * time.Second
	// MaxResponseBody bounds what the client reads of a response body.
	// Callers discard the body; it is read so that the connection can be
	// reused.
	MaxResponseBody = 64 << 10
	// maxResponseHeader bounds the headers of a response.
	maxResponseHeader = 16 << 10
)

// ErrResponseTooLarge means that a response body exceeded MaxResponseBody.
var ErrResponseTooLarge = errors.New("ssrf: response body too large")

// Client returns an HTTP client that reaches allowed targets only. Every
// request is checked like CheckURL, without resolving the name in advance:
// the client resolves it when it connects, checks every address and dials one
// of them. It follows no redirect and returns the redirect response instead,
// ignores the proxy settings of the environment, whose proxy would be the
// address dialed, and bounds the time of a request and the size of its
// response. Callers keep the client for the connections it pools.
func (g *Guard) Client() *http.Client {
	t := &http.Transport{
		// An explicit nil keeps HTTP_PROXY and HTTPS_PROXY from routing
		// requests through a host that the guard did not check.
		Proxy:                  nil,
		DialContext:            g.dial,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    tlsTimeout,
		ResponseHeaderTimeout:  RequestTimeout,
		MaxResponseHeaderBytes: maxResponseHeader,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           16,
		IdleConnTimeout:        30 * time.Second,
	}
	return &http.Client{
		Transport: &transport{guard: g, next: t},
		Timeout:   RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// transport checks every request before it is sent and bounds its response.
type transport struct {
	guard *Guard
	next  http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if _, _, err := t.guard.parse(req.URL.String()); err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitedBody{body: resp.Body, left: MaxResponseBody}
	return resp, nil
}

// limitedBody fails a read beyond MaxResponseBody.
type limitedBody struct {
	body io.ReadCloser
	left int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, ErrResponseTooLarge
	}
	// One byte more than allowed tells a body at the limit from a longer one.
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.body.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return n + int(b.left), ErrResponseTooLarge
	}
	return n, err
}

func (b *limitedBody) Close() error { return b.body.Close() }

// dial resolves the host of address, checks every address it resolves to,
// and dials them one after another until a connection succeeds. A blocked
// target fails with ErrBlocked, a name that does not resolve with another
// error, because a resolver can fail for a while.
func (g *Guard) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("ssrf: dial %q: %w", address, err)
	}
	addrs, err := g.resolve(ctx, host)
	if err != nil {
		if errors.Is(err, ErrBlocked) {
			return nil, ErrBlocked
		}
		return nil, fmt.Errorf("ssrf: resolve: %w", err)
	}
	var errs []error
	for _, a := range addrs {
		conn, err := g.connect(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

// control is the control function of the dialer. It checks the address that
// is actually dialed, as a second line behind dial, so that a dialer that ever
// resolves on its own still reaches no blocked address.
func (g *Guard) control(network, address string, _ syscall.RawConn) error {
	if network != "tcp4" && network != "tcp6" {
		return ErrBlocked
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !g.Allowed(ap.Addr()) {
		return ErrBlocked
	}
	return nil
}
