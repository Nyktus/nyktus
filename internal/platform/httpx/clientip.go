// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

type clientIPKey struct{}

// ClientIPFrom returns the client address stored in ctx by the ClientIP
// middleware. The zero Addr means that the address is unknown.
func ClientIPFrom(ctx context.Context) netip.Addr {
	addr, _ := ctx.Value(clientIPKey{}).(netip.Addr)
	return addr
}

// ClientIP determines the address of the client once per request and stores it
// in the request context.
//
// The address of the socket counts unless it lies within one of the trusted
// ranges, which belong to reverse proxies. Only then is X-Forwarded-For evaluated,
// from right to left: each proxy appends the address it received the request
// from, so the entries on the right were written by trusted proxies and the
// first untrusted one is the client. Everything left of it was sent by the
// client and can be forged. This works for chains of proxies without counting
// hops. A fixed hop count is not used, because it would trust the header even
// when a client bypasses the proxy and connects directly. X-Real-IP is ignored.
//
// An entry that is not an address ends the search, because the proxy that
// appended it cannot be identified. The last address read before it is the
// best one known.
func ClientIP(trusted []netip.Prefix) Middleware {
	trusted = slices.Clone(trusted)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), clientIPKey{}, clientIP(r, trusted))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func clientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	socket, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	addr := canonicalAddr(socket.Addr())
	if !isTrusted(addr, trusted) {
		return addr
	}

	// Several header lines form one list, in the order in which they arrived.
	entries := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for _, entry := range slices.Backward(entries) {
		next, err := netip.ParseAddr(strings.TrimSpace(entry))
		if err != nil {
			return addr
		}
		addr = canonicalAddr(next)
		if !isTrusted(addr, trusted) {
			return addr
		}
	}
	return addr
}

// canonicalAddr gives every client exactly one spelling: a dual-stack socket
// reports an IPv4 client as ::ffff:a.b.c.d, and a zone only names the interface
// that received the request. netip.Prefix.Contains never matches an address with
// a zone.
func canonicalAddr(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	return slices.ContainsFunc(trusted, func(p netip.Prefix) bool { return p.Contains(addr) })
}
