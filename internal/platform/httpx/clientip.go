// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"nyktus.org/nyktus/internal/platform/request"
)

// ClientIP determines the address of the client once per request and stores it
// in the request context, where request.ClientIP reads it.
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
			ctx := request.WithClientIP(r.Context(), clientIP(r, trusted))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func clientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	socket, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	addr := request.CanonicalAddr(socket.Addr())
	if !isTrusted(addr, trusted) {
		return addr
	}

	// Several header lines form one list, in the order in which they arrived.
	entries := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for _, entry := range slices.Backward(entries) {
		next, ok := parseForwardedAddr(strings.TrimSpace(entry))
		if !ok {
			return addr
		}
		addr = request.CanonicalAddr(next)
		if !isTrusted(addr, trusted) {
			return addr
		}
	}
	return addr
}

// parseForwardedAddr reads an X-Forwarded-For entry. Besides a bare address,
// some proxies append the port ("192.0.2.1:4711", "[2001:db8::1]:4711") or put
// an IPv6 address in brackets ("[2001:db8::1]"). The port is not needed.
func parseForwardedAddr(s string) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr, true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr(), true
	}
	if inner, ok := strings.CutPrefix(s, "["); ok {
		if inner, ok := strings.CutSuffix(inner, "]"); ok {
			if addr, err := netip.ParseAddr(inner); err == nil && addr.Is6() {
				return addr, true
			}
		}
	}
	return netip.Addr{}, false
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	return slices.ContainsFunc(trusted, func(p netip.Prefix) bool { return p.Contains(addr) })
}
