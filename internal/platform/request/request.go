// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package request carries metadata of the request being served in its context:
// the request ID and the address of the client. The HTTP middleware sets them;
// code below it, such as the audit log, reads them without depending on HTTP.
package request

import (
	"context"
	"net/netip"
)

type idKey struct{}

type clientIPKey struct{}

// WithID returns a copy of ctx that carries the request ID id.
func WithID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, idKey{}, id)
}

// ID returns the request ID carried by ctx, or an empty string.
func ID(ctx context.Context) string {
	id, _ := ctx.Value(idKey{}).(string)
	return id
}

// WithClientIP returns a copy of ctx that carries the client address addr in its
// canonical form.
func WithClientIP(ctx context.Context, addr netip.Addr) context.Context {
	return context.WithValue(ctx, clientIPKey{}, CanonicalAddr(addr))
}

// ClientIP returns the client address carried by ctx. The zero Addr means that
// the address is unknown.
func ClientIP(ctx context.Context) netip.Addr {
	addr, _ := ctx.Value(clientIPKey{}).(netip.Addr)
	return addr
}

// CanonicalAddr gives every client exactly one spelling: a dual-stack socket
// reports an IPv4 client as ::ffff:a.b.c.d, and a zone only names the interface
// that received the request. netip.Prefix.Contains never matches an address with
// a zone.
func CanonicalAddr(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}
