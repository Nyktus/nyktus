// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package request

import (
	"net/netip"
	"testing"
)

func TestContextValues(t *testing.T) {
	t.Parallel()

	if ID(t.Context()) != "" || ClientIP(t.Context()).IsValid() {
		t.Error("an empty context carries request metadata")
	}
	ctx := WithClientIP(WithID(t.Context(), "abc"), netip.MustParseAddr("::ffff:192.0.2.1"))
	if ID(ctx) != "abc" || ClientIP(ctx) != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("ID = %q, ClientIP = %s; want abc and 192.0.2.1", ID(ctx), ClientIP(ctx))
	}
}

func TestCanonicalAddr(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		"192.0.2.1":           "192.0.2.1",
		"::ffff:192.0.2.1":    "192.0.2.1",
		"fe80::1%eth0":        "fe80::1",
		"2001:db8::1":         "2001:db8::1",
		"::ffff:192.0.2.1%en": "192.0.2.1",
	} {
		if got := CanonicalAddr(netip.MustParseAddr(in)); got.String() != want {
			t.Errorf("CanonicalAddr(%s) = %s, want %s", in, got, want)
		}
	}
}
