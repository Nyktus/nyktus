// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ssrf

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// lastAddr returns the last address of p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	bits := p.Bits()
	for i := range b {
		for j := range 8 {
			if i*8+j >= bits {
				b[i] |= 0x80 >> j
			}
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

func TestAllowed_BlocksEveryReservedRange(t *testing.T) {
	t.Parallel()

	g := New(Options{})
	var addrs []netip.Addr
	for _, p := range append(append([]netip.Prefix{}, never...), internal...) {
		addrs = append(addrs, p.Masked().Addr(), lastAddr(p))
	}
	for _, s := range []string{
		"127.0.0.1", "::1", "0.0.0.0", "::", "255.255.255.255", "169.254.169.254", "fe80::1", "fe80::1%eth0",
		"ff02::1", "239.255.255.250", "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1",
		"fd00::1", "fd00:ec2::254", "100.100.100.200",
		// Mapped, compatible and translated forms of internal IPv4 addresses.
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::127.0.0.1", "::ffff:0:7f00:1",
		// NAT64 with an internal IPv4 address.
		"64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::a00:1",
		// Tunnels that embed IPv4 addresses.
		"2002:7f00:1::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
	} {
		addrs = append(addrs, netip.MustParseAddr(s))
	}
	for _, a := range addrs {
		if g.Allowed(a) {
			t.Errorf("Allowed(%s) = true, want false", a)
		}
	}
}

func TestAllowed_AdmitsPublicAddresses(t *testing.T) {
	t.Parallel()

	g := New(Options{})
	for _, s := range []string{
		"8.8.8.8", "1.1.1.1", "93.184.215.14", "2606:4700:4700::1111", "2a00:1450:4001:80b::200e",
		"::ffff:8.8.8.8",
		// NAT64 with a public IPv4 address, as on networks that reach IPv4
		// only through it.
		"64:ff9b::808:808",
	} {
		if a := netip.MustParseAddr(s); !g.Allowed(a) {
			t.Errorf("Allowed(%s) = false, want true", a)
		}
	}
}

func TestAllowed_AllowedNetworksOpenOnlyInternalRanges(t *testing.T) {
	t.Parallel()

	g := New(Options{AllowedNetworks: []netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/16"),
		netip.MustParsePrefix("fc00::/7"),
		// Even everything opens nothing that is never allowed.
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}})
	for _, s := range []string{"10.20.1.2", "192.168.1.1", "fd12::1", "8.8.8.8"} {
		if !g.Allowed(netip.MustParseAddr(s)) {
			t.Errorf("Allowed(%s) = false, want true", s)
		}
	}
	for _, s := range []string{
		"127.0.0.1", "::1", "169.254.169.254", "fe80::1", "100.100.100.200", "fd00:ec2::254", "0.0.0.0",
		"224.0.0.1", "64:ff9b::7f00:1",
	} {
		if g.Allowed(netip.MustParseAddr(s)) {
			t.Errorf("Allowed(%s) = true, want false", s)
		}
	}

	narrow := New(Options{AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("10.20.1.9/16")}})
	if !narrow.Allowed(netip.MustParseAddr("10.20.200.1")) || narrow.Allowed(netip.MustParseAddr("10.21.0.1")) {
		t.Error("an allowed network with host bits set does not cover exactly its masked range")
	}
}

// fakeLookup resolves names from a map and fails for others.
func fakeLookup(names map[string][]string) func(context.Context, string) ([]netip.Addr, error) {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		ss, ok := names[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		addrs := make([]netip.Addr, len(ss))
		for i, s := range ss {
			addrs[i] = netip.MustParseAddr(s)
		}
		return addrs, nil
	}
}

func TestCheckURL(t *testing.T) {
	t.Parallel()

	names := map[string][]string{
		"hooks.example.com": {"93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"},
		"shop.cafe":         {"93.184.215.14"},
		"mixed.example.com": {"93.184.215.14", "10.0.0.1"},
		"empty.example.com": {},
		"soar.internal":     {"10.20.0.5"},
		"soar":              {"10.20.0.5"},
		"rebind.example":    {"127.0.0.1"},
		// Names that are internal by convention are rejected before they are
		// resolved, whatever they resolve to.
		"localhost":       {"93.184.215.14"},
		"a.localhost":     {"93.184.215.14"},
		"public.internal": {"93.184.215.14"},
		"intranet":        {"93.184.215.14"},
	}
	strict := New(Options{})
	strict.lookup = fakeLookup(names)
	dev := New(Options{AllowHTTP: true})
	dev.lookup = fakeLookup(names)
	inside := New(Options{AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}})
	inside.lookup = fakeLookup(names)

	tests := []struct {
		name  string
		guard *Guard
		url   string
		want  error
	}{
		{"https name", strict, "https://hooks.example.com/services/T0/B0/x?token=y", nil},
		{"port", strict, "https://hooks.example.com:8088/", nil},
		{"trailing dot", strict, "https://hooks.example.com./x", nil},
		{"upper case", strict, "https://HOOKS.example.com/x", nil},
		{"top-level domain of hex letters", strict, "https://shop.cafe/", nil},
		{"public address", strict, "https://93.184.215.14/x", nil},
		{"http", strict, "http://hooks.example.com/", ErrInvalidURL},
		{"http in development", dev, "http://hooks.example.com/", nil},
		{"other scheme", dev, "ftp://hooks.example.com/", ErrInvalidURL},
		{"no scheme", strict, "hooks.example.com/x", ErrInvalidURL},
		{"opaque", strict, "https:hooks.example.com", ErrInvalidURL},
		{"user information", strict, "https://user:pass@hooks.example.com/", ErrInvalidURL},
		{"fragment", strict, "https://hooks.example.com/#x", ErrInvalidURL},
		{"space", strict, "https://hooks.example.com/a b", ErrInvalidURL},
		{"control character", strict, "https://hooks.example.com/\x7f", ErrInvalidURL},
		{"non-ASCII", strict, "https://hooks.example.com/\u00e4", ErrInvalidURL},
		{"too long", strict, "https://hooks.example.com/" + strings.Repeat("a", MaxURLLength), ErrInvalidURL},
		{"empty host", strict, "https:///x", ErrInvalidURL},
		{"port 0", strict, "https://hooks.example.com:0/", ErrInvalidURL},
		{"port too large", strict, "https://hooks.example.com:65536/", ErrInvalidURL},
		{"decimal address", strict, "https://2130706433/", ErrInvalidURL},
		{"hexadecimal address", strict, "https://0x7f.1/", ErrInvalidURL},
		{"numeric last label", strict, "https://hooks.example.123/", ErrInvalidURL},
		{"loopback", strict, "https://127.0.0.1/", ErrBlocked},
		{"loopback in IPv6", strict, "https://[::1]/", ErrBlocked},
		{"mapped loopback", strict, "https://[::ffff:127.0.0.1]/", ErrBlocked},
		{"metadata", strict, "https://169.254.169.254/latest/meta-data/", ErrBlocked},
		{"private address", strict, "https://10.0.0.1/", ErrBlocked},
		{"localhost", strict, "https://localhost/", ErrBlocked},
		{"under localhost", strict, "https://a.localhost/", ErrBlocked},
		{"internal name", strict, "https://soar.internal/", ErrBlocked},
		{"one label", strict, "https://intranet/", ErrBlocked},
		{"internal name with a public address", strict, "https://public.internal/", ErrBlocked},
		{"resolves to loopback", strict, "https://rebind.example/", ErrBlocked},
		{"resolves to public and private", strict, "https://mixed.example.com/", ErrBlocked},
		{"resolves to nothing", strict, "https://empty.example.com/", ErrBlocked},
		{"does not resolve", strict, "https://unknown.example.com/", ErrBlocked},
		{"allowed internal name", inside, "https://soar.internal/", nil},
		{"allowed one label", inside, "https://soar/", nil},
		{"allowed address", inside, "https://10.20.0.5/", nil},
		{"internal address outside the allowed network", inside, "https://10.21.0.5/", ErrBlocked},
		{"localhost despite allowed networks", inside, "https://localhost/", ErrBlocked},
	}
	for _, tt := range tests {
		_, err := tt.guard.CheckURL(t.Context(), tt.url)
		if !errors.Is(err, tt.want) || (tt.want == nil && err != nil) {
			t.Errorf("%s: CheckURL(%q) error = %v, want %v", tt.name, tt.url, err, tt.want)
		}
	}
}
