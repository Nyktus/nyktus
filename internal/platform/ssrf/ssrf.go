// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ssrf guards requests to URLs that users supply, such as the targets
// of alert channels, against reaching internal systems.
//
// A Guard checks a URL when it is saved, so that a mistake shows at once, and
// every connection when it is made, because the name of a host can resolve to
// another address by then. The client of a Guard resolves the name itself,
// checks every address, and dials exactly an address it checked; the control
// function of its dialer checks that address once more. Nothing that the
// server learns between the check and the connection can change the target.
package ssrf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

var (
	// ErrInvalidURL means that a URL is malformed, uses a scheme other than
	// https, or names a host in a form that no regular target uses.
	ErrInvalidURL = errors.New("ssrf: invalid URL")
	// ErrBlocked means that a target is not allowed: its name or one of its
	// addresses is internal, or its name does not resolve. Both look the same,
	// so that the check cannot tell which internal names exist.
	ErrBlocked = errors.New("ssrf: target not allowed")
)

// MaxURLLength bounds a URL that a Guard accepts.
const MaxURLLength = 2048

// never are ranges that no configuration opens. They reach the host itself,
// its link, the metadata services of cloud providers, or addresses that are
// not unicast or not in use. Loopback, link-local, multicast, unspecified and
// broadcast addresses are recognized by netip as well.
var never = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	// The metadata service of Alibaba Cloud lies within the shared address
	// space of carrier-grade NAT.
	netip.MustParsePrefix("100.100.100.200/32"),
	// IPv4-compatible and IPv4-translated addresses embed an IPv4 address
	// that some stacks reach directly.
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::ffff:0:0:0/96"),
	// The local-use prefix of NAT64 embeds IPv4 addresses at a position that
	// depends on the network; unlike the well-known prefix, it is not
	// unwrapped and checked.
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	// Teredo and 6to4 tunnel to IPv4 addresses that they embed.
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("ff00::/8"),
	// The metadata service of AWS over IPv6 lies within the unique local
	// addresses, which an operator may allow.
	netip.MustParsePrefix("fd00:ec2::254/128"),
}

// internal are ranges that are not reachable from the internet. An operator
// can allow parts of them for targets in their own networks.
var internal = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// nat64 is the well-known prefix of NAT64. On networks that reach IPv4 only
// through it, every IPv4 target resolves to an address within it, so it is
// unwrapped and the embedded IPv4 address is checked instead.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// Options configures a Guard.
type Options struct {
	// AllowedNetworks are internal networks that targets may be in, chosen by
	// the operator, such as the network of a SOAR platform. They never open
	// loopback, link-local or metadata addresses.
	AllowedNetworks []netip.Prefix
	// AllowHTTP admits plain http besides https. It is for development only.
	AllowHTTP bool
}

// Guard decides which targets requests may reach. It is safe for concurrent
// use.
type Guard struct {
	allowed   []netip.Prefix
	allowHTTP bool
	// lookup resolves a host name. Tests replace it.
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// connect dials an address that the guard checked. Tests replace it.
	connect func(ctx context.Context, network, address string) (net.Conn, error)
}

// New returns a Guard for o.
func New(o Options) *Guard {
	g := &Guard{allowed: slices.Clone(o.AllowedNetworks), allowHTTP: o.AllowHTTP}
	g.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	d := &net.Dialer{Timeout: dialTimeout, KeepAlive: keepAlive, Control: g.control}
	g.connect = d.DialContext
	return g
}

// Allowed reports whether a may be dialed.
func (g *Guard) Allowed(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	if nat64.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte(b[12:]))
	}
	if !a.IsValid() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() ||
		!a.IsGlobalUnicast() || containsAddr(never, a) {
		return false
	}
	if !containsAddr(internal, a) {
		return true
	}
	return containsAddr(g.allowed, a)
}

func containsAddr(prefixes []netip.Prefix, a netip.Addr) bool {
	return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(a) })
}

// blockedSuffixes are names under which hosts are internal by convention.
// They are rejected before they are resolved, unless the operator allowed
// internal networks, where such names are what targets are called.
var blockedSuffixes = []string{".local", ".internal", ".lan", ".home.arpa", ".intranet", ".corp", ".private"}

// CheckURL parses s and checks that a request to it is allowed: the scheme is
// https, or http if allowed, the host is a name or an address without user
// information or fragment, and the name resolves to allowed addresses only. It
// returns ErrInvalidURL or ErrBlocked.
func (g *Guard) CheckURL(ctx context.Context, s string) (*url.URL, error) {
	u, host, err := g.parse(s)
	if err != nil {
		return nil, err
	}
	if _, err := g.resolve(ctx, host); err != nil {
		return nil, ErrBlocked
	}
	return u, nil
}

// parse checks the form of s and returns the URL and its host.
func (g *Guard) parse(s string) (*url.URL, string, error) {
	if len(s) > MaxURLLength {
		return nil, "", ErrInvalidURL
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return nil, "", ErrInvalidURL
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" || u.Fragment != "" || u.User != nil || !g.schemeAllowed(u.Scheme) {
		return nil, "", ErrInvalidURL
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" || (u.Port() != "" && !validPort(u.Port())) {
		return nil, "", ErrInvalidURL
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return u, host, nil
	}
	// A resolver may read a name whose last label is a number, such as
	// 2130706433 or 0x7f.1, as an IPv4 address. No regular target is called
	// like that.
	labels := strings.Split(host, ".")
	last := labels[len(labels)-1]
	if numericLabel(last) {
		return nil, "", ErrInvalidURL
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return nil, "", ErrBlocked
	}
	// A name of one label is completed with the search domains of the host,
	// which name internal hosts.
	if len(g.allowed) == 0 && (len(labels) == 1 || slices.ContainsFunc(blockedSuffixes, func(suffix string) bool {
		return strings.HasSuffix(host, suffix)
	})) {
		return nil, "", ErrBlocked
	}
	return u, host, nil
}

// numericLabel reports whether label is a decimal number or a hexadecimal one
// with the prefix 0x.
func numericLabel(label string) bool {
	if hex, ok := strings.CutPrefix(label, "0x"); ok {
		return strings.Trim(hex, "0123456789abcdef") == ""
	}
	return label != "" && strings.Trim(label, "0123456789") == ""
}

func (g *Guard) schemeAllowed(scheme string) bool {
	return scheme == "https" || (g.allowHTTP && scheme == "http")
}

func validPort(p string) bool {
	if len(p) > 5 || strings.Trim(p, "0123456789") != "" {
		return false
	}
	n := 0
	for _, c := range p {
		n = n*10 + int(c-'0')
	}
	return n >= 1 && n <= 65535
}

// resolve returns the addresses of host, a name or an address. Every address
// must be allowed: a name that resolves to an internal address besides public
// ones is a sign of an attack on the check.
func (g *Guard) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		if !g.Allowed(a) {
			return nil, ErrBlocked
		}
		return []netip.Addr{a}, nil
	}
	addrs, err := g.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, ErrBlocked
	}
	for _, a := range addrs {
		if !g.Allowed(a) {
			return nil, ErrBlocked
		}
	}
	return addrs, nil
}
