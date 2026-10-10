// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"nyktus.org/nyktus/internal/platform/request"
)

func TestClientIP(t *testing.T) {
	t.Parallel()

	trusted := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8:1::/48"),
	}
	tests := []struct {
		name    string
		trusted []netip.Prefix
		remote  string
		xff     []string
		want    string
	}{
		{
			name:   "socket without trusted proxies",
			remote: "198.51.100.7:4711",
			xff:    []string{"203.0.113.9"},
			want:   "198.51.100.7",
		},
		{
			name:    "client bypasses the proxy and forges the header",
			trusted: trusted,
			remote:  "198.51.100.7:4711",
			xff:     []string{"203.0.113.9, 10.0.0.2"},
			want:    "198.51.100.7",
		},
		{
			name:    "one trusted proxy",
			trusted: trusted,
			remote:  "10.0.0.2:4711",
			xff:     []string{"203.0.113.9"},
			want:    "203.0.113.9",
		},
		{
			name:    "chain of trusted proxies",
			trusted: trusted,
			remote:  "10.0.0.2:4711",
			xff:     []string{"203.0.113.9, 10.1.0.1 , 10.2.0.1"},
			want:    "203.0.113.9",
		},
		{
			name:    "entries forged by the client are left of the client",
			trusted: trusted,
			remote:  "10.0.0.2:4711",
			xff:     []string{"10.9.9.9, 192.0.2.1, 203.0.113.9"},
			want:    "203.0.113.9",
		},
		{
			name:    "several header lines in order",
			trusted: trusted,
			remote:  "10.0.0.2:4711",
			xff:     []string{"192.0.2.1, 203.0.113.9", "10.1.0.1"},
			want:    "203.0.113.9",
		},
		{
			name:    "trusted proxy without header",
			trusted: trusted,
			remote:  "10.0.0.2:4711",
			want:    "10.0.0.2",
		},
		{
			name:    "invalid entry ends the search at the last known address",
			trusted: trusted,
			remote:  "10.0.0.2:4711",
			xff:     []string{"203.0.113.9, unknown, 10.1.0.1"},
			want:    "10.1.0.1",
		},
		{
			name:    "IPv4 entry with a port",
			trusted: trusted,
			remote:  "10.0.0.2:4711",
			xff:     []string{"203.0.113.9:80"},
			want:    "203.0.113.9",
		},
		{
			name:    "IPv6 entry in brackets with a port",
			trusted: trusted,
			remote:  "10.0.0.2:4711",
			xff:     []string{"[2001:db8:2::9]:80"},
			want:    "2001:db8:2::9",
		},
		{
			name:    "IPv6 entry in brackets",
			trusted: trusted,
			remote:  "10.0.0.2:4711",
			xff:     []string{"[2001:db8:2::9]"},
			want:    "2001:db8:2::9",
		},
		{
			name:    "trusted entry with a port is skipped",
			trusted: trusted,
			remote:  "10.0.0.2:4711",
			xff:     []string{"203.0.113.9, 10.1.0.1:443"},
			want:    "203.0.113.9",
		},
		{
			name:    "IPv4 address in brackets is invalid",
			trusted: trusted,
			remote:  "10.0.0.2:4711",
			xff:     []string{"[203.0.113.9]"},
			want:    "10.0.0.2",
		},
		{
			name:    "host name is invalid",
			trusted: trusted,
			remote:  "10.0.0.2:4711",
			xff:     []string{"client.example.com:80"},
			want:    "10.0.0.2",
		},
		{
			name:    "empty entry is invalid",
			trusted: trusted,
			remote:  "10.0.0.2:4711",
			xff:     []string{"203.0.113.9,,10.1.0.1"},
			want:    "10.1.0.1",
		},
		{
			name:    "only trusted addresses",
			trusted: trusted,
			remote:  "10.0.0.2:4711",
			xff:     []string{"10.3.0.1, 10.1.0.1"},
			want:    "10.3.0.1",
		},
		{
			name:    "IPv4-mapped socket address of a trusted proxy",
			trusted: trusted,
			remote:  "[::ffff:10.0.0.2]:4711",
			xff:     []string{"::ffff:203.0.113.9"},
			want:    "203.0.113.9",
		},
		{
			name:    "IPv6 proxy with zone",
			trusted: trusted,
			remote:  "[2001:db8:1::5%eth0]:4711",
			xff:     []string{"2001:db8:2::9"},
			want:    "2001:db8:2::9",
		},
		{
			name:   "X-Real-IP is ignored",
			remote: "198.51.100.7:4711",
			want:   "198.51.100.7",
		},
		{
			name:   "socket address that is not an IP address",
			remote: "@",
			want:   "invalid IP",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remote
			r.Header.Set("X-Real-IP", "192.0.2.200")
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}

			var got netip.Addr
			h := ClientIP(tt.trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = request.ClientIP(r.Context())
			}))
			h.ServeHTTP(httptest.NewRecorder(), r)
			if got.String() != tt.want {
				t.Errorf("request.ClientIP() = %s, want %s", got, tt.want)
			}
		})
	}
}
