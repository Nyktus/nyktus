// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func dnsEnv() map[string]string {
	return map[string]string{
		"NYKTUS_DNS_DATABASE_URL": "postgres://dns@db/nyktus",
		"NYKTUS_DNS_ZONES":        "d.example.com",
		"NYKTUS_DNS_NAMESERVERS":  "ns1.example.net",
	}
}

func TestLoadServe_DNSDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := LoadServe(fakeSource{env: dnsEnv()}.source(), []Role{RoleDNS})
	if err != nil {
		t.Fatalf("LoadServe() error = %v", err)
	}
	d := cfg.DNS
	if d.Addr != "127.0.0.1:8053" || d.DatabaseURL.Value() != "postgres://dns@db/nyktus" || d.TTL != time.Minute || d.DatabaseMaxConns != 10 {
		t.Errorf("DNS = %+v, want loopback port 8053, the database URL and a TTL of one minute", d)
	}
	if d.AnswerIPv4.IsValid() || d.AnswerIPv6.IsValid() {
		t.Errorf("answer addresses = %v, %v; want none by default", d.AnswerIPv4, d.AnswerIPv6)
	}
	if cfg.Has(RoleConsole) || cfg.Has(RoleTrigger) || cfg.EncryptionKeys != nil {
		t.Error("the DNS role alone read the settings of other roles")
	}
}

func TestLoadServe_DNSSettings(t *testing.T) {
	t.Parallel()

	env := dnsEnv()
	env["NYKTUS_DNS_DATABASE_URL"] = ""
	env["NYKTUS_DNS_DATABASE_URL_FILE"] = "/run/secrets/dns"
	env["NYKTUS_DNS_ADDR"] = "0.0.0.0:53"
	env["NYKTUS_DNS_ZONES"] = "D.Example.COM., e.example.org"
	env["NYKTUS_DNS_NAMESERVERS"] = "ns1.example.net., NS2.example.net, NS1.example.net"
	env["NYKTUS_DNS_ANSWER_IPV4"] = "203.0.113.7"
	env["NYKTUS_DNS_ANSWER_IPV6"] = "2001:db8::7"
	env["NYKTUS_DNS_TTL"] = "5m"
	env["NYKTUS_DNS_DATABASE_MAX_CONNS"] = "25"
	src := fakeSource{env: env, files: map[string]string{"/run/secrets/dns": "postgres://dns@db/nyktus\n"}}
	cfg, err := LoadServe(src.source(), []Role{RoleDNS})
	if err != nil {
		t.Fatalf("LoadServe() error = %v", err)
	}
	d := cfg.DNS
	if !slices.Equal(d.Zones, []string{"d.example.com", "e.example.org"}) {
		t.Errorf("Zones = %v, want lower case without trailing dots", d.Zones)
	}
	if !slices.Equal(d.Nameservers, []string{"ns1.example.net", "ns2.example.net"}) {
		t.Errorf("Nameservers = %v, want lower case without trailing dots", d.Nameservers)
	}
	if d.AnswerIPv4 != netip.MustParseAddr("203.0.113.7") || d.AnswerIPv6 != netip.MustParseAddr("2001:db8::7") {
		t.Errorf("answer addresses = %v, %v", d.AnswerIPv4, d.AnswerIPv6)
	}
	if d.Addr != "0.0.0.0:53" || d.TTL != 5*time.Minute || d.DatabaseURL.Value() != "postgres://dns@db/nyktus" || d.DatabaseMaxConns != 25 {
		t.Errorf("DNS = %+v", d)
	}
}

func TestLoadServe_DNSRejectsInvalidSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, variable, value, want string
	}{
		{name: "no zone", variable: "NYKTUS_DNS_ZONES", value: "", want: "NYKTUS_DNS_ZONES is required"},
		{name: "single label", variable: "NYKTUS_DNS_ZONES", value: "example", want: "at least two labels"},
		{name: "underscore", variable: "NYKTUS_DNS_ZONES", value: "d_1.example.com", want: "letters, digits and hyphens"},
		{name: "leading hyphen", variable: "NYKTUS_DNS_ZONES", value: "-d.example.com", want: "hyphen"},
		{name: "empty label", variable: "NYKTUS_DNS_ZONES", value: "d..example.com", want: "letters, digits and hyphens"},
		{name: "long label", variable: "NYKTUS_DNS_ZONES", value: strings.Repeat("a", 64) + ".example.com", want: "1 to 63"},
		{name: "address", variable: "NYKTUS_DNS_ZONES", value: "192.0.2.1", want: "address"},
		{name: "long zone", variable: "NYKTUS_DNS_ZONES", value: strings.Repeat(strings.Repeat("a", 63)+".", 3) + "example.com", want: "longer than 200"},
		{name: "nested zones", variable: "NYKTUS_DNS_ZONES", value: "example.com,d.example.com", want: "overlap"},
		{name: "nested zones reversed", variable: "NYKTUS_DNS_ZONES", value: "d.example.com,example.com", want: "overlap"},
		{name: "no name server", variable: "NYKTUS_DNS_NAMESERVERS", value: "", want: "NYKTUS_DNS_NAMESERVERS is required"},
		{name: "name server in zone", variable: "NYKTUS_DNS_NAMESERVERS", value: "ns1.d.example.com", want: "outside the zones"},
		{name: "name server is zone", variable: "NYKTUS_DNS_NAMESERVERS", value: "d.example.com", want: "outside the zones"},
		{name: "too many name servers", variable: "NYKTUS_DNS_NAMESERVERS", value: "a.n.net,b.n.net,c.n.net,d.n.net,e.n.net,f.n.net,g.n.net,h.n.net,i.n.net", want: "at most 8"},
		{name: "IPv6 as IPv4", variable: "NYKTUS_DNS_ANSWER_IPV4", value: "2001:db8::1", want: "not an IPv4 address"},
		{name: "IPv4 as IPv6", variable: "NYKTUS_DNS_ANSWER_IPV6", value: "192.0.2.1", want: "not an IPv6 address"},
		{name: "IPv4 in IPv6 notation", variable: "NYKTUS_DNS_ANSWER_IPV6", value: "::ffff:192.0.2.1", want: "not an IPv6 address"},
		{name: "no address", variable: "NYKTUS_DNS_ANSWER_IPV4", value: "example.com", want: "not an IP address"},
		{name: "address with zone", variable: "NYKTUS_DNS_ANSWER_IPV6", value: "fe80::1%eth0", want: "not an IP address"},
		{name: "TTL too long", variable: "NYKTUS_DNS_TTL", value: "2h", want: "between"},
		{name: "TTL negative", variable: "NYKTUS_DNS_TTL", value: "-1s", want: "between"},
		{name: "TTL fraction", variable: "NYKTUS_DNS_TTL", value: "1500ms", want: "whole seconds"},
		{name: "address without port", variable: "NYKTUS_DNS_ADDR", value: "127.0.0.1", want: "NYKTUS_DNS_ADDR"},
		{name: "connections not a number", variable: "NYKTUS_DNS_DATABASE_MAX_CONNS", value: "ten", want: "not a whole number"},
		{name: "no connections", variable: "NYKTUS_DNS_DATABASE_MAX_CONNS", value: "0", want: "between 1 and 100"},
		{name: "too many connections", variable: "NYKTUS_DNS_DATABASE_MAX_CONNS", value: "101", want: "between 1 and 100"},
		{name: "no database", variable: "NYKTUS_DNS_DATABASE_URL", value: "", want: "NYKTUS_DNS_DATABASE_URL or NYKTUS_DNS_DATABASE_URL_FILE is required"},
	}
	for _, tt := range tests {
		env := dnsEnv()
		env[tt.variable] = tt.value
		_, err := LoadServe(fakeSource{env: env}.source(), []Role{RoleDNS})
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: LoadServe() error = %v, want it to mention %q", tt.name, err, tt.want)
		}
	}
}

// The TTL may be zero: a resolver then asks again for every lookup.
func TestLoadServe_DNSTTLMayBeZero(t *testing.T) {
	t.Parallel()

	env := dnsEnv()
	env["NYKTUS_DNS_TTL"] = "0s"
	cfg, err := LoadServe(fakeSource{env: env}.source(), []Role{RoleDNS})
	if err != nil || cfg.DNS.TTL != 0 {
		t.Errorf("LoadServe() = %v, %v; want a TTL of zero", cfg.DNS.TTL, err)
	}
}

func consoleEnvWithZones(zones string) map[string]string {
	return map[string]string{
		"NYKTUS_CONSOLE_DATABASE_URL": "postgres://console@db/nyktus",
		"NYKTUS_CONSOLE_URL":          "https://nyktus.example.com",
		"NYKTUS_TRIGGER_URL":          "https://t.example.net",
		"NYKTUS_ENCRYPTION_KEYS":      testKeys,
		"NYKTUS_DNS_ZONES":            zones,
	}
}

// The console shows the names of DNS honeytokens and needs the zones for them,
// but runs without them.
func TestLoadServe_ConsoleZones(t *testing.T) {
	t.Parallel()

	cfg, err := LoadServe(fakeSource{env: consoleEnvWithZones("")}.source(), []Role{RoleConsole})
	if err != nil || cfg.Console.DNSZones != nil {
		t.Errorf("LoadServe() = %v, %v; want no zones", cfg.Console.DNSZones, err)
	}

	cfg, err = LoadServe(fakeSource{env: consoleEnvWithZones("D.example.org, t.example.org.")}.source(), []Role{RoleConsole})
	if err != nil || !slices.Equal(cfg.Console.DNSZones, []string{"d.example.org", "t.example.org"}) {
		t.Errorf("LoadServe() = %v, %v; want both zones", cfg.Console.DNSZones, err)
	}
}

// A zone that holds the host of the console or the trigger would answer that
// host itself, and a DNS honeytoken would name it. A zone below such a host
// does neither.
func TestLoadServe_ZonesMustNotHoldTheConsoleOrTrigger(t *testing.T) {
	t.Parallel()

	for zone, wantErr := range map[string]bool{
		"nyktus.example.com":   true,
		"example.com":          true,
		"t.example.net":        true,
		"example.net":          true,
		"d.t.example.net":      false,
		"d.nyktus.example.com": false,
		"other.example.org":    false,
	} {
		_, err := LoadServe(fakeSource{env: consoleEnvWithZones(zone)}.source(), []Role{RoleConsole})
		if gotErr := err != nil && strings.Contains(err.Error(), "neither the console nor the trigger"); gotErr != wantErr {
			t.Errorf("zone %q: LoadServe() error = %v, want error %v", zone, err, wantErr)
		}
	}
}

// One process with every role reads the zones once for both roles.
func TestLoadServe_AllRolesShareTheZones(t *testing.T) {
	t.Parallel()

	env := consoleEnvWithZones("d.example.org")
	maps.Copy(env, map[string]string{
		"NYKTUS_TRIGGER_DATABASE_URL":     "postgres://trigger@db/nyktus",
		"NYKTUS_TRIGGER_DEFAULT_REDIRECT": "https://www.example.com/",
		"NYKTUS_DNS_DATABASE_URL":         "postgres://dns@db/nyktus",
		"NYKTUS_DNS_NAMESERVERS":          "ns1.example.net",
		"NYKTUS_DNS_ZONES":                "d.example.org",
		"NYKTUS_WORKER_DATABASE_URL":      "postgres://worker@db/nyktus",
	})
	cfg, err := LoadServe(fakeSource{env: env}.source(), Roles)
	if err != nil {
		t.Fatalf("LoadServe() error = %v", err)
	}
	if !slices.Equal(cfg.Console.DNSZones, cfg.DNS.Zones) {
		t.Errorf("console zones %v, DNS zones %v; want the same", cfg.Console.DNSZones, cfg.DNS.Zones)
	}
}

// A process with the console and the DNS role reports a problem of the zones
// once, and still requires them for the DNS role.
func TestLoadServe_ConsoleAndDNSReportZonesOnce(t *testing.T) {
	t.Parallel()

	env := consoleEnvWithZones("bad_zone.example")
	maps.Copy(env, map[string]string{
		"NYKTUS_DNS_DATABASE_URL": "postgres://dns@db/nyktus",
		"NYKTUS_DNS_NAMESERVERS":  "ns1.example.net",
	})
	_, err := LoadServe(fakeSource{env: env}.source(), []Role{RoleConsole, RoleDNS})
	if err == nil || strings.Count(err.Error(), "bad_zone.example") != 1 {
		t.Errorf("LoadServe() error = %v, want the zone reported once", err)
	}

	env["NYKTUS_DNS_ZONES"] = ""
	_, err = LoadServe(fakeSource{env: env}.source(), []Role{RoleConsole, RoleDNS})
	if err == nil || !strings.Contains(err.Error(), "NYKTUS_DNS_ZONES is required") {
		t.Errorf("LoadServe() error = %v, want the zones required", err)
	}
}
