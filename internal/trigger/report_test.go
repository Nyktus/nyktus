// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package trigger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// goldenDir holds the reports that the sensor and the trigger agree on: the
// trigger decodes every file, and the sensor writes the same JSON.
const goldenDir = "../../sensor/internal/report/testdata"

func golden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := fs.ReadFile(os.DirFS(goldenDir), name)
	if err != nil {
		t.Fatalf("read golden report: %v", err)
	}
	return b
}

// mutated returns the golden report name with edit applied to its members.
func mutated(t *testing.T, name string, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(golden(t, name), &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func intPtr(n int) *int { return &n }

func TestDecodeReport_GoldenFiles(t *testing.T) {
	t.Parallel()

	const fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tests := []struct {
		file string
		want Report
	}{
		{"session_ssh.json", Report{Session: &Session{
			ID: "0123456789abcdef0123456789abcdef", Age: 1500 * time.Millisecond, Duration: 4200 * time.Millisecond,
			ClientIP: netip.MustParseAddr("203.0.113.9"), Port: 22, ClientVersion: "SSH-2.0-OpenSSH_9.6",
			Attempts: []Attempt{{Username: "root", PasswordLength: intPtr(8)}, {Username: "admin", KeyFingerprint: fingerprint}},
		}}},
		{"session_postgres.json", Report{Session: &Session{
			ID: "fedcba9876543210fedcba9876543210", Duration: 350 * time.Millisecond,
			ClientIP: netip.MustParseAddr("2001:db8::7"), Port: 5432, Database: "postgres", ApplicationName: "psql",
			Attempts: []Attempt{{Username: "postgres"}},
		}}},
		{"session_ldap.json", Report{Session: &Session{
			ID: "00112233445566778899aabbccddeeff", Age: 800 * time.Millisecond, Duration: 1200 * time.Millisecond,
			ClientIP: netip.MustParseAddr("198.51.100.23"), Port: 389,
			Attempts: []Attempt{{Username: "cn=admin,dc=example,dc=com", PasswordLength: intPtr(0)}},
			Query:    &Query{BaseDN: "dc=example,dc=com", Filter: "(objectClass=*)"},
		}}},
		{"session_telnet.json", Report{Session: &Session{
			ID: "ffeeddccbbaa99887766554433221100", Age: 5 * time.Minute,
			ClientIP: netip.MustParseAddr("192.0.2.77"), Port: 23, Attempts: []Attempt{},
		}}},
		{"heartbeat.json", Report{Heartbeat: &Heartbeat{SensorVersion: "0.1.0-rc.1+build5"}}},
		{"heartbeat_without_version.json", Report{Heartbeat: &Heartbeat{}}},
	}
	files, err := filepath.Glob(filepath.Join(goldenDir, "*.json"))
	if err != nil || len(files) != len(tests) {
		t.Fatalf("golden files = %v, %v; the test covers %d", files, err, len(tests))
	}
	for _, tt := range tests {
		got, err := DecodeReport(golden(t, tt.file))
		if err != nil {
			t.Errorf("DecodeReport(%s) error = %v", tt.file, err)
			continue
		}
		if !sameReport(got, tt.want) {
			t.Errorf("DecodeReport(%s) = %s, want %s", tt.file, describe(got), describe(tt.want))
		}
	}
}

func describe(r Report) string {
	if r.Session != nil {
		return fmt.Sprintf("session %+v", *r.Session)
	}
	return fmt.Sprintf("heartbeat %+v", *r.Heartbeat)
}

func sameReport(a, b Report) bool { return reflect.DeepEqual(a, b) }

// Every rule of the form of a report has a case of its own, so that a rule that
// stops working fails exactly one case. The reason is checked as well: a case
// must not pass because another rule caught it.
func TestDecodeReport_RefusesWhatDoesNotFit(t *testing.T) {
	t.Parallel()

	set := func(key string, value any) func(map[string]any) {
		return func(m map[string]any) { m[key] = value }
	}
	drop := func(key string) func(map[string]any) {
		return func(m map[string]any) { delete(m, key) }
	}
	attempt := func(edit func(a map[string]any)) func(map[string]any) {
		return func(m map[string]any) { edit(m["attempts"].([]any)[0].(map[string]any)) }
	}
	manyAttempts := func(n int) func(map[string]any) {
		return func(m map[string]any) {
			list := make([]any, n)
			for i := range list {
				list[i] = map[string]any{"username": "root"}
			}
			m["attempts"] = list
		}
	}

	tests := []struct {
		name string
		file string
		edit func(map[string]any)
		want error
	}{
		{"no version", "session_ssh.json", drop("version"), ErrUnsupportedVersion},
		{"version 0", "session_ssh.json", set("version", 0), ErrUnsupportedVersion},
		{"version 2", "session_ssh.json", set("version", 2), ErrUnsupportedVersion},
		{"version that is a string", "session_ssh.json", set("version", "1"), ErrUnsupportedVersion},
		{"unknown type", "session_ssh.json", set("type", "event"), ErrInvalidReport},
		{"no type", "session_ssh.json", drop("type"), ErrInvalidReport},
		{"unknown member", "session_ssh.json", set("service", "ssh"), ErrInvalidReport},
		{"password member", "session_ssh.json", attempt(func(a map[string]any) { a["password"] = "hunter2" }), ErrInvalidReport},
		{"unknown member of a heartbeat", "heartbeat.json", set("host", "web1"), ErrInvalidReport},
		{"unknown member of a query", "session_ldap.json", func(m map[string]any) {
			m["query"].(map[string]any)["scope"] = "sub"
		}, ErrInvalidReport},
		{"no session id", "session_ssh.json", drop("session_id"), ErrInvalidReport},
		{"session id in upper case", "session_ssh.json", set("session_id", strings.Repeat("A", 32)), ErrInvalidReport},
		{"session id too short", "session_ssh.json", set("session_id", strings.Repeat("a", 31)), ErrInvalidReport},
		{"session id with a dash", "session_ssh.json", set("session_id", "01234567-89ab-cdef-0123-456789abcdef"), ErrInvalidReport},
		{"no age", "session_ssh.json", drop("age_ms"), ErrInvalidReport},
		{"negative age", "session_ssh.json", set("age_ms", -1), ErrInvalidReport},
		{"age that is no integer", "session_ssh.json", set("age_ms", 1.5), ErrInvalidReport},
		{"no duration", "session_ssh.json", drop("duration_ms"), ErrInvalidReport},
		{"negative duration", "session_ssh.json", set("duration_ms", -1), ErrInvalidReport},
		{"version 1.5", "session_ssh.json", set("version", 1.5), ErrUnsupportedVersion},
		{"version of a newer form", "session_ssh.json", set("version", "2"), ErrUnsupportedVersion},
		{"newer version that changes the type", "session_ssh.json", func(m map[string]any) { m["version"], m["type"] = 2, []any{"session"} }, ErrUnsupportedVersion},
		{"type that is no string", "session_ssh.json", set("type", 7), ErrInvalidReport},
		{"no address", "session_ssh.json", drop("client_ip"), ErrInvalidReport},
		{"address that is none", "session_ssh.json", set("client_ip", "web1"), ErrInvalidReport},
		{"address with a zone", "session_ssh.json", set("client_ip", "fe80::1%eth0"), ErrInvalidReport},
		{"no port", "session_ssh.json", drop("port"), ErrInvalidReport},
		{"port 0", "session_ssh.json", set("port", 0), ErrInvalidReport},
		{"port 65536", "session_ssh.json", set("port", 65536), ErrInvalidReport},
		{"no attempts", "session_ssh.json", drop("attempts"), ErrInvalidReport},
		{"null attempts", "session_ssh.json", set("attempts", nil), ErrInvalidReport},
		{"seven attempts", "session_ssh.json", manyAttempts(7), ErrInvalidReport},
		{"attempt without a user name", "session_ssh.json", attempt(func(a map[string]any) { delete(a, "username") }), ErrInvalidReport},
		{"negative password length", "session_ssh.json", attempt(func(a map[string]any) { a["password_length"] = -1 }), ErrInvalidReport},
		{"password length beyond 65535", "session_ssh.json", attempt(func(a map[string]any) { a["password_length"] = 65536 }), ErrInvalidReport},
		{"fingerprint of another form", "session_ssh.json", attempt(func(a map[string]any) { a["key_fingerprint"] = "MD5:aa:bb" }), ErrInvalidReport},
		{"query without a base", "session_ldap.json", func(m map[string]any) { delete(m["query"].(map[string]any), "base_dn") }, ErrInvalidReport},
		{"query without a filter", "session_ldap.json", func(m map[string]any) { delete(m["query"].(map[string]any), "filter") }, ErrInvalidReport},
		{"heartbeat version with a space", "heartbeat.json", set("sensor_version", "0.1 beta"), ErrInvalidReport},
		{"heartbeat version too long", "heartbeat.json", set("sensor_version", "1"+strings.Repeat("0", 32)), ErrInvalidReport},
		{"empty heartbeat version", "heartbeat.json", set("sensor_version", ""), ErrInvalidReport},
	}
	for _, tt := range tests {
		_, err := DecodeReport(mutated(t, tt.file, tt.edit))
		if !errors.Is(err, tt.want) {
			t.Errorf("%s: DecodeReport() error = %v, want %v", tt.name, err, tt.want)
		}
	}

	// Cases of the form of the JSON itself.
	for name, body := range map[string]string{
		"empty":               "",
		"no JSON":             "version 1",
		"array":               "[]",
		"data after the JSON": string(golden(t, "heartbeat.json")) + "{}",
		"null":                "null",
	} {
		_, err := DecodeReport([]byte(body))
		if err == nil {
			t.Errorf("%s: DecodeReport() succeeded", name)
		}
	}
}

// The limits that the database enforces too hold at their edge, in the trigger
// and without a database.
func TestDecodeReport_AcceptsTheLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		file  string
		edit  func(map[string]any)
		check func(Session) bool
	}{
		{"six attempts", "session_ssh.json", func(m map[string]any) {
			list := make([]any, 6)
			for i := range list {
				list[i] = map[string]any{"username": "root"}
			}
			m["attempts"] = list
		}, func(s Session) bool { return len(s.Attempts) == 6 }},
		{
			"duration of five minutes", "session_ssh.json", func(m map[string]any) { m["duration_ms"] = 300000 },
			func(s Session) bool { return s.Duration == 5*time.Minute },
		},
		{
			"a longer duration is cut", "session_ssh.json", func(m map[string]any) { m["duration_ms"] = 300001 },
			func(s Session) bool { return s.Duration == 5*time.Minute },
		},
		{"port 1", "session_ssh.json", func(m map[string]any) { m["port"] = 1 }, func(s Session) bool { return s.Port == 1 }},
		{"port 65535", "session_ssh.json", func(m map[string]any) { m["port"] = 65535 }, func(s Session) bool { return s.Port == 65535 }},
		{"password length 65535", "session_ssh.json", func(m map[string]any) {
			m["attempts"] = []any{map[string]any{"username": "root", "password_length": 65535}}
		}, func(s Session) bool { return *s.Attempts[0].PasswordLength == 65535 }},
		{
			"the root of a directory", "session_ldap.json", func(m map[string]any) { m["query"].(map[string]any)["base_dn"] = "" },
			func(s Session) bool { return s.Query != nil && s.Query.BaseDN == "" },
		},
		{"an empty user name", "session_ssh.json", func(m map[string]any) {
			m["attempts"] = []any{map[string]any{"username": ""}}
		}, func(s Session) bool { return len(s.Attempts) == 1 && s.Attempts[0].Username == "" }},
		{
			"an address of IPv4 in IPv6", "session_ssh.json", func(m map[string]any) { m["client_ip"] = "::ffff:203.0.113.9" },
			func(s Session) bool { return s.ClientIP == netip.MustParseAddr("203.0.113.9") },
		},
		{
			"an age of years", "session_ssh.json", func(m map[string]any) { m["age_ms"] = int64(1) << 62 },
			func(s Session) bool { return s.Age == maxAge },
		},
		{"null members", "session_ssh.json", func(m map[string]any) {
			m["client_version"], m["database"], m["application_name"], m["query"] = nil, nil, nil, nil
		}, func(s Session) bool { return s.ClientVersion == "" && s.Query == nil }},
	}
	for _, tt := range tests {
		r, err := DecodeReport(mutated(t, tt.file, tt.edit))
		if err != nil || r.Session == nil || !tt.check(*r.Session) {
			t.Errorf("%s: DecodeReport() = %s, %v", tt.name, describe(r), err)
		}
	}
}

// Whoever sends a report chooses its text, so every field is cut to its length
// and stripped of characters that are not printable, as the headers of a
// request are.
func TestDecodeReport_CleansEveryTextField(t *testing.T) {
	t.Parallel()

	hostile := "a\r\nb" + string([]rune{0x202e, 0x2028, 0x85, 0x200b}) + "c" + strings.Repeat("x", 600)
	body := mutated(t, "session_ldap.json", func(m map[string]any) {
		m["client_version"] = hostile
		m["database"] = hostile
		m["application_name"] = hostile
		m["attempts"] = []any{map[string]any{"username": hostile, "password_length": 3}}
		m["query"] = map[string]any{"base_dn": hostile, "filter": hostile}
	})
	r, err := DecodeReport(body)
	if err != nil {
		t.Fatalf("DecodeReport() error = %v", err)
	}
	s := r.Session
	for name, field := range map[string]struct {
		value string
		max   int
	}{
		"client version":   {s.ClientVersion, maxClientVersion},
		"database":         {s.Database, maxDatabase},
		"application name": {s.ApplicationName, maxApplicationName},
		"user name":        {s.Attempts[0].Username, maxUsername},
		"base":             {s.Query.BaseDN, maxBaseDN},
		"filter":           {s.Query.Filter, maxFilter},
	} {
		if len(field.value) > field.max || !utf8.ValidString(field.value) || strings.ContainsAny(field.value, "\r\n") ||
			strings.ContainsRune(field.value, 0x202e) || strings.ContainsRune(field.value, 0x2028) ||
			strings.ContainsRune(field.value, 0x85) || strings.ContainsRune(field.value, 0x200b) {
			t.Errorf("%s = %q, want cut to %d bytes and without characters that are not printable", name, field.value, field.max)
		}
	}
	// The cut is not made by dropping a field: what is printable stays.
	if !strings.HasPrefix(s.Attempts[0].Username, "a") {
		t.Errorf("user name = %q, want the start of the value", s.Attempts[0].Username)
	}
}

// The event type is the highest stage that a session reached, whatever the
// lower stages say: a directory query ranks above a login attempt, which ranks
// above a connection.
func TestSession_EventTypeIsTheHighestStage(t *testing.T) {
	t.Parallel()

	attempt := []Attempt{{Username: "root"}}
	tests := []struct {
		name string
		s    Session
		want EventType
	}{
		{"nothing", Session{}, EventConnection},
		{"empty attempts", Session{Attempts: []Attempt{}}, EventConnection},
		{"an attempt", Session{Attempts: attempt}, EventLoginAttempt},
		{"a query", Session{Query: &Query{}}, EventDirectoryQuery},
		{"a query after an attempt", Session{Attempts: attempt, Query: &Query{BaseDN: "dc=example"}}, EventDirectoryQuery},
	}
	for _, tt := range tests {
		if got := tt.s.EventType(); got != tt.want {
			t.Errorf("%s: EventType() = %q, want %q", tt.name, got, tt.want)
		}
	}
	if want := []EventType{EventConnection, EventLoginAttempt, EventDirectoryQuery}; !slices.Equal(EventTypes, want) {
		t.Errorf("EventTypes = %v, want %v from the lowest stage to the highest", EventTypes, want)
	}
}

func TestKindTechniques(t *testing.T) {
	t.Parallel()

	tests := []struct {
		service string
		event   EventType
		want    []string
	}{
		{"ssh", EventConnection, []string{"T1046"}},
		{"ssh", EventLoginAttempt, []string{"T1110", "T1021.004"}},
		{"telnet", EventLoginAttempt, []string{"T1110"}},
		{"postgres", EventLoginAttempt, []string{"T1110"}},
		{"ldap", EventLoginAttempt, []string{"T1110"}},
		{"ldap", EventDirectoryQuery, []string{"T1087.002"}},
		{"ssh", EventDirectoryQuery, nil},
		{"smtp", EventConnection, nil},
	}
	for _, tt := range tests {
		if got := KindTechniques(tt.service, tt.event); !slices.Equal(got, tt.want) {
			t.Errorf("KindTechniques(%q, %q) = %v, want %v", tt.service, tt.event, got, tt.want)
		}
	}
	// A caller cannot change the table.
	KindTechniques("ssh", EventConnection)[0] = "T0000"
	if got := KindTechniques("ssh", EventConnection); got[0] != "T1046" {
		t.Errorf("KindTechniques() changed to %v", got)
	}
}

func TestBearerSecret(t *testing.T) {
	t.Parallel()

	secret := strings.Repeat("aB3-_", 8) + "xyz"
	if len(secret) != secretLength {
		t.Fatalf("test secret has %d characters", len(secret))
	}
	tests := []struct {
		name   string
		header string
		ok     bool
	}{
		{"bearer", "Bearer " + secret, true},
		{"scheme in lower case", "bearer " + secret, true},
		{"scheme in upper case", "BEARER " + secret, true},
		{"no header", "", false},
		{"other scheme", "Basic " + secret, false},
		{"no scheme", secret, false},
		{"one character short", "Bearer " + secret[1:], false},
		{"one character too long", "Bearer " + secret + "a", false},
		{"second space", "Bearer  " + secret[1:], false},
		{"character outside the alphabet", "Bearer " + secret[:42] + "+", false},
		{"padding", "Bearer " + secret[:42] + "=", false},
	}
	for _, tt := range tests {
		got, ok := bearerSecret(tt.header)
		if ok != tt.ok || (ok && got != secret) {
			t.Errorf("%s: bearerSecret(%q) = %q, %v; want ok %v", tt.name, tt.header, got, ok, tt.ok)
		}
	}
}

func TestSecretHash_IsTheSHA256OfTheBytes(t *testing.T) {
	t.Parallel()

	// SHA-256 of "abc", from FIPS 180-4.
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	got := SecretHash("abc")
	if len(got) != 32 {
		t.Fatalf("SecretHash() has %d bytes", len(got))
	}
	var hex strings.Builder
	for _, b := range got {
		hex.WriteString(string("0123456789abcdef"[b>>4]) + string("0123456789abcdef"[b&15]))
	}
	if hex.String() != want {
		t.Errorf("SecretHash(%q) = %s, want %s", "abc", hex.String(), want)
	}
}

// fakeReporter answers with the result configured for a hash, and records the
// reports it receives.
type fakeReporter struct {
	mu         sync.Mutex
	result     ReportResult
	err        error
	panics     bool
	sessions   []Session
	heartbeats []Heartbeat
	hashes     [][]byte
}

func (f *fakeReporter) enter(ctx context.Context, hash []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hashes = append(f.hashes, hash)
	if f.panics {
		panic("reporter failed")
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("no deadline")
	}
	return f.err
}

func (f *fakeReporter) RecordSession(ctx context.Context, hash []byte, s Session) (ReportResult, error) {
	if err := f.enter(ctx, hash); err != nil {
		return ReportResult{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions = append(f.sessions, s)
	return f.outcome(), nil
}

func (f *fakeReporter) RecordHeartbeat(ctx context.Context, hash []byte, h Heartbeat) (ReportResult, error) {
	if err := f.enter(ctx, hash); err != nil {
		return ReportResult{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heartbeats = append(f.heartbeats, h)
	return f.outcome(), nil
}

func (f *fakeReporter) outcome() ReportResult {
	if f.result.Outcome == "" {
		return ReportResult{Outcome: ReportUnknown}
	}
	return f.result
}

func (f *fakeReporter) reported() (sessions int, heartbeats int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sessions), len(f.heartbeats)
}
