// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package trigger

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"time"
)

// A sensor reports to the trigger with a POST of JSON to "/", authenticated by
// the secret of a honeypot as a bearer token. The trigger decodes the report
// strictly and passes it to the database function of its kind, which resolves
// the secret and decides what is stored.
//
// A report names a version. A version that this server does not know is not
// stored, and neither is a report with an unknown member: a new member needs a
// new version, so that a sensor that is newer than the server is noticed in the
// log instead of silently losing fields. Operators update the server before the
// sensors.

// ReportVersion is the version of the report that sensors send. The trigger
// also accepts the one before it, so that a sensor that has not been updated
// keeps reporting; that version has no tool calls.
const (
	ReportVersion         = 2
	previousReportVersion = 1
)

// Errors of a report that is not stored. The response is the same for every
// outcome; the log tells them apart.
var (
	// ErrUnsupportedVersion means that the report names a version that the
	// trigger does not accept, or none.
	ErrUnsupportedVersion = errors.New("unsupported report version")
	// ErrInvalidReport means that the report is not JSON of a known form or
	// holds a value that the trigger refuses.
	ErrInvalidReport = errors.New("invalid report")
)

// EventType is the highest stage that a session reached.
type EventType string

// Event types of a session, from the lowest to the highest stage. A session
// that reached several stages raises one event of the highest, so that the
// first event of an incident describes what the attacker did and the handshake
// does not hide it.
const (
	EventConnection     EventType = "connection"
	EventLoginAttempt   EventType = "login_attempt"
	EventDirectoryQuery EventType = "directory_query"
	EventToolCall       EventType = "tool_call"
)

// EventTypes lists every event type, from the lowest stage to the highest.
var EventTypes = []EventType{EventConnection, EventLoginAttempt, EventDirectoryQuery, EventToolCall}

// kind is the key of the techniques that an event suggests by itself.
type kind struct {
	service string
	event   EventType
}

// kindTechniques are the ATT&CK techniques that an event of a kind suggests,
// in addition to those of the honeypot. The database function keeps the same
// table, and a test compares both: the services are those of the honeypots,
// which the trigger does not import.
var kindTechniques = map[kind][]string{
	{"ssh", EventConnection}:      {"T1046"},
	{"telnet", EventConnection}:   {"T1046"},
	{"postgres", EventConnection}: {"T1046"},
	{"ldap", EventConnection}:     {"T1046"},
	{"mcp", EventConnection}:      {"T1046"},

	{"ssh", EventLoginAttempt}:      {"T1110", "T1021.004"},
	{"telnet", EventLoginAttempt}:   {"T1110"},
	{"postgres", EventLoginAttempt}: {"T1110"},
	{"ldap", EventLoginAttempt}:     {"T1110"},

	{"ldap", EventDirectoryQuery}: {"T1087.002"},

	{"mcp", EventToolCall}: {"T1213"},
}

// KindTechniques returns the techniques that an event of the type t suggests
// for a honeypot of the service, or nil if a honeypot of the service has no
// event of that type.
func KindTechniques(service string, t EventType) []string {
	return append([]string(nil), kindTechniques[kind{service, t}]...)
}

// Limits of a session. The database enforces the same limits; these values are
// the lengths up to which the trigger keeps the text that a client chose.
const (
	maxAttempts        = 6
	maxClientVersion   = 128
	maxDatabase        = 64
	maxApplicationName = 64
	maxUsername        = 256
	maxBaseDN          = 256
	maxFilter          = 256
	maxToolCalls       = 6
	maxToolName        = 128
	maxToolArguments   = 2048
	maxPasswordLength  = 65535
	// maxAge is the oldest age that the trigger passes on, and the longest
	// duration. The database keeps the age within five minutes as well, and a
	// session is reported within that window of its beginning, so it cannot
	// have lasted longer; a sensor that reports more has waited so long that
	// the exact time no longer matters.
	maxAge = 5 * time.Minute
)

// Attempt is one login or bind of a session. The password is never part of it:
// only its length.
type Attempt struct {
	// Username is the user name or the distinguished name that the client used.
	Username string
	// PasswordLength is the length of the password that was sent, or nil if
	// none was.
	PasswordLength *int
	// KeyFingerprint is the fingerprint of the public key that was offered, or
	// empty.
	KeyFingerprint string
}

// Query is the first search of a directory client.
type Query struct {
	BaseDN string
	Filter string
}

// ToolCall is one call of a tool of an MCP honeypot.
type ToolCall struct {
	// ToolName is the name that the client asked for, whether or not the
	// honeypot has such a tool.
	ToolName string
	// Arguments is the start of the arguments as JSON text. It is what an
	// attacker wrote: it is stored as text and never parsed.
	Arguments string
}

// Session is what a sensor reports about one session of an attacker. The sensor
// is not trusted: it chooses every value, and the trigger shortens text and
// replaces characters that are not printable, as for the headers of a request.
type Session struct {
	// ID identifies the session, 128 random bits in 32 lowercase hexadecimal
	// digits, so that a report that arrives twice is stored once.
	ID string
	// Age is how long ago the session began, measured by the sensor with its
	// monotonic clock.
	Age      time.Duration
	Duration time.Duration
	// ClientIP is the address of the attacker as the sensor saw it.
	ClientIP netip.Addr
	// Port is the port of the honeypot that the attacker reached.
	Port int
	// ClientVersion, Database and ApplicationName are what the client says
	// about itself; empty if it said nothing.
	ClientVersion   string
	Database        string
	ApplicationName string
	Attempts        []Attempt
	// Query is the first search of the session, or nil if there was none.
	Query *Query
	// ToolCalls are the first tool calls of the session, or nil if there were
	// none.
	ToolCalls []ToolCall
}

// EventType returns the highest stage that the session reached.
func (s Session) EventType() EventType {
	switch {
	case len(s.ToolCalls) > 0:
		return EventToolCall
	case s.Query != nil:
		return EventDirectoryQuery
	case len(s.Attempts) > 0:
		return EventLoginAttempt
	default:
		return EventConnection
	}
}

// Heartbeat is a sensor's sign of life for one honeypot.
type Heartbeat struct {
	// SensorVersion is the version of the sensor, or empty if it named none.
	SensorVersion string
}

// Report is a decoded report: exactly one of its members is set.
type Report struct {
	Session   *Session
	Heartbeat *Heartbeat
}

// Kind returns "session" or "heartbeat".
func (r Report) Kind() string {
	if r.Session != nil {
		return "session"
	}
	return "heartbeat"
}

// envelope reads the version and the type of a report loosely, so that a
// report of a newer version, which may change what they look like, is still
// recognized as one.
type envelope struct {
	Version json.RawMessage `json:"version"`
	Type    json.RawMessage `json:"type"`
}

type sessionWire struct {
	Version         int            `json:"version"`
	Type            string         `json:"type"`
	SessionID       *string        `json:"session_id"`
	AgeMS           *int64         `json:"age_ms"`
	DurationMS      *int64         `json:"duration_ms"`
	ClientIP        *string        `json:"client_ip"`
	Port            *int           `json:"port"`
	ClientVersion   *string        `json:"client_version"`
	Database        *string        `json:"database"`
	ApplicationName *string        `json:"application_name"`
	Attempts        *[]attemptWire `json:"attempts"`
	Query           *queryWire     `json:"query"`
	ToolCalls       []toolCallWire `json:"tool_calls"`
}

type attemptWire struct {
	Username       *string `json:"username"`
	PasswordLength *int    `json:"password_length"`
	KeyFingerprint *string `json:"key_fingerprint"`
}

type queryWire struct {
	BaseDN *string `json:"base_dn"`
	Filter *string `json:"filter"`
}

type toolCallWire struct {
	ToolName  *string `json:"tool_name"`
	Arguments *string `json:"arguments"`
}

type heartbeatWire struct {
	Version       int     `json:"version"`
	Type          string  `json:"type"`
	SensorVersion *string `json:"sensor_version"`
}

var (
	sessionIDPattern  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	fingerprintFormat = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
	// sensorVersionPattern is the pattern of the column honeypots.sensor_version.
	sensorVersionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$`)
)

// DecodeReport decodes the body of a report. It returns ErrUnsupportedVersion
// or ErrInvalidReport, never details of the body, which the sensor chose.
func DecodeReport(body []byte) (Report, error) {
	// The version decides how the rest is read, so it is read first and
	// without objection to the other members.
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return Report{}, ErrInvalidReport
	}
	if !acceptedVersion(env.Version) {
		return Report{}, ErrUnsupportedVersion
	}
	switch string(env.Type) {
	case `"session"`:
		var w sessionWire
		if !decodeStrict(body, &w) {
			return Report{}, ErrInvalidReport
		}
		s, ok := w.session()
		if !ok {
			return Report{}, ErrInvalidReport
		}
		return Report{Session: &s}, nil
	case `"heartbeat"`:
		var w heartbeatWire
		if !decodeStrict(body, &w) {
			return Report{}, ErrInvalidReport
		}
		h, ok := w.heartbeat()
		if !ok {
			return Report{}, ErrInvalidReport
		}
		return Report{Heartbeat: &h}, nil
	default:
		return Report{}, ErrInvalidReport
	}
}

func acceptedVersion(v json.RawMessage) bool {
	return string(v) == strconv.Itoa(ReportVersion) || string(v) == strconv.Itoa(previousReportVersion)
}

// decodeStrict decodes body into v, refusing unknown members. Data after the
// value was refused already when the version was read.
func decodeStrict(body []byte, v any) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	return dec.Decode(v) == nil
}

func (w sessionWire) session() (Session, bool) {
	if w.SessionID == nil || w.AgeMS == nil || w.DurationMS == nil || w.ClientIP == nil || w.Port == nil || w.Attempts == nil {
		return Session{}, false
	}
	// The member is new in the current version, and a new member needs a new
	// version.
	if w.Version == previousReportVersion && w.ToolCalls != nil {
		return Session{}, false
	}
	ip, err := netip.ParseAddr(*w.ClientIP)
	if err != nil || ip.Zone() != "" {
		return Session{}, false
	}
	switch {
	case !sessionIDPattern.MatchString(*w.SessionID),
		*w.AgeMS < 0,
		*w.DurationMS < 0,
		*w.Port < 1 || *w.Port > 65535,
		len(*w.Attempts) > maxAttempts,
		len(w.ToolCalls) > maxToolCalls:
		return Session{}, false
	}
	s := Session{
		ID:              *w.SessionID,
		Age:             time.Duration(min(*w.AgeMS, int64(maxAge/time.Millisecond))) * time.Millisecond,
		Duration:        time.Duration(min(*w.DurationMS, int64(maxAge/time.Millisecond))) * time.Millisecond,
		ClientIP:        ip.Unmap(),
		Port:            *w.Port,
		ClientVersion:   untrusted(deref(w.ClientVersion), maxClientVersion),
		Database:        untrusted(deref(w.Database), maxDatabase),
		ApplicationName: untrusted(deref(w.ApplicationName), maxApplicationName),
		Attempts:        make([]Attempt, 0, len(*w.Attempts)),
	}
	for _, a := range *w.Attempts {
		if a.Username == nil || (a.PasswordLength != nil && (*a.PasswordLength < 0 || *a.PasswordLength > maxPasswordLength)) ||
			(a.KeyFingerprint != nil && !fingerprintFormat.MatchString(*a.KeyFingerprint)) {
			return Session{}, false
		}
		s.Attempts = append(s.Attempts, Attempt{
			Username:       untrusted(*a.Username, maxUsername),
			PasswordLength: a.PasswordLength,
			KeyFingerprint: deref(a.KeyFingerprint),
		})
	}
	if w.Query != nil {
		// The root of a directory has the empty name, so an empty base is a value.
		if w.Query.BaseDN == nil || w.Query.Filter == nil {
			return Session{}, false
		}
		s.Query = &Query{BaseDN: untrusted(*w.Query.BaseDN, maxBaseDN), Filter: untrusted(*w.Query.Filter, maxFilter)}
	}
	for _, c := range w.ToolCalls {
		if c.ToolName == nil || c.Arguments == nil {
			return Session{}, false
		}
		s.ToolCalls = append(s.ToolCalls, ToolCall{ToolName: untrusted(*c.ToolName, maxToolName), Arguments: untrusted(*c.Arguments, maxToolArguments)})
	}
	return s, true
}

func (w heartbeatWire) heartbeat() (Heartbeat, bool) {
	if w.SensorVersion == nil {
		return Heartbeat{}, true
	}
	if !sensorVersionPattern.MatchString(*w.SensorVersion) {
		return Heartbeat{}, false
	}
	return Heartbeat{SensorVersion: *w.SensorVersion}, true
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// SecretHash returns the hash under which the database keeps the secret of a
// honeypot: the SHA-256 of its UTF-8 bytes. The console stores the same hash;
// the trigger does not import it, and a test compares both.
func SecretHash(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// secretLength is the length of the secret of a honeypot: 256 bits in unpadded
// base64url.
const secretLength = 43

// isSecret reports whether s has the form of the secret of a honeypot. Anything
// else cannot be one, so the database is not asked.
func isSecret(s string) bool {
	if len(s) != secretLength {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}
