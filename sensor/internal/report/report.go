// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package report holds the documents that a sensor sends to the trigger. They
// are the contract between the two: the server decodes the same JSON with
// types of its own, and both sides test against the files in testdata.
//
// A sensor does not name the service, the severity, the techniques or the kind
// of event. The server takes the first three from the honeypot and derives the
// last from the content.
package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// Version is the version of the documents. The server reads only versions it
// knows, so a new member needs a new version.
const Version = 2

// Types of reports.
const (
	TypeSession   = "session"
	TypeHeartbeat = "heartbeat"
)

// Limits that the server enforces as well. The sensor keeps within them, so
// that it does not send what would be cut or refused.
const (
	MaxAttempts        = 6
	MaxUsername        = 256
	MaxClientVersion   = 128
	MaxDatabase        = 64
	MaxApplicationName = 64
	MaxBaseDN          = 256
	MaxFilter          = 256
	MaxToolCalls       = 6
	MaxToolName        = 128
	MaxToolArguments   = 2048
)

// MaxBody is the most that the trigger reads of a report. A larger one is not
// stored, and the sensor cannot tell.
const MaxBody = 64 << 10

// Marshal returns the JSON of a report. The characters that matter only in HTML
// stay as they are: json.Marshal writes < as six bytes, and an attacker who
// fills the arguments of six calls with it would make the report larger than
// MaxBody, so that the whole session, its first connection included, was lost.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// Session is the report of one session of an attacker.
type Session struct {
	Version int    `json:"version"`
	Type    string `json:"type"`
	// SessionID is 128 random bits in 32 lowercase hexadecimal digits.
	SessionID string `json:"session_id"`
	// AgeMS is how long ago the session began, in milliseconds.
	AgeMS      int64  `json:"age_ms"`
	DurationMS int64  `json:"duration_ms"`
	ClientIP   string `json:"client_ip"`
	Port       int    `json:"port"`

	ClientVersion   string `json:"client_version,omitempty"`
	Database        string `json:"database,omitempty"`
	ApplicationName string `json:"application_name,omitempty"`

	// Attempts is never nil, because the server requires the member.
	Attempts []Attempt `json:"attempts"`
	Query    *Query    `json:"query,omitempty"`
	// ToolCalls are the first tool calls of an MCP client.
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}

// Attempt is one login or bind. A password is never part of it, only its
// length.
type Attempt struct {
	Username string `json:"username"`
	// PasswordLength is the length of the password that was sent, or nil if
	// none was.
	PasswordLength *int   `json:"password_length,omitempty"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
}

// Query is the first search of a directory client. The base may be empty, the
// root of the directory.
type Query struct {
	BaseDN string `json:"base_dn"`
	Filter string `json:"filter"`
}

// ToolCall is one call of a tool of an MCP honeypot: the name that the client
// asked for and the start of its arguments as JSON text.
type ToolCall struct {
	ToolName  string `json:"tool_name"`
	Arguments string `json:"arguments"`
}

// Heartbeat is the sign of life of a sensor for one honeypot.
type Heartbeat struct {
	Version       int    `json:"version"`
	Type          string `json:"type"`
	SensorVersion string `json:"sensor_version,omitempty"`
}

// NewHeartbeat returns the heartbeat of a sensor of the given version, which
// may be empty.
func NewHeartbeat(sensorVersion string) Heartbeat {
	return Heartbeat{Version: Version, Type: TypeHeartbeat, SensorVersion: sensorVersion}
}

// Clean returns a text that a client chose in a form that the server accepts:
// valid UTF-8 of at most limit bytes. The server removes characters that do not
// show; what it cannot repair is a text that is not UTF-8 or that is longer than
// its columns.
func Clean(s string, limit int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	// The cut may have ended in the middle of a character.
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
