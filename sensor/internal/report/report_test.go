// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package report_test

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"nyktus.org/nyktus/sensor/internal/report"
)

// The files in testdata are the reports that the server decodes. A report of
// the sensor serializes to the same JSON values, and every member of the
// files has a field in the types, so that neither side can add one alone.
func TestReport_GoldenFiles_RoundTripToTheSameJSON(t *testing.T) {
	t.Parallel()

	testdata := os.DirFS("testdata")
	files, err := fs.Glob(testdata, "*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob testdata = %v, %v; want the golden reports", files, err)
	}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			t.Parallel()
			golden, err := fs.ReadFile(testdata, file)
			if err != nil {
				t.Fatal(err)
			}
			var typed any
			switch {
			case strings.HasPrefix(file, "session"):
				typed = new(report.Session)
			case strings.HasPrefix(file, "heartbeat"):
				typed = new(report.Heartbeat)
			default:
				t.Fatalf("%s is neither a session nor a heartbeat", file)
			}
			dec := json.NewDecoder(bytes.NewReader(golden))
			dec.DisallowUnknownFields()
			if err := dec.Decode(typed); err != nil {
				t.Fatalf("decode golden report into the types of the sensor: %v", err)
			}
			got, err := json.Marshal(typed)
			if err != nil {
				t.Fatal(err)
			}
			var want, have any
			if err := json.Unmarshal(golden, &want); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(got, &have); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(have, want) {
				t.Errorf("serialized = %s, want the JSON values of %s", got, golden)
			}
		})
	}
}

// The server requires the member attempts, also when the session has none.
func TestSession_WithoutAttempts_SerializesAnEmptyList(t *testing.T) {
	t.Parallel()

	b, err := json.Marshal(report.Session{Version: report.Version, Type: report.TypeSession, Attempts: []report.Attempt{}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"attempts":[]`) {
		t.Errorf("serialized = %s, want attempts as an empty list", b)
	}
}

// The root of a directory has the empty name, and the server needs the member.
func TestQuery_WithAnEmptyBase_KeepsTheMember(t *testing.T) {
	t.Parallel()

	b, err := json.Marshal(report.Query{Filter: "(objectClass=*)"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"base_dn":""`) {
		t.Errorf("serialized = %s, want base_dn", b)
	}
}

func TestHeartbeat_WithoutVersion_OmitsTheMember(t *testing.T) {
	t.Parallel()

	b, err := json.Marshal(report.NewHeartbeat(""))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "sensor_version") {
		t.Errorf("serialized = %s, want no sensor_version", b)
	}
}

// The trigger reads at most MaxBody of a report and loses the whole session if
// it is larger. A session that holds the most the sensor keeps, filled with
// what a JSON encoder writes longest, fits, whatever the attacker typed: it
// is not the characters that json.Marshal escapes that decide, but the size.
func TestMarshal_TheLargestSession_FitsWhatTheTriggerReads(t *testing.T) {
	t.Parallel()

	// < is six bytes with json.Marshal, a backslash and a quote two, and the
	// line separator, which the encoder always escapes, six for three.
	for _, filler := range []string{"<", `\`, `"`, "\u2028"} {
		fill := func(n int) string { return report.Clean(strings.Repeat(filler, n), n) }
		s := report.Session{
			Version: report.Version, Type: report.TypeSession, SessionID: strings.Repeat("a", 32), ClientIP: "203.0.113.9", Port: 8080,
			ClientVersion: fill(report.MaxClientVersion), Database: fill(report.MaxDatabase), ApplicationName: fill(report.MaxApplicationName),
			Query: &report.Query{BaseDN: fill(report.MaxBaseDN), Filter: fill(report.MaxFilter)},
		}
		length := 1
		for range report.MaxAttempts {
			s.Attempts = append(s.Attempts, report.Attempt{Username: fill(report.MaxUsername), PasswordLength: &length, KeyFingerprint: "SHA256:" + strings.Repeat("A", 43)})
		}
		for range report.MaxToolCalls {
			s.ToolCalls = append(s.ToolCalls, report.ToolCall{ToolName: fill(report.MaxToolName), Arguments: fill(report.MaxToolArguments)})
		}
		got, err := report.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) > report.MaxBody {
			t.Errorf("filled with %q: %d bytes, more than the %d that the trigger reads", filler, len(got), report.MaxBody)
		}
	}
}

// Marshal leaves the characters of HTML as they are and ends no line.
func TestMarshal_KeepsHTMLCharacters(t *testing.T) {
	t.Parallel()

	got, err := report.Marshal(report.ToolCall{ToolName: "a", Arguments: "<&>"})
	if err != nil || string(got) != `{"tool_name":"a","arguments":"<&>"}` {
		t.Errorf("Marshal() = %q, %v", got, err)
	}
}

func TestClean(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{name: "short", in: "root", max: 8, want: "root"},
		{name: "exact", in: "12345678", max: 8, want: "12345678"},
		{name: "cut", in: "123456789", max: 8, want: "12345678"},
		{name: "invalid bytes", in: "ro\xff\xfeot", max: 16, want: "ro\uFFFDot"},
		{name: "cut in the middle of a character", in: "1234567\u00e9", max: 8, want: "1234567"},
		{name: "cut after a character", in: "123456\u00e9x", max: 8, want: "123456\u00e9"},
		{name: "empty", in: "", max: 8, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := report.Clean(tt.in, tt.max)
			if got != tt.want || !utf8.ValidString(got) {
				t.Errorf("Clean(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
			}
		})
	}
}
