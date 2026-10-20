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
