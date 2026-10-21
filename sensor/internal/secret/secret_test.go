// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package secret_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"nyktus.org/nyktus/sensor/internal/secret"
)

const sample = "Abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"

func TestValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "43 characters of base64url", value: sample, want: true},
		{name: "one too short", value: sample[:42]},
		{name: "one too long", value: sample + "A"},
		{name: "empty", value: ""},
		{name: "a character of standard base64", value: sample[:42] + "+"},
		{name: "padding", value: sample[:42] + "="},
		{name: "a space", value: sample[:42] + " "},
		{name: "a line break", value: sample[:42] + "\n"},
		{name: "a non-ASCII letter", value: sample[:41] + "\u00e4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := secret.Valid(tt.value); got != tt.want {
				t.Errorf("Valid(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// A secret that reaches a log, a message or a document by mistake writes a
// placeholder.
func TestSecret_Written_IsRedacted(t *testing.T) {
	t.Parallel()

	type holder struct {
		Secret secret.Secret
	}
	s := secret.Secret(sample)
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("test", slog.Any("secret", s), slog.Any("holder", holder{s}))
	encoded, err := json.Marshal(holder{s}) //nolint:gosec // G117: the test proves that the secret is not written.
	if err != nil {
		t.Fatal(err)
	}

	outputs := map[string]string{
		"%s":         fmt.Sprintf("<%s>", s),
		"%v":         fmt.Sprintf("%v", s),
		"%#v":        fmt.Sprintf("%#v", s),
		"%+v":        fmt.Sprintf("%+v", holder{s}),
		"%#v holder": fmt.Sprintf("%#v", holder{s}),
		"slog":       logged.String(),
		"json":       string(encoded),
	}
	for name, out := range outputs {
		if strings.Contains(out, sample) {
			t.Errorf("%s wrote the secret: %s", name, out)
		}
		if !strings.Contains(out, "redacted") {
			t.Errorf("%s = %q, want the placeholder", name, out)
		}
	}
}
