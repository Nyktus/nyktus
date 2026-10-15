// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package alerting

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const hookURL = "https://hooks.example.com/services/T000/B000/abcdef"

func TestSpecValidate(t *testing.T) {
	t.Parallel()

	header := &Header{Name: "Authorization", Value: "Bearer abc"}
	tests := []struct {
		name string
		spec Spec
		want error
	}{
		{"webhook", Spec{Name: "SOAR", Type: TypeWebhook, URL: hookURL}, nil},
		{"webhook with header", Spec{Name: "SOAR", Type: TypeWebhook, URL: hookURL, Header: header}, nil},
		{"slack", Spec{Name: "Slack", Type: TypeSlack, URL: hookURL}, nil},
		{"teams", Spec{Name: "Teams", Type: TypeTeams, URL: hookURL}, nil},
		{"unknown type", Spec{Name: "x", Type: "email", URL: hookURL}, ErrInvalidType},
		{"empty name", Spec{Type: TypeWebhook, URL: hookURL}, ErrInvalidName},
		{"name with spaces around", Spec{Name: " x", Type: TypeWebhook, URL: hookURL}, ErrInvalidName},
		{"name too long", Spec{Name: strings.Repeat("x", MaxNameLength+1), Type: TypeWebhook, URL: hookURL}, ErrInvalidName},
		{"name with control character", Spec{Name: "a\nb", Type: TypeWebhook, URL: hookURL}, ErrInvalidName},
		{"name with bidirectional override", Spec{Name: "a\u202eb", Type: TypeWebhook, URL: hookURL}, ErrInvalidName},
		{"no URL", Spec{Name: "x", Type: TypeWebhook}, ErrInvalidURL},
		{"other scheme", Spec{Name: "x", Type: TypeWebhook, URL: "ftp://hooks.example.com/"}, ErrInvalidURL},
		{"URL with space", Spec{Name: "x", Type: TypeWebhook, URL: "https://hooks.example.com/a b"}, ErrInvalidURL},
		{"URL with fragment", Spec{Name: "x", Type: TypeWebhook, URL: "https://hooks.example.com/#x"}, ErrInvalidURL},
		{"URL with user information", Spec{Name: "x", Type: TypeWebhook, URL: "https://u:p@hooks.example.com/"}, ErrInvalidURL},
		{"URL too long", Spec{Name: "x", Type: TypeWebhook, URL: Secret("https://hooks.example.com/" + strings.Repeat("a", MaxURLLength))}, ErrInvalidURL},
		{"header for slack", Spec{Name: "x", Type: TypeSlack, URL: hookURL, Header: header}, ErrHeaderNotAllowed},
		{"header without value", Spec{Name: "x", Type: TypeWebhook, URL: hookURL, Header: &Header{Name: "X-Token"}}, ErrInvalidHeaderValue},
	}
	for _, tt := range tests {
		if err := tt.spec.Validate(); !errors.Is(err, tt.want) || (tt.want == nil && err != nil) {
			t.Errorf("%s: Validate() = %v, want %v", tt.name, err, tt.want)
		}
	}
}

func TestValidateHeaderName(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"Authorization", "X-API-Key", "x-token", "Splunk~1", "a"} {
		if err := ValidateHeaderName(name); err != nil {
			t.Errorf("ValidateHeaderName(%q) = %v, want nil", name, err)
		}
	}
	rejected := []string{"", strings.Repeat("x", MaxHeaderNameLength+1), "X Token", "X:Token", "X-T\u00f6k\u00e9n", "X\r\nInjected"}
	for _, h := range reservedHeaders {
		rejected = append(rejected, h, strings.ToUpper(h))
	}
	rejected = append(rejected, "Proxy-Authorization", "proxy-connection")
	for _, name := range rejected {
		if err := ValidateHeaderName(name); !errors.Is(err, ErrInvalidHeaderName) {
			t.Errorf("ValidateHeaderName(%q) = %v, want ErrInvalidHeaderName", name, err)
		}
	}
}

func TestHeaderValue(t *testing.T) {
	t.Parallel()

	for _, v := range []Secret{"Bearer abc", "Splunk 1234-5678", "x", Secret(strings.Repeat("a", MaxHeaderValueLength))} {
		if err := (Header{Name: "X-Token", Value: v}).validate(); err != nil {
			t.Errorf("value of %d bytes: validate() = %v, want nil", len(v), err)
		}
	}
	for _, v := range []Secret{"", " abc", "abc ", "a\r\nX-Injected: 1", "a\tb", "t\u00f6ken", Secret(strings.Repeat("a", MaxHeaderValueLength+1))} {
		if err := (Header{Name: "X-Token", Value: v}).validate(); !errors.Is(err, ErrInvalidHeaderValue) {
			t.Errorf("value %q: validate() = %v, want ErrInvalidHeaderValue", v, err)
		}
	}
}

func TestTarget_ShowsSchemeHostAndPortOnly(t *testing.T) {
	t.Parallel()

	tests := map[Secret]string{
		hookURL: "https://hooks.example.com",
		"https://HOOKS.example.com:8088/services/collector?token=abc": "https://hooks.example.com:8088",
		"https://[2001:db8::1]/x":                                     "https://[2001:db8::1]",
		"https://[2001:db8::1]:8443/x":                                "https://[2001:db8::1]:8443",
		"http://localhost:8080/hook":                                  "http://localhost:8080",
		"https://hooks.example.com./x":                                "https://hooks.example.com",
	}
	for u, want := range tests {
		got, err := Target(u)
		if err != nil || got != want {
			t.Errorf("Target(%s) = %q, %v; want %q", string(u), got, err, want)
		}
	}
}

func TestChange_NeedsConfirmation(t *testing.T) {
	t.Parallel()

	on, off, name := true, false, "x"
	u := Secret(hookURL)
	tests := []struct {
		name   string
		change Change
		want   bool
	}{
		{"rename", Change{Name: &name}, false},
		{"enable", Change{Enabled: &on}, true},
		{"disable", Change{Enabled: &off}, true},
		{"new URL", Change{URL: &u}, true},
		{"new header", Change{Header: &Header{Name: "X-Token", Value: "y"}}, true},
		{"remove header", Change{RemoveHeader: true}, true},
		{"rename and new URL", Change{Name: &name, URL: &u}, true},
	}
	for _, tt := range tests {
		if got := tt.change.NeedsConfirmation(); got != tt.want {
			t.Errorf("%s: NeedsConfirmation() = %t, want %t", tt.name, got, tt.want)
		}
	}
}

// A secret never appears in formatted output or in logs, also when the value
// that holds it is logged as a whole.
func TestSecret_NeverAppearsInOutput(t *testing.T) {
	t.Parallel()

	const value = "s3cr3t-token-value"
	spec := Spec{
		Name: "x", Type: TypeWebhook, URL: Secret("https://hooks.example.com/" + value),
		Header: &Header{Name: "X-Token", Value: value},
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	u := spec.URL
	change := Change{URL: &u, Header: spec.Header}
	logger.Info("test", slog.Any("spec", spec), slog.Any("url", spec.URL), slog.Any("header", spec.Header),
		slog.Any("change", change), slog.Any("headers", []Header{*spec.Header}))
	encoded, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String() + string(encoded) + fmt.Sprintf("%v %+v %#v %s %v", spec, spec, spec, spec.URL, *spec.Header)
	if strings.Contains(out, value) {
		t.Errorf("output contains the secret: %s", out)
	}
}
