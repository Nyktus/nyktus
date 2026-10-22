// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package console

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"nyktus.org/nyktus/api"
	"nyktus.org/nyktus/internal/auth/oidc"
	"nyktus.org/nyktus/internal/auth/session"
	"nyktus.org/nyktus/internal/platform/apispec"
	"nyktus.org/nyktus/internal/platform/httpx"
)

type fakeProvider bool

func (f fakeProvider) Available() bool { return bool(f) }

func TestSignInOptions_DescribeTheConfiguration(t *testing.T) {
	t.Parallel()

	schemas, err := apispec.ParseSchemas(api.OpenAPI())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		password bool
		provider Provider
		want     string
	}{
		{name: "passwords only", password: true, want: `{"password":true,"oidc":"off"}`},
		{name: "provider reached", password: true, provider: fakeProvider(true), want: `{"password":true,"oidc":"available"}`},
		{name: "provider not reached yet", password: true, provider: fakeProvider(false), want: `{"password":true,"oidc":"unavailable"}`},
		{name: "provider only", password: false, provider: fakeProvider(true), want: `{"password":false,"oidc":"available"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			SignInOptionsHandler(tt.password, tt.provider).ServeHTTP(w,
				httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/sign-in-options", nil))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			if got := strings.TrimSpace(w.Body.String()); got != tt.want {
				t.Errorf("body = %s, want %s", got, tt.want)
			}
			for _, p := range schemas.Check("SignInOptions", w.Body.Bytes()) {
				t.Error(p)
			}
		})
	}
}

// The sign-in page loads the options before anyone has signed in.
func TestSignInOptions_AreAnsweredWithoutCredentials(t *testing.T) {
	t.Parallel()

	d := deps(fakePinger{})
	d.SignInOptions = SignInOptionsHandler(true, nil)
	w := httptest.NewRecorder()
	NewHandler(d).ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/sign-in-options", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for a caller without credentials", w.Code)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// A browser that reaches the console under another address receives a code of
// its own, so that the page can say so instead of reporting a missing permission.
func TestCrossOrigin_HasACodeOfItsOwnInTheSpecification(t *testing.T) {
	t.Parallel()

	var spec struct {
		Components struct {
			Responses map[string]struct {
				Description string `yaml:"description"`
			} `yaml:"responses"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(api.OpenAPI(), &spec); err != nil {
		t.Fatal(err)
	}
	if d := spec.Components.Responses["CrossOrigin"].Description; !strings.Contains(d, "`"+httpx.CodeCrossOrigin+"`") {
		t.Errorf("the response CrossOrigin does not name the code %s", httpx.CodeCrossOrigin)
	}
}

// The options follow the configuration of the console: the policy of the local
// login and the identity provider, which counts as there only if it was configured.
func TestSignInOptions_FollowTheConfigurationOfTheConsole(t *testing.T) {
	t.Parallel()

	provider := oidc.NewProvider(oidc.ProviderConfig{
		Issuer:      "https://idp.example.com",
		ClientID:    "nyktus",
		RedirectURL: "https://nyktus.example.com/api/v1/oidc/callback",
	}, slog.New(slog.DiscardHandler))
	tests := []struct {
		name string
		o    Options
		want string
	}{
		{name: "everyone with a password", o: Options{}, want: `{"password":true,"oidc":"off"}`},
		{name: "only administrators with a password", o: Options{Sessions: session.Config{LocalLogin: session.LocalLoginAdmins}}, want: `{"password":true,"oidc":"off"}`},
		{name: "no password", o: Options{Sessions: session.Config{LocalLogin: session.LocalLoginOff}}, want: `{"password":false,"oidc":"off"}`},
		{name: "provider not discovered yet", o: Options{OIDC: provider}, want: `{"password":true,"oidc":"unavailable"}`},
		{name: "provider and no password", o: Options{OIDC: provider, Sessions: session.Config{LocalLogin: session.LocalLoginOff}}, want: `{"password":false,"oidc":"unavailable"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			signInOptionsOf(tt.o).ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/sign-in-options", nil))
			if got := strings.TrimSpace(w.Body.String()); got != tt.want {
				t.Errorf("body = %s, want %s", got, tt.want)
			}
		})
	}
}
