// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSameOrigin(t *testing.T) {
	t.Parallel()

	const origin = "https://nyktus.example.com"
	tests := []struct {
		name    string
		method  string
		origins []string
		want    int
	}{
		{name: "same origin", method: http.MethodPost, origins: []string{origin}, want: http.StatusNoContent},
		{name: "no origin", method: http.MethodPost, want: http.StatusNoContent},
		{name: "other subdomain", method: http.MethodPost, origins: []string{"https://wiki.example.com"}, want: http.StatusForbidden},
		{name: "other scheme", method: http.MethodDelete, origins: []string{"http://nyktus.example.com"}, want: http.StatusForbidden},
		{name: "other port", method: http.MethodPatch, origins: []string{"https://nyktus.example.com:8443"}, want: http.StatusForbidden},
		{name: "opaque origin", method: http.MethodPut, origins: []string{"null"}, want: http.StatusForbidden},
		{name: "trailing slash", method: http.MethodPost, origins: []string{origin + "/"}, want: http.StatusForbidden},
		{name: "two origin headers", method: http.MethodPost, origins: []string{origin, "https://evil.example"}, want: http.StatusForbidden},
		{name: "GET from another origin", method: http.MethodGet, origins: []string{"https://evil.example"}, want: http.StatusNoContent},
		{name: "HEAD from another origin", method: http.MethodHead, origins: []string{"https://evil.example"}, want: http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reached := false
			h := SameOrigin(origin)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusNoContent)
			}))
			r := httptest.NewRequestWithContext(t.Context(), tt.method, "/api/v1/session", nil)
			for _, o := range tt.origins {
				r.Header.Add("Origin", o)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tt.want || reached != (tt.want == http.StatusNoContent) {
				t.Errorf("status = %d, handler reached = %v; want %d", w.Code, reached, tt.want)
			}
		})
	}
}

func TestSameOrigin_RejectsInvalidOrigin(t *testing.T) {
	t.Parallel()

	for _, origin := range []string{"", "nyktus.example.com", "https://nyktus.example.com/", "https://nyktus.example.com/api"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("SameOrigin(%q) did not panic", origin)
				}
			}()
			SameOrigin(origin)
		}()
	}
}
