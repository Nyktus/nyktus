// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/platform/httpx"
)

// requestEntry passes a request from a client behind a trusted proxy through the
// console's middleware and returns the entry that a handler would build from it,
// together with the request ID sent to the client.
func requestEntry(t *testing.T, e audit.Entry) (audit.Entry, string) {
	t.Helper()
	var got audit.Entry
	h := httpx.Chain(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = e.WithRequest(r.Context())
	}), httpx.RequestID, httpx.ClientIP([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}))

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", nil)
	r.RemoteAddr = "10.0.0.2:4711"
	r.Header.Set("X-Forwarded-For", "::ffff:203.0.113.9")
	r.Header.Set("X-Request-ID", "forged")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return got, w.Header().Get("X-Request-ID")
}

func TestEntry_WithRequestTakesClientAndRequestFromMiddleware(t *testing.T) {
	t.Parallel()

	e, requestID := requestEntry(t, systemEntry())
	if want := netip.MustParseAddr("203.0.113.9"); e.ClientIP != want {
		t.Errorf("ClientIP = %s, want %s", e.ClientIP, want)
	}
	if e.RequestID == "" || e.RequestID != requestID {
		t.Errorf("RequestID = %q, want the ID sent to the client %q", e.RequestID, requestID)
	}
	if e.Action != systemEntry().Action || e.Actor != systemEntry().Actor {
		t.Errorf("WithRequest() changed the entry: %+v", e)
	}
}

func TestEntry_WithRequestOutsideARequestLeavesBothEmpty(t *testing.T) {
	t.Parallel()

	e := systemEntry().WithRequest(t.Context())
	if e.ClientIP.IsValid() || e.RequestID != "" {
		t.Errorf("ClientIP = %s, RequestID = %q, want both empty", e.ClientIP, e.RequestID)
	}
}
