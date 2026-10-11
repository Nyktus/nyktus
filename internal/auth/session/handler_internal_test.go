// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/user"
)

// Only a session may change the password, so that a leaked API key cannot take
// over the account. The request is rejected before the service is used: the
// service of the handler has no database.
func TestChangePassword_RequiresASession(t *testing.T) {
	t.Parallel()

	h := &Handler{logger: slog.New(slog.DiscardHandler), svc: &Service{}}
	p := access.Principal{UserID: "00000000-0000-4000-8000-000000000000", Role: user.RoleAdmin, Method: audit.AuthAPIKey}
	req := httptest.NewRequestWithContext(access.WithPrincipal(t.Context(), p), http.MethodPut, "/api/v1/session/password",
		strings.NewReader(`{"current_password": "correct horse battery", "new_password": "a brand new horse battery"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.ChangePassword(w, req)

	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), `"forbidden"`) {
		t.Errorf("API key: %d %s, want 403 forbidden", w.Code, w.Body)
	}
}
