// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"nyktus.org/nyktus/internal/user"
)

// Every expected error maps to its status and code, also when it is wrapped.
// The last active administrator, for example, can only be reached through the
// API by concurrent requests.
func TestWriteError_MapsExpectedErrors(t *testing.T) {
	t.Parallel()

	h := &Handler{logger: slog.New(slog.DiscardHandler)}
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{user.ErrNotFound, http.StatusNotFound, "not_found"},
		{user.ErrEmailTaken, http.StatusConflict, CodeEmailTaken},
		{user.ErrLastActiveAdmin, http.StatusConflict, CodeLastActiveAdmin},
		{ErrOwnAccount, http.StatusConflict, CodeOwnAccount},
		{user.ErrInvalidTransition, http.StatusConflict, CodeInvalidState},
		{ErrNotPending, http.StatusConflict, CodeInvalidState},
		{errors.New("database is down"), http.StatusInternalServerError, "internal_error"},
	}
	for _, tt := range tests {
		rec := httptest.NewRecorder()
		h.writeError(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/", nil), "test", fmt.Errorf("wrapped: %w", tt.err))
		var body struct {
			Error struct{ Code string } `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != tt.status || body.Error.Code != tt.code {
			t.Errorf("writeError(%v) = %d %s, want %d %s", tt.err, rec.Code, rec.Body, tt.status, tt.code)
		}
	}
}
