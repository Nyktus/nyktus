// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package session

import (
	"errors"
	"net/http"

	"nyktus.org/nyktus/internal/platform/httpx"
)

// codeReauthenticationRequired asks an administrator of the identity provider,
// who has no password, to sign in there again.
const codeReauthenticationRequired = "reauthentication_required"

// WriteConfirmationError writes the response for an error of Confirm that
// concerns the confirmation itself and reports whether it did. Other errors,
// such as those of the change, are left to the caller.
func WriteConfirmationError(w http.ResponseWriter, r *http.Request, err error) bool {
	var locked *LockedError
	switch {
	case errors.Is(err, ErrWrongPassword):
		httpx.WriteError(w, r, http.StatusForbidden, codeWrongPassword, "the password is wrong")
	case errors.As(err, &locked):
		writeLocked(w, r, locked)
	case errors.Is(err, ErrNoSession):
		writeNoSession(w, r)
	case errors.Is(err, ErrReauthenticationRequired):
		httpx.WriteError(w, r, http.StatusForbidden, codeReauthenticationRequired,
			"sign in at the identity provider again through GET /api/v1/oidc/reauthenticate, then repeat the request within 5 minutes")
	default:
		return false
	}
	return true
}
