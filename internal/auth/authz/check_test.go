// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"errors"
	"testing"

	"nyktus.org/nyktus/internal/audit"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/internal/user"
)

// A route that admits only sessions rejects a principal of another credential,
// even one whose role holds the permission, before the permission is checked.
// The authorizer has no database: the decision must not need one.
func TestCheck_SessionOnlyRejectsOtherCredentials(t *testing.T) {
	t.Parallel()

	a := &Authorizer{}
	key := access.Principal{UserID: "00000000-0000-4000-8000-000000000000", Role: user.RoleAdmin, Method: audit.AuthAPIKey}
	signedIn := access.Principal{UserID: key.UserID, Role: user.RoleAdmin, Method: audit.AuthSession, SessionID: "00000000-0000-4000-8000-000000000001"}
	for _, acc := range []httpx.Access{httpx.Authenticated.SessionOnly(), httpx.Require("users:write").SessionOnly()} {
		if err := a.check(t.Context(), key, acc); !errors.Is(err, httpx.ErrForbidden) {
			t.Errorf("%v with an API key: error = %v, want ErrForbidden", acc, err)
		}
		if err := a.check(t.Context(), signedIn, acc); err != nil {
			t.Errorf("%v with a session: error = %v, want nil", acc, err)
		}
	}
	if err := a.check(t.Context(), key, httpx.Authenticated); err != nil {
		t.Errorf("authenticated route with an API key: error = %v, want nil", err)
	}
}
