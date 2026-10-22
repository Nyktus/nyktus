// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package console

import (
	"net/http"

	"nyktus.org/nyktus/internal/platform/httpx"
)

// Identity provider states that the sign-in page distinguishes.
const (
	providerOff         = "off"
	providerAvailable   = "available"
	providerUnavailable = "unavailable"
)

// Provider is the identity provider as far as the sign-in page needs it.
type Provider interface {
	// Available reports whether a sign-in through the provider can succeed.
	Available() bool
}

type signInOptions struct {
	Password bool   `json:"password"`
	OIDC     string `json:"oidc"`
}

// SignInOptionsHandler tells the sign-in page which forms of sign-in to offer.
// It describes the configuration of the instance and nothing about an account:
// whether only administrators may sign in with a password is not revealed,
// because that would tell an intruder which accounts matter. provider is nil
// without an identity provider.
//
// Without the answer, the page could only offer the button for the provider
// blindly, and the browser would show the raw error of a provider that is
// missing or down, because the sign-in is a navigation, not a request of the page.
func SignInOptionsHandler(passwordAllowed bool, provider Provider) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		state := providerOff
		if provider != nil {
			state = providerUnavailable
			if provider.Available() {
				state = providerAvailable
			}
		}
		httpx.WriteJSON(w, http.StatusOK, signInOptions{Password: passwordAllowed, OIDC: state})
	})
}
