// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"net/http"
	"net/url"
)

// SameOrigin rejects requests that change state and come from another origin than
// origin, such as "https://nyktus.example.com". It protects session cookies
// against cross-site request forgery.
//
// SameSite=Strict cookies are not enough: they are also sent by pages on other
// subdomains of the same registrable domain, which count as the same site. A
// browser sends an Origin header with every request whose method is neither GET
// nor HEAD, so such a request must name origin. Requests without an Origin header
// come from clients other than browsers, which do not send cookies of their own
// accord, and are passed on. GET and HEAD must never change state.
//
// The error has a code of its own, so that the web console can tell a browser
// that reaches the console under another address than NYKTUS_CONSOLE_URL from a
// missing permission.
//
// SameOrigin panics if origin is not of the form scheme://host[:port].
func SameOrigin(origin string) Middleware {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Scheme+"://"+u.Host != origin {
		panic("httpx: origin must have the form scheme://host[:port], got " + origin)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				if values := r.Header.Values("Origin"); len(values) > 0 && (len(values) > 1 || values[0] != origin) {
					WriteError(w, r, http.StatusForbidden, CodeCrossOrigin, "cross-origin request")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
