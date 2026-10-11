// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package oidc_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc/oidctest"
)

const (
	clientID     = "nyktus"
	clientSecret = "client secret"
	keyID        = "key-1"
)

// idp is an identity provider for tests. It serves discovery, its keys and the
// token endpoint; the authorization endpoint, which a browser would visit, is
// replaced by authorize, which the test calls with the URL that the console
// sends the browser to.
type idp struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey
	// redirectURL is the callback that the client registered.
	redirectURL string

	mu     sync.Mutex
	grants map[string]grant
}

type grant struct {
	challenge string
	claims    map[string]any
	// signer signs the ID token; the key of the provider if nil.
	signer *rsa.PrivateKey
}

func newIDP(t *testing.T, redirectURL string) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p := &idp{t: t, key: key, redirectURL: redirectURL, grants: map[string]grant{}}
	keys := &oidctest.Server{PublicKeys: []oidctest.PublicKey{{PublicKey: key.Public(), KeyID: keyID, Algorithm: "RS256"}}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", p.token)
	mux.Handle("/", keys)
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	keys.SetIssuer(p.srv.URL)
	return p
}

func (p *idp) issuer() string { return p.srv.URL }

// option changes the grant of a code.
type option func(*grant)

// withClaims sets claims of the ID token, or removes those set to nil.
func withClaims(claims map[string]any) option {
	return func(g *grant) {
		for k, v := range claims {
			if v == nil {
				delete(g.claims, k)
			} else {
				g.claims[k] = v
			}
		}
	}
}

func signedBy(key *rsa.PrivateKey) option {
	return func(g *grant) { g.signer = key }
}

// authorize checks the request with which the console sent the browser to the
// provider and returns the code with which the provider sends it back, for a
// user with the subject sub, the given groups and default claims.
func (p *idp) authorize(location, sub string, groups []string, opts ...option) (state, code string) {
	p.t.Helper()
	u, err := url.Parse(location)
	if err != nil || !strings.HasPrefix(location, p.issuer()+"/auth?") {
		p.t.Fatalf("the console sent the browser to %q, want the authorization endpoint", location)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"response_type": "code", "client_id": clientID, "redirect_uri": p.redirectURL, "code_challenge_method": "S256",
	} {
		if got := q.Get(k); got != want {
			p.t.Fatalf("authorization request: %s = %q, want %q", k, got, want)
		}
	}
	if !strings.Contains(" "+q.Get("scope")+" ", " openid ") {
		p.t.Fatalf("authorization request: scope = %q, want openid", q.Get("scope"))
	}
	now := time.Now()
	g := grant{
		challenge: q.Get("code_challenge"),
		claims: map[string]any{
			"iss": p.issuer(), "aud": clientID, "sub": sub, "nonce": q.Get("nonce"),
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"email": sub + "@example.com", "email_verified": true, "name": "User " + sub, "groups": groups,
		},
	}
	for _, o := range opts {
		o(&g)
	}
	code = rand.Text()
	p.mu.Lock()
	p.grants[code] = g
	p.mu.Unlock()
	return q.Get("state"), code
}

// token serves the token endpoint: it checks the client, the redirect URI and
// the PKCE verifier, and issues the ID token of the code once.
func (p *idp) token(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := r.BasicAuth()
	if err := r.ParseForm(); err != nil || !ok || id != url.QueryEscape(clientID) || secret != url.QueryEscape(clientSecret) {
		tokenError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	p.mu.Lock()
	g, found := p.grants[r.PostForm.Get("code")]
	delete(p.grants, r.PostForm.Get("code"))
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !found || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("redirect_uri") != p.redirectURL ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	signer := g.signer
	if signer == nil {
		signer = p.key
	}
	claims, err := json.Marshal(maps.Clone(g.claims))
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "access", "token_type": "Bearer", "expires_in": 3600,
		"id_token": oidctest.SignIDToken(signer, keyID, "RS256", string(claims)),
	})
	if err != nil {
		p.t.Errorf("write token response: %v", err)
	}
}

func tokenError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
}
