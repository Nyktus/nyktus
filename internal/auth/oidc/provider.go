// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Timeouts of the requests to the identity provider. The sign-in of a user
// waits for the exchange of the code, so it must not hang on an unresponsive
// provider.
const (
	requestTimeout = 10 * time.Second
	dialTimeout    = 5 * time.Second
)

// Delays between attempts to discover the provider. The first attempt is made
// at once; each failure doubles the delay up to the maximum.
const (
	firstRetryDelay = 30 * time.Second
	maxRetryDelay   = 5 * time.Minute
)

// ErrUnavailable means that the provider has not been discovered yet.
var ErrUnavailable = errors.New("identity provider not discovered yet")

// ProviderConfig configures the connection to the identity provider.
type ProviderConfig struct {
	// Issuer is the URL of the provider, exactly as its tokens name it.
	Issuer       string
	ClientID     string
	ClientSecret string
	// Scopes are requested in addition to openid.
	Scopes []string
	// RedirectURL is the callback of the console, which the provider must
	// have registered for the client.
	RedirectURL string
	// AllowHTTP permits requests to the provider without TLS, for development.
	AllowHTTP bool
}

// Provider is the identity provider. It discovers its endpoints and keys in the
// background, so that a provider that is unreachable when the console starts
// does not keep the console from serving; until then, sign-ins through it fail
// with ErrUnavailable. Signing keys are fetched again when a token names a key
// that is not known yet, so that the provider can rotate its keys.
//
// The provider is configured by the operator and is often reachable only in
// the internal network, so its requests do not go through the guard against
// server-side request forgery that protects requests to URLs supplied by users.
type Provider struct {
	cfg     ProviderConfig
	logger  *slog.Logger
	client  *http.Client
	current atomic.Pointer[endpoints]
}

// endpoints are what the discovery of the provider yields.
type endpoints struct {
	oauth    oauth2.Config
	verifier *gooidc.IDTokenVerifier
}

// NewProvider returns a Provider that is not yet discovered. Run discovers it.
func NewProvider(cfg ProviderConfig, logger *slog.Logger) *Provider {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" || logger == nil {
		panic("oidc: provider needs an issuer, a client ID, a redirect URL and a logger")
	}
	return &Provider{cfg: cfg, logger: logger, client: newClient(cfg.AllowHTTP)}
}

// newClient returns the HTTP client for the provider, with timeouts and,
// unless allowHTTP is set, only for https, which also applies to every
// redirect and to the endpoints that the discovery document names.
func newClient(allowHTTP bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Timeout: dialTimeout}).DialContext
	var rt http.RoundTripper = transport
	if !allowHTTP {
		rt = httpsOnly{next: transport}
	}
	return &http.Client{Transport: rt, Timeout: requestTimeout}
}

type httpsOnly struct {
	next http.RoundTripper
}

func (t httpsOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" {
		return nil, fmt.Errorf("oidc: refusing a request to the identity provider without TLS: %s://%s", r.URL.Scheme, r.URL.Host)
	}
	return t.next.RoundTrip(r)
}

// Run discovers the provider, and retries with a growing delay until it
// succeeds or ctx ends.
func (p *Provider) Run(ctx context.Context) {
	delay := firstRetryDelay
	for {
		err := p.discover(ctx)
		if err == nil {
			p.logger.InfoContext(ctx, "oidc: identity provider discovered", slog.String("issuer", p.cfg.Issuer))
			return
		}
		p.logger.WarnContext(ctx, "oidc: identity provider unreachable; sign-ins through it fail until it is discovered",
			slog.String("issuer", p.cfg.Issuer), slog.Duration("retry_in", delay), slog.Any("error", err))
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(2*delay, maxRetryDelay)
	}
}

func (p *Provider) discover(ctx context.Context) error {
	discovered, err := gooidc.NewProvider(p.withClient(ctx), p.cfg.Issuer)
	if err != nil {
		return err
	}
	p.current.Store(&endpoints{
		oauth: oauth2.Config{
			ClientID:     p.cfg.ClientID,
			ClientSecret: p.cfg.ClientSecret,
			Endpoint:     discovered.Endpoint(),
			RedirectURL:  p.cfg.RedirectURL,
			Scopes:       append([]string{gooidc.ScopeOpenID}, p.cfg.Scopes...),
		},
		// The key set of the verifier uses the client of the discovery, and
		// fetches keys independently of the request that needs them.
		verifier: discovered.Verifier(&gooidc.Config{ClientID: p.cfg.ClientID}),
	})
	return nil
}

// Available reports whether the provider has been discovered, so that a
// sign-in through it can succeed.
func (p *Provider) Available() bool {
	return p.current.Load() != nil
}

func (p *Provider) endpoints() (*endpoints, error) {
	e := p.current.Load()
	if e == nil {
		return nil, ErrUnavailable
	}
	return e, nil
}

// withClient returns ctx with the HTTP client of the provider.
func (p *Provider) withClient(ctx context.Context) context.Context {
	return gooidc.ClientContext(ctx, p.client)
}
