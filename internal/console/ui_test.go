// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package console

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"nyktus.org/nyktus/internal/platform/httpx"
	"nyktus.org/nyktus/web"
)

const indexHTML = `<!doctype html><html><head><script type="module" src="/assets/app-1a2b3c.js"></script></head><body><div id="app"></div></body></html>`

func buildFiles() fstest.MapFS {
	return fstest.MapFS{
		"index.html":            {Data: []byte(indexHTML)},
		"assets/app-1a2b3c.js":  {Data: []byte("console.log(1)")},
		"assets/app-1a2b3c.css": {Data: []byte("body{}")},
		"assets/font-9f.woff2":  {Data: []byte("wOF2")},
		"favicon.svg":           {Data: []byte("<svg/>")},
		"robots.txt":            {Data: []byte("User-agent: *")},
		"data.bin":              {Data: []byte{1, 2}},
		".gitkeep":              {},
	}
}

func uiConsole(t *testing.T, files fstest.MapFS) http.Handler {
	t.Helper()
	pages, err := newUIHandler(files)
	if err != nil {
		t.Fatal(err)
	}
	d := deps(fakePinger{})
	d.Fallback = pages
	return NewHandler(d)
}

func get(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), method, path, nil))
	return w
}

// The pages of the console are requested under paths that only its script knows,
// so every page path receives the same index.html, and nothing else does.
func TestUI_AnswersPagePathsWithTheIndex(t *testing.T) {
	t.Parallel()

	h := uiConsole(t, buildFiles())
	for _, path := range []string{"/", "/sign-in", "/sign-in/", "/setup", "/incidents/8d1c0f0e-1111-4222-8333-944444444444", "/assets"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			w := get(t, h, method, path)
			if w.Code != http.StatusOK {
				t.Errorf("%s %s status = %d, want 200", method, path, w.Code)
			}
			if got := w.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
				t.Errorf("%s %s Content-Type = %q", method, path, got)
			}
			wantBody := indexHTML
			if method == http.MethodHead {
				wantBody = ""
			}
			if w.Body.String() != wantBody {
				t.Errorf("%s %s body = %q, want %q", method, path, w.Body.String(), wantBody)
			}
		}
	}
}

// The page is never stored, carries the policy that keeps scripts and styles to
// the console's own files, and cannot be framed.
func TestUI_IndexCarriesTheSecurityHeaders(t *testing.T) {
	t.Parallel()

	w := get(t, uiConsole(t, buildFiles()), http.MethodGet, "/sign-in")
	want := map[string]string{
		"Cache-Control":           "no-store",
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": contentSecurityPolicy,
	}
	for name, value := range want {
		if got := w.Header().Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
	for _, name := range []string{"Server", "X-Powered-By"} {
		if got := w.Header().Get(name); got != "" {
			t.Errorf("%s = %q, want none", name, got)
		}
	}
}

// The policy allows no inline code and no source other than the console.
func TestContentSecurityPolicy_AllowsOnlyTheConsole(t *testing.T) {
	t.Parallel()

	directives := map[string]string{}
	for _, d := range strings.Split(contentSecurityPolicy, ";") {
		name, value, _ := strings.Cut(strings.TrimSpace(d), " ")
		directives[name] = value
	}
	for name, value := range directives {
		for _, bad := range []string{"unsafe-inline", "unsafe-eval", "data:", "blob:", "http:", "https:", "*"} {
			if strings.Contains(value, bad) {
				t.Errorf("%s allows %s", name, bad)
			}
		}
	}
	for name, want := range map[string]string{
		"default-src": "'none'", "script-src": "'self'", "style-src": "'self'", "connect-src": "'self'",
		"frame-ancestors": "'none'", "base-uri": "'none'",
	} {
		if directives[name] != want {
			t.Errorf("%s = %q, want %q", name, directives[name], want)
		}
	}
}

func TestUI_ServesTheFilesOfTheBuild(t *testing.T) {
	t.Parallel()

	h := uiConsole(t, buildFiles())
	tests := []struct {
		path, typ, cache string
	}{
		{"/assets/app-1a2b3c.js", "text/javascript; charset=utf-8", "public, max-age=31536000, immutable"},
		{"/assets/app-1a2b3c.css", "text/css; charset=utf-8", "public, max-age=31536000, immutable"},
		{"/assets/font-9f.woff2", "font/woff2", "public, max-age=31536000, immutable"},
		{"/favicon.svg", "image/svg+xml", "no-cache"},
		{"/robots.txt", "text/plain; charset=utf-8", "no-cache"},
		{"/data.bin", "application/octet-stream", "no-cache"},
	}
	for _, tt := range tests {
		w := get(t, h, http.MethodGet, tt.path)
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != tt.typ || w.Header().Get("Cache-Control") != tt.cache {
			t.Errorf("GET %s = %d, %q, %q; want 200, %q, %q", tt.path, w.Code, w.Header().Get("Content-Type"), w.Header().Get("Cache-Control"), tt.typ, tt.cache)
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("GET %s lacks nosniff", tt.path)
		}
		if w.Header().Get("Content-Security-Policy") != "" {
			t.Errorf("GET %s carries a policy, which only documents need", tt.path)
		}
	}
}

// What is not a page keeps the JSON 404: the API, files that do not exist, files
// the build does not contain, dotfiles and every method other than GET and HEAD.
func TestUI_KeepsTheJSONNotFound(t *testing.T) {
	t.Parallel()

	h := uiConsole(t, buildFiles())
	tests := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/nope"},
		{http.MethodGet, "/api/v1/setup"},
		{http.MethodGet, "/api"},
		{http.MethodGet, "/livez/"},
		{http.MethodGet, "/readyz/"},
		{http.MethodGet, "/readyz/extra"},
		{http.MethodHead, "/livez/extra"},
		{http.MethodGet, "/assets/missing.js"},
		{http.MethodGet, "/missing.png"},
		{http.MethodGet, "/.gitkeep"},
		{http.MethodGet, "/index.html"},
		{http.MethodGet, "/%2e%2e/etc/passwd"},
		{http.MethodGet, "/a//b"},
		{http.MethodPost, "/sign-in"},
		{http.MethodDelete, "/"},
		{http.MethodPost, "/livez"},
	}
	for _, tt := range tests {
		w := get(t, h, tt.method, tt.path)
		if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), `"code":"`+httpx.CodeNotFound+`"`) {
			t.Errorf("%s %s = %d %q, want the JSON 404", tt.method, tt.path, w.Code, w.Body.String())
		}
	}
}

// The health endpoints and the API are the same with the pages.
func TestUI_LeavesTheRoutesAlone(t *testing.T) {
	t.Parallel()

	h := uiConsole(t, buildFiles())
	for path, want := range map[string]string{"/livez": `{"status":"ok"}`, "/readyz": `{"status":"ok"}`} {
		w := get(t, h, http.MethodGet, path)
		if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != want {
			t.Errorf("GET %s = %d %q", path, w.Code, w.Body.String())
		}
	}
	// A route of the API still asks for credentials.
	if w := get(t, h, http.MethodGet, "/api/v1/session"); w.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/session = %d, want 401", w.Code)
	}
}

func TestNewUIHandler_NeedsAnIndex(t *testing.T) {
	t.Parallel()

	for name, files := range map[string]fstest.MapFS{
		"only the placeholder": {".gitkeep": {}},
		"no files":             {},
	} {
		if _, err := newUIHandler(files); !errors.Is(err, ErrNoUI) {
			t.Errorf("%s: newUIHandler() error = %v, want ErrNoUI", name, err)
		}
	}
}

// Without the pages, every other path is the JSON 404.
func TestConsole_WithoutPagesAnswersTheJSONNotFound(t *testing.T) {
	t.Parallel()

	w := get(t, NewHandler(deps(fakePinger{})), http.MethodGet, "/sign-in")
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), `"code":"not_found"`) {
		t.Errorf("GET /sign-in = %d %q, want the JSON 404", w.Code, w.Body.String())
	}
}

// The console serves the build that is embedded into the binary: the page, and
// the script that it names, with the types and the caching of each.
func TestUI_ServesTheEmbeddedBuild(t *testing.T) {
	t.Parallel()

	files := web.Dist()
	index, err := fs.ReadFile(files, "index.html")
	if err != nil {
		if os.Getenv("NYKTUS_REQUIRE_WEB_BUILD") != "" {
			t.Fatal("the web console has not been built; run make web-build")
		}
		t.Skip("the web console has not been built")
	}
	m := regexp.MustCompile(`src="(/assets/[^"]+\.js)"`).FindSubmatch(index)
	if m == nil {
		t.Fatal("index.html names no script in assets/")
	}
	pages, err := newUIHandler(files)
	if err != nil {
		t.Fatal(err)
	}
	d := deps(fakePinger{})
	d.Fallback = pages
	h := NewHandler(d)

	if w := get(t, h, http.MethodGet, "/sign-in"); w.Body.String() != string(index) {
		t.Error("/sign-in does not answer with index.html")
	}
	w := get(t, h, http.MethodGet, string(m[1]))
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/javascript; charset=utf-8" ||
		w.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" || w.Body.Len() == 0 {
		t.Errorf("GET %s = %d, %q, %q", m[1], w.Code, w.Header().Get("Content-Type"), w.Header().Get("Cache-Control"))
	}
}
