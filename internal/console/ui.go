// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package console

import (
	"errors"
	"io/fs"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"

	"nyktus.org/nyktus/internal/platform/httpx"
)

// contentSecurityPolicy lets the page load its script, style, fonts and images
// from the console only, and talk to the console only. It has no 'unsafe-inline'
// and no 'unsafe-eval': the build extracts every script and style into files, and
// the code sets styles through the DOM, which the policy permits. Nothing may
// frame the console, and a page cannot change what relative URLs mean.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; " +
	"font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

// assetsDir holds the files of the build whose names carry a hash of their
// content, so that a browser may keep them for good.
const assetsDir = "assets"

// contentTypes are the types of the files that the build produces, from a table
// of ours: the host's table of types, which the mime package reads, differs
// between systems.
var contentTypes = map[string]string{
	".js":    "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".woff2": "font/woff2",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".ico":   "image/x-icon",
	".txt":   "text/plain; charset=utf-8",
}

// ErrNoUI means that the files of the web console have not been built into the
// binary.
var ErrNoUI = errors.New("the web console is not part of this build")

// uiHandler serves the single-page application of the web console.
type uiHandler struct {
	files fs.FS
	index []byte
}

// newUIHandler returns the handler for the files of a build of the web console,
// or ErrNoUI if they hold no index.html, as in a build that skipped the web
// console.
//
// Every GET and HEAD request that no route of the API answers receives either a
// file of the build or index.html, from which the script reads the path and shows
// the page. A path under /api/ and a path of a file that does not exist keep the
// JSON 404, so that a mistyped URL of the API, of a check of health or of an asset
// is not answered with a page.
func newUIHandler(files fs.FS) (http.Handler, error) {
	index, err := fs.ReadFile(files, "index.html")
	if err != nil {
		return nil, ErrNoUI
	}
	return &uiHandler{files: files, index: index}, nil
}

// notPages are the paths of the API and of the checks of health, with everything
// below them. A probe that is misspelled, such as /readyz/, must not receive a
// page and so look healthy.
var notPages = []string{"/api", "/livez", "/readyz"}

func (h *uiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if slices.ContainsFunc(notPages, func(prefix string) bool { return p == prefix || strings.HasPrefix(p, prefix+"/") }) {
		httpx.NotFound(w, r)
		return
	}
	// The router checks the escaped path, in which %2e%2e is clean; only the
	// decoded path says where a request really points.
	if p != "/" && strings.TrimSuffix(p, "/") != path.Clean(p) {
		httpx.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(p, "/")
	if name != "" && name != "index.html" && fs.ValidPath(name) && !strings.HasPrefix(path.Base(name), ".") {
		if body, err := fs.ReadFile(h.files, name); err == nil {
			h.serveFile(w, r, name, body)
			return
		}
	}
	// A path with an extension names a file, so a missing one is a 404 and not the
	// page, which a script or style sheet would then fail to parse.
	if strings.Contains(path.Base(p), ".") {
		httpx.NotFound(w, r)
		return
	}
	h.serveIndex(w, r)
}

func (h *uiHandler) serveFile(w http.ResponseWriter, r *http.Request, name string, body []byte) {
	typ, ok := contentTypes[path.Ext(name)]
	if !ok {
		typ = "application/octet-stream"
	}
	header := w.Header()
	header.Set("Content-Type", typ)
	header.Set("X-Content-Type-Options", "nosniff")
	if strings.HasPrefix(name, assetsDir+"/") {
		header.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		header.Set("Cache-Control", "no-cache")
	}
	write(w, r, body)
}

// serveIndex answers with the page. It is never stored, so that a browser asks
// for it again, as it names the files of the current build, and shows nothing
// from the cache after the user has signed out.
func (h *uiHandler) serveIndex(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Security-Policy", contentSecurityPolicy)
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	write(w, r, h.index)
}

func write(w http.ResponseWriter, r *http.Request, body []byte) {
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	// A failed write means the client has gone away; there is nobody left to inform.
	_, _ = w.Write(body) //nolint:gosec // The body is a file of the build, never input.
}
