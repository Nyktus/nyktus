// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"io/fs"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

// built returns the files of the build. Without one, the test is skipped, as
// go test works without Node.js; CI builds first and sets the variable, which
// turns the skip into a failure.
func built(t *testing.T) fs.FS {
	t.Helper()
	files := Dist()
	if _, err := fs.Stat(files, "index.html"); err != nil {
		if os.Getenv("NYKTUS_REQUIRE_WEB_BUILD") != "" {
			t.Fatal("the web console has not been built; run make web-build")
		}
		t.Skip("the web console has not been built")
	}
	return files
}

func read(t *testing.T, files fs.FS, name string) string {
	t.Helper()
	b, err := fs.ReadFile(files, name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func each(t *testing.T, files fs.FS, f func(name, text string)) {
	t.Helper()
	err := fs.WalkDir(files, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			return err
		}
		switch path.Ext(name) {
		case ".html", ".js", ".css", ".svg":
			f(name, read(t, files, name))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

var (
	inlineScript  = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>`)
	scriptSource  = regexp.MustCompile(`(?i)\ssrc\s*=`)
	inlineHandler = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	inlineStyle   = regexp.MustCompile(`(?i)<style[\s>]|\sstyle\s*=`)
	absoluteURL   = regexp.MustCompile("(?i)https?://[a-z0-9._-]+|[\"'`]//[a-z0-9._-]+")
	codeFromText  = regexp.MustCompile(`new Function\(|\beval\(|document\.write\(`)
)

// The content security policy allows no inline script and no inline style, so
// the page must not contain any.
func TestIndex_HoldsNoInlineCode(t *testing.T) {
	html := read(t, built(t), "index.html")
	for _, tag := range inlineScript.FindAllString(html, -1) {
		if !scriptSource.MatchString(tag) {
			t.Errorf("index.html has an inline script: %s", tag)
		}
	}
	if m := inlineHandler.FindString(html); m != "" {
		t.Errorf("index.html has an inline event handler: %q", m)
	}
	if m := inlineStyle.FindString(html); m != "" {
		t.Errorf("index.html has inline style: %q", m)
	}
}

// Every file that the page names is part of the build, so a page never loads
// from anywhere else.
func TestIndex_NamesOnlyFilesOfTheBuild(t *testing.T) {
	files := built(t)
	html := read(t, files, "index.html")
	refs := regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"']+)["']`).FindAllStringSubmatch(html, -1)
	if len(refs) == 0 {
		t.Fatal("index.html names no script")
	}
	for _, ref := range refs {
		if !strings.HasPrefix(ref[1], "/") || strings.HasPrefix(ref[1], "//") {
			t.Errorf("index.html names %q, which is not a path of the console", ref[1])
			continue
		}
		if _, err := fs.Stat(files, strings.TrimPrefix(ref[1], "/")); err != nil {
			t.Errorf("index.html names %q, which the build does not contain", ref[1])
		}
	}
}

// The console loads nothing from outside: no script, style, font or image names
// another host. Three strings are no address that anyone requests: the SVG
// namespace, the link to its documentation that Vue puts into the message of an
// error in the console of the browser, and the address of the documentation of
// Nyktus, which the pages offer as a link that the user follows. The second is
// allowed only with that path.
func TestBuild_NamesNoOtherHost(t *testing.T) {
	allowed := map[string]string{"//www.w3.org": "", "//vuejs.org": "/error-reference/", "//docs.nyktus.org": ""}
	each(t, built(t), func(name, text string) {
		for _, loc := range absoluteURL.FindAllStringIndex(text, -1) {
			m := text[loc[0]:loc[1]]
			_, rest, _ := strings.Cut(m, "//")
			host := "//" + rest
			prefix, ok := allowed[host]
			if !ok || !strings.HasPrefix(text[loc[1]:], prefix) {
				t.Errorf("%s names the host in %q", name, m+text[loc[1]:min(loc[1]+20, len(text))])
			}
		}
	})
}

// The runtime of Vue without its template compiler builds nothing from text.
func TestBuild_RunsNoTextAsCode(t *testing.T) {
	each(t, built(t), func(name, text string) {
		if path.Ext(name) != ".js" {
			return
		}
		if m := codeFromText.FindString(text); m != "" {
			t.Errorf("%s contains %s", name, m)
		}
	})
}

// The patterns find what they are for, also where the build does not, so that a
// pattern that is too narrow fails here and not unnoticed: a host without a
// top-level domain, an address or a protocol-relative URL in quotes is as external as a name.
func TestBuildPatterns_FindWhatTheyAreFor(t *testing.T) {
	t.Parallel()

	for _, text := range []string{"http://localhost:9000/x.js", "https://10.0.0.5/track", `"//intranet/x"`, `<script src="//cdn.example.com/a.js">`, "HTTPS://Example.COM"} {
		if !absoluteURL.MatchString(text) {
			t.Errorf("absoluteURL does not find %q", text)
		}
	}
	for _, text := range []string{"eval(x)", "window.eval(x)", "new Function(a)", "document.write(a)"} {
		if !codeFromText.MatchString(text) {
			t.Errorf("codeFromText does not find %q", text)
		}
	}
	for _, text := range []string{"reeval(x)", "retrieval(x)", "const evalx = 1"} {
		if codeFromText.MatchString(text) {
			t.Errorf("codeFromText finds %q, which is no call of eval", text)
		}
	}
}
