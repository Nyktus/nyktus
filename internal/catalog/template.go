// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package catalog holds the deception catalog: blueprints of scenarios, with
// the honeytokens they create and the templates of their artifacts and
// guides.
//
// Templates are data, not code. They use the syntax of text/template, but only
// a small part of it: text, references to values such as {{.Gateway.Host}},
// and {{if}} on such a value. Everything else, such as {{range}}, {{template}},
// variables, pipelines and functions, is rejected when a template is compiled,
// so that rendering is bounded by the size of the template and can never
// perform I/O. Values are escaped for the format of the template by the
// engine, not by the author of the template.
package catalog

import (
	"bytes"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"net/url"
	"regexp"
	"slices"
	"strings"
	texttemplate "text/template"
	"text/template/parse"
	"unicode"
	"unicode/utf8"
)

// Format is the kind of file that a template produces. It decides how values
// are escaped and which kinds of values the template may contain.
type Format string

// Formats of templates.
const (
	// FormatText is plain text that a person reads, such as a note.
	FormatText Format = "text"
	// FormatMarkdown is Markdown that a person reads, such as a guide.
	FormatMarkdown Format = "markdown"
	// FormatHTML is an HTML page or a file of bookmarks, opened in a browser.
	// It is rendered with html/template, which escapes every value for its
	// context.
	FormatHTML Format = "html"
	// FormatConfig is a file that a tool reads and acts on, such as an SSH
	// configuration, an INI file, a .netrc, an RDP connection or a Windows
	// shortcut.
	FormatConfig Format = "config"
)

// Formats lists every format.
var Formats = []Format{FormatText, FormatMarkdown, FormatHTML, FormatConfig}

// Valid reports whether f is a known format.
func (f Format) Valid() bool {
	return slices.Contains(Formats, f)
}

// inert reports whether a person reads files of the format, as opposed to a
// tool that acts on them. Only inert formats may contain free text: in a file
// that a tool interprets, free text could change what the tool does, such as
// a line break that starts a new directive.
func (f Format) inert() bool {
	return f != FormatConfig
}

// Kind is the kind of a value that a template references. Every kind but
// KindText is limited to characters that no supported format treats
// specially, so that such a value can never end the field it is written in.
type Kind string

// Kinds of values.
const (
	// KindHost is a host name, such as the name of a DNS honeytoken or the
	// domain of an organization: lowercase letters, digits, hyphens and dots.
	KindHost Kind = "host"
	// KindURL is an absolute http or https URL in printable ASCII without
	// quotes, spaces, backslashes or angle brackets, such as the URL of a
	// honeytoken.
	KindURL Kind = "url"
	// KindName is an account name, such as svc_backup or j.doe.
	KindName Kind = "name"
	// KindSecret is a random value of letters and digits, such as a password
	// that the server generated.
	KindSecret Kind = "secret"
	// KindText is free text on one line, such as the name of an organization.
	// It appears only in inert formats.
	KindText Kind = "text"
)

// Kinds lists every kind of value.
var Kinds = []Kind{KindHost, KindURL, KindName, KindSecret, KindText}

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	return slices.Contains(Kinds, k)
}

// Fields names the values that a template may reference, such as
// "Gateway.Host", with their kinds. A name consists of identifiers separated
// by dots, and no name is a prefix of another one, so that every name is a
// value and not a group of values.
type Fields map[string]Kind

// Limits of templates and their output.
const (
	MaxTemplateBytes = 256 << 10
	MaxOutputBytes   = 1 << 20
	// MaxTextLength is the length of a value of KindText in characters.
	MaxTextLength = 200
)

// Errors of templates.
var (
	// ErrInvalidTemplate means that a template uses something outside the
	// allowed constructs, references an unknown value or does not render.
	ErrInvalidTemplate = errors.New("invalid template")
	// ErrInvalidValue means that a value is missing or does not match its
	// kind.
	ErrInvalidValue = errors.New("invalid template value")
	// ErrOutputTooLarge means that the output of a template exceeds
	// MaxOutputBytes.
	ErrOutputTooLarge = errors.New("template output too large")
)

// Template is a compiled template.
type Template struct {
	format Format
	// fields are the values that the template references, with their kinds.
	fields Fields
	// static is the text of the template outside its actions, in every
	// branch: everything that the output can contain apart from values.
	static string
	text   *texttemplate.Template
	html   *htmltemplate.Template
}

// Compile compiles the template src of format f, which may reference the
// values fields. It rejects a template that uses a construct other than text,
// references to values and {{if}} on them, that references a value not in
// fields or a value of KindText in a format that is not inert, and a template
// that does not render with values of every kind, such as HTML whose branches
// end in different contexts. name identifies the template in errors.
func Compile(name string, f Format, src string, fields Fields) (*Template, error) {
	if !f.Valid() {
		return nil, fmt.Errorf("%w: %s: unknown format %q", ErrInvalidTemplate, name, f)
	}
	if err := fields.check(); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidTemplate, name, err)
	}
	if err := checkSource(src); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrInvalidTemplate, name, err)
	}
	tt, err := texttemplate.New(name).Option("missingkey=error").Parse(src)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidTemplate, err)
	}
	// {{define}} and {{block}} add templates of their own.
	if len(tt.Templates()) != 1 {
		return nil, fmt.Errorf("%w: %s: only one template per file is allowed", ErrInvalidTemplate, name)
	}
	used := Fields{}
	var static strings.Builder
	if err := walk(tt.Tree, tt.Root, &static, func(n parse.Node, path string) error {
		kind, ok := fields[path]
		switch {
		case !ok:
			return nodeError(tt.Tree, n, "unknown value ."+path)
		case kind == KindText && !f.inert():
			return nodeError(tt.Tree, n, fmt.Sprintf("free text .%s in a file that a tool interprets", path))
		}
		used[path] = kind
		return nil
	}); err != nil {
		return nil, err
	}

	t := &Template{format: f, fields: used, static: static.String()}
	if f == FormatHTML {
		if t.html, err = htmltemplate.New(name).Option("missingkey=error").Parse(src); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidTemplate, err)
		}
	} else {
		t.text = tt
	}
	// html/template escapes on the first execution and reports there what it
	// cannot escape, so every template renders once before it is used.
	if _, err := t.Render(sampleValues(used)); err != nil {
		return nil, fmt.Errorf("%w: %s: test render: %w", ErrInvalidTemplate, name, err)
	}
	return t, nil
}

// Render renders the template with values, which hold a value for every name
// that the template references. Values that the template does not reference
// are ignored.
func (t *Template) Render(values map[string]string) ([]byte, error) {
	data := map[string]any{}
	for path, kind := range t.fields {
		v, ok := values[path]
		if !ok {
			return nil, fmt.Errorf("%w: .%s is missing", ErrInvalidValue, path)
		}
		// The value is not part of the error: it can be inventory, such as
		// the URL of a honeytoken.
		if !validValue(kind, v) {
			return nil, fmt.Errorf("%w: .%s is not a valid %s", ErrInvalidValue, path, kind)
		}
		if kind == KindText && t.format == FormatMarkdown {
			v = escapeMarkdown(v)
		}
		insert(data, path, v)
	}

	out := &limitedBuffer{max: MaxOutputBytes}
	var err error
	if t.html != nil {
		err = t.html.Execute(out, data)
	} else {
		err = t.text.Execute(out, data)
	}
	if err != nil {
		if out.full {
			return nil, ErrOutputTooLarge
		}
		return nil, fmt.Errorf("render: %w", err)
	}
	return out.buf.Bytes(), nil
}

// walk checks the nodes below n, writes their text to static and calls field
// for every value they reference, with its name.
func walk(tree *parse.Tree, n parse.Node, static *strings.Builder, field func(n parse.Node, path string) error) error {
	switch n := n.(type) {
	case *parse.ListNode:
		for _, child := range n.Nodes {
			if err := walk(tree, child, static, field); err != nil {
				return err
			}
		}
		return nil
	case *parse.TextNode:
		static.Write(n.Text)
		// Text of different nodes is separated, so that a word cannot form
		// across a branch.
		static.WriteByte('\n')
		return nil
	case *parse.ActionNode:
		path, err := fieldOf(tree, n, n.Pipe)
		if err != nil {
			return err
		}
		return field(n, path)
	case *parse.IfNode:
		path, err := fieldOf(tree, n, n.Pipe)
		if err != nil {
			return err
		}
		if err := field(n, path); err != nil {
			return err
		}
		if err := walk(tree, n.List, static, field); err != nil {
			return err
		}
		if n.ElseList != nil {
			return walk(tree, n.ElseList, static, field)
		}
		return nil
	default:
		return nodeError(tree, n, "only text, values and {{if}} on a value are allowed")
	}
}

// fieldOf returns the name of the value that pipe references. A pipeline must
// be a single reference to a value, such as .Gateway.Host: no function, no
// variable, no literal and no second command.
func fieldOf(tree *parse.Tree, n parse.Node, pipe *parse.PipeNode) (string, error) {
	if pipe == nil || len(pipe.Decl) != 0 || pipe.IsAssign || len(pipe.Cmds) != 1 || len(pipe.Cmds[0].Args) != 1 {
		return "", nodeError(tree, n, "an action must reference exactly one value")
	}
	f, ok := pipe.Cmds[0].Args[0].(*parse.FieldNode)
	if !ok {
		return "", nodeError(tree, n, "an action must reference exactly one value")
	}
	return strings.Join(f.Ident, "."), nil
}

func nodeError(tree *parse.Tree, n parse.Node, reason string) error {
	location, _ := tree.ErrorContext(n)
	return fmt.Errorf("%w: %s: %s", ErrInvalidTemplate, location, reason)
}

// checkSource accepts UTF-8 of at most MaxTemplateBytes with no control
// characters other than tabs and line feeds, and no format characters, such
// as bidirectional overrides, which make text read differently from what it
// holds. Carriage returns are rejected as well: an artifact declares its line
// endings, and editors and Git change those of a file without notice.
func checkSource(src string) error {
	if len(src) > MaxTemplateBytes {
		return fmt.Errorf("larger than %d bytes", MaxTemplateBytes)
	}
	if !utf8.ValidString(src) {
		return errors.New("not valid UTF-8")
	}
	for _, r := range src {
		if !unicode.IsGraphic(r) && r != '\n' && r != '\t' {
			return fmt.Errorf("contains the character %U", r)
		}
	}
	return nil
}

var identifier = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

func (f Fields) check() error {
	for path, kind := range f {
		if !kind.Valid() {
			return fmt.Errorf("value .%s has the unknown kind %q", path, kind)
		}
		for segment := range strings.SplitSeq(path, ".") {
			if !identifier.MatchString(segment) {
				return fmt.Errorf("value name %q is malformed", path)
			}
		}
		for other := range f {
			if strings.HasPrefix(other, path+".") {
				return fmt.Errorf("value .%s is also a group of values, such as .%s", path, other)
			}
		}
	}
	return nil
}

// insert sets the value of the name path in data, a tree of maps, which
// text/template reads with {{.A.B}}.
func insert(data map[string]any, path, v string) {
	segments := strings.Split(path, ".")
	m := data
	for _, s := range segments[:len(segments)-1] {
		next, ok := m[s].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[s] = next
		}
		m = next
	}
	m[segments[len(segments)-1]] = v
}

var (
	hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	name      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	secret    = regexp.MustCompile(`^[A-Za-z0-9]{8,128}$`)
)

// maxURLLength is the length of a value of KindURL in bytes.
const maxURLLength = 2048

// validValue reports whether v is a valid value of kind k. An empty value is
// valid for every kind and means that the value is not set, which {{if}} can
// test.
func validValue(k Kind, v string) bool {
	if v == "" {
		return true
	}
	switch k {
	case KindHost:
		return validHost(v)
	case KindURL:
		return validURL(v)
	case KindName:
		return name.MatchString(v)
	case KindSecret:
		return secret.MatchString(v)
	case KindText:
		if utf8.RuneCountInString(v) > MaxTextLength || !utf8.ValidString(v) {
			return false
		}
		for _, r := range v {
			if !unicode.IsGraphic(r) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// validHost accepts a host name of lowercase labels. A name whose last label
// is a number is rejected, because tools read it as an IPv4 address.
func validHost(v string) bool {
	if len(v) > 253 {
		return false
	}
	labels := strings.Split(v, ".")
	for _, l := range labels {
		if !hostLabel.MatchString(l) {
			return false
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

func validURL(v string) bool {
	if len(v) > maxURLLength || (!strings.HasPrefix(v, "https://") && !strings.HasPrefix(v, "http://")) {
		return false
	}
	for i := range len(v) {
		if v[i] < 0x21 || v[i] > 0x7e || strings.IndexByte("\"'<>\\`{}|^", v[i]) >= 0 {
			return false
		}
	}
	u, err := url.Parse(v)
	return err == nil && u.Host != "" && u.User == nil
}

// escapeMarkdown escapes every ASCII punctuation character with a backslash,
// which CommonMark allows for each of them, so that free text cannot start a
// link, an image, HTML or any other markup.
func escapeMarkdown(v string) string {
	var b strings.Builder
	for _, r := range v {
		if r < utf8.RuneSelf && (unicode.IsPunct(r) || unicode.IsSymbol(r)) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// sampleValues returns a valid value of its kind for every name of fields.
func sampleValues(fields Fields) map[string]string {
	samples := map[Kind]string{
		KindHost:   "host.example.net",
		KindURL:    "https://host.example.net/path",
		KindName:   "account",
		KindSecret: "Sample0Secret0Value",
		KindText:   "Sample <text> & \"quotes\"",
	}
	values := make(map[string]string, len(fields))
	for path, kind := range fields {
		values[path] = samples[kind]
	}
	return values
}

// limitedBuffer collects output up to max bytes and fails the write that
// would exceed it, which stops the execution of the template.
type limitedBuffer struct {
	buf  bytes.Buffer
	max  int
	full bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.max {
		b.full = true
		return 0, ErrOutputTooLarge
	}
	return b.buf.Write(p)
}
