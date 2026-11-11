// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mcp emulates a server of the Model Context Protocol, revision
// 2026-07-28, over Streamable HTTP: it lists tools from its configuration and
// answers a call with a fixed text.
//
// Nothing is run, and a tool reads no file and opens no connection. What a
// client sends is read, counted and recorded in the session; of it, only the
// identifier of a request and, in a refusal, a protocol version in the form of a
// date are sent back. Only the current revision is spoken. A client of an older
// one is refused as the specification says and appears as a connection.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strings"

	"nyktus.org/nyktus/sensor/internal/clock"
	"nyktus.org/nyktus/sensor/internal/guard"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/session"
)

// protocolVersion is the only revision that the honeypot speaks.
const protocolVersion = "2026-07-28"

// Keys of the metadata of a request and a result.
const (
	metaVersion = "io.modelcontextprotocol/protocolVersion"
	metaClient  = "io.modelcontextprotocol/clientInfo"
	metaServer  = "io.modelcontextprotocol/serverInfo"
)

// Limits of a connection, within those of the guard.
const (
	maxRequests = 16
	// maxWritten bounds what a client can make the honeypot send, as answers can
	// be much larger than the requests.
	maxWritten = 256 << 10
	// maxIDBytes is the longest identifier of a request that is sent back.
	maxIDBytes = 64
)

// JSON-RPC and MCP error codes.
const (
	codeParse           = -32700
	codeInvalidRequest  = -32600
	codeMethodNotFound  = -32601
	codeInvalidParams   = -32602
	codeHeaderMismatch  = -32020
	codeUnsupportedVers = -32022
)

// How long and where a client may cache a list. The specification requires both.
const (
	cacheTTL   = 300000
	cacheScope = "private"
)

var (
	numericID   = regexp.MustCompile(`^-?[0-9]{1,18}$`)
	datePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	nullID      = json.RawMessage("null")
)

// Options configure a Service.
type Options struct {
	Config *Config
	Clock  clock.Clock
	// Start begins the session of a source, and Submit reports it when it ends.
	Start  func(remote, local netip.AddrPort) (*session.Session, error)
	Submit func(*session.Session)
}

// Service is the MCP honeypot.
type Service struct {
	clock    clock.Clock
	path     string
	tls      *tls.Config
	tools    map[string]*Tool
	meta     json.RawMessage
	discover json.RawMessage
	list     json.RawMessage
	sessions *sessions
}

// New returns an MCP honeypot of a configuration that has been validated. It
// panics if a dependency is missing.
func New(o Options) *Service {
	if o.Config == nil || o.Clock == nil || o.Start == nil || o.Submit == nil {
		panic("mcp: missing configuration, clock, start or submit")
	}
	s := &Service{
		clock: o.Clock,
		path:  o.Config.Path,
		tools: make(map[string]*Tool, len(o.Config.Tools)),
		sessions: &sessions{
			clock: o.Clock, start: o.Start, submit: o.Submit, open: map[netip.Addr]*entry{},
		},
	}
	if o.Config.Certificate != nil {
		s.tls = &tls.Config{
			Certificates: []tls.Certificate{*o.Config.Certificate},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1"},
		}
	}
	s.meta = encode(map[string]any{metaServer: map[string]string{"name": o.Config.ServerName, "version": o.Config.ServerVersion}})
	listed := make([]listedTool, 0, len(o.Config.Tools))
	for i := range o.Config.Tools {
		t := &o.Config.Tools[i]
		s.tools[t.Name] = t
		listed = append(listed, listedTool{Name: t.Name, Description: t.Description, InputSchema: inputSchema(t.Arguments)})
	}
	s.list = encode(listResult{ResultType: "complete", Tools: listed, TTLMs: cacheTTL, CacheScope: cacheScope, Meta: s.meta})
	s.discover = encode(discoverResult{
		ResultType: "complete", SupportedVersions: []string{protocolVersion},
		Capabilities: map[string]any{"tools": struct{}{}}, Instructions: o.Config.Instructions,
		TTLMs: cacheTTL, CacheScope: cacheScope, Meta: s.meta,
	})
	return s
}

// Run ends the sessions that are over until ctx is done.
func (s *Service) Run(ctx context.Context) {
	for s.clock.Wait(ctx, sweepInterval) == nil {
		s.sessions.expire()
	}
}

// Flush ends and reports every open session. The caller has ended the
// connections.
func (s *Service) Flush() { s.sessions.flush() }

// TakeDropped returns how many requests were not recorded because the table of
// sessions was full, since the last call.
func (s *Service) TakeDropped() int { return s.sessions.takeDropped() }

// Serve answers the requests of a connection and records them in the session of
// the source. It returns when the client closes, was silent for too long or sent
// too much, and leaves closing the connection to its caller.
func (s *Service) Serve(ctx context.Context, conn net.Conn, remote, local netip.AddrPort) {
	// A connection is what every other honeypot reports, also without a request.
	s.sessions.with(remote, local, nil)

	var c net.Conn = guard.New(conn, s.clock)
	if s.tls != nil {
		tc := tls.Server(c, s.tls)
		if tc.HandshakeContext(ctx) != nil {
			return
		}
		c = tc
	}
	r := bufio.NewReaderSize(c, maxHeaderBytes)
	written := 0
	for n := 1; n <= maxRequests && ctx.Err() == nil; n++ {
		req, err := readRequest(r, c)
		if err != nil {
			var status refusal
			if errors.As(err, &status) {
				_, _ = c.Write(reply{status: int(status)}.encode(s.clock.Deadline(0), true))
			}
			return
		}
		out, record := s.answer(req)
		// One call for everything that the request records, so that the request is
		// counted once and lands in one session however the clock moves.
		s.sessions.with(remote, local, record)
		closing := n == maxRequests || hasToken(req.header["connection"], "close")
		// The clock names no time of its own: a deadline of now is the current time.
		b := out.encode(s.clock.Deadline(0), closing)
		if _, err := c.Write(b); err != nil || closing {
			return
		}
		if written += len(b); written > maxWritten {
			return
		}
	}
}

// answer returns the reply to a request and, if the request says something
// that belongs in the session of its source, what to record there.
func (s *Service) answer(req *request) (reply, func(*entry)) {
	if req.path != s.path {
		return reply{status: statusNotFound}, nil
	}
	if req.method != "POST" {
		return reply{status: statusMethodNotAllowed, allow: "POST"}, nil
	}
	// The specification requires a check of the origin. A browser is never a
	// client of this server, so every origin is invalid.
	if _, ok := req.header["origin"]; ok {
		return reply{status: statusForbidden}, nil
	}
	// The members are matched exactly, as a strict server does: encoding/json
	// would take "Method" for "method".
	m, ok := decodeObject(req.body)
	if !ok {
		return rpcError(statusBadRequest, nullID, codeParse, "Parse error", nil), nil
	}
	var version, method string
	if json.Unmarshal(m["jsonrpc"], &version) != nil || version != "2.0" ||
		json.Unmarshal(m["method"], &method) != nil || method == "" {
		return rpcError(statusBadRequest, nullID, codeInvalidRequest, "Invalid request", nil), nil
	}
	rawID, hasID := m["id"]
	if !hasID {
		return reply{status: statusAccepted}, nil
	}
	id, ok := responseID(rawID)
	if !ok {
		return rpcError(statusBadRequest, nullID, codeInvalidRequest, "Invalid request", nil), nil
	}
	p, ok := decodeParams(m["params"])
	if !ok {
		return rpcError(statusBadRequest, id, codeInvalidParams, "Invalid params", nil), nil
	}
	if method == "initialize" {
		return unsupportedVersion(id, p.ProtocolVersion), nil
	}
	if bad, ok := checkHeaders(req, method, &p, id); !ok {
		return bad, refusedCall(req, method, &p)
	}
	record := func(e *entry) { recordClient(e, &p) }

	switch method {
	case "server/discover":
		return rpcResult(id, s.discover), record
	case "tools/list":
		return rpcResult(id, s.list), record
	case "tools/call":
		return s.call(id, &p)
	default:
		return rpcError(statusNotFound, id, codeMethodNotFound, "Method not found", nil), record
	}
}

// decodeObject decodes a JSON object into its members, which keep the case that
// the client wrote. What is no object has none.
func decodeObject(raw []byte) (map[string]json.RawMessage, bool) {
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil {
		return nil, false
	}
	return members, true
}

// decodeParams reads the parameters of a request. Absent ones are empty, and so
// is metadata that is no object, which a check of the fields then refuses.
func decodeParams(raw json.RawMessage) (params, bool) {
	if len(raw) == 0 {
		return params{}, true
	}
	members, ok := decodeObject(raw)
	if !ok {
		return params{}, false
	}
	p := params{Name: members["name"], Arguments: members["arguments"]}
	_ = json.Unmarshal(members["protocolVersion"], &p.ProtocolVersion)
	p.Meta, _ = decodeObject(members["_meta"])
	return p, true
}

// checkHeaders compares the headers that the transport mirrors with the body, as
// a server of this revision must. It returns the refusal if they do not agree.
func checkHeaders(req *request, method string, p *params, id json.RawMessage) (reply, bool) {
	mismatch := rpcError(statusBadRequest, id, codeHeaderMismatch, "Header mismatch", nil)
	version := req.header["mcp-protocol-version"]
	if !datePattern.MatchString(version) {
		return mismatch, false
	}
	if version != protocolVersion {
		return unsupportedVersion(id, version), false
	}
	if req.header["mcp-method"] != method {
		return mismatch, false
	}
	// What is no version stays empty and so differs from the header.
	var declared string
	_ = json.Unmarshal(p.Meta[metaVersion], &declared)
	if declared != version {
		return mismatch, false
	}
	if method == "tools/call" {
		var name string
		if json.Unmarshal(p.Name, &name) != nil {
			return rpcError(statusOK, id, codeInvalidParams, "Invalid params", nil), false
		}
		header, present := req.header["mcp-name"]
		if !present || decodeHeader(header) != name {
			return mismatch, false
		}
	}
	return reply{}, true
}

// decodeHeader undoes the encoding of a value that cannot stand in a header. A
// value that is broken stays as it is, and so matches no name of a client that
// encodes what looks like the encoding.
func decodeHeader(v string) string {
	if !strings.HasPrefix(v, "=?base64?") || !strings.HasSuffix(v, "?=") || len(v) < len("=?base64??=") {
		return v
	}
	decoded, err := base64.StdEncoding.DecodeString(v[len("=?base64?") : len(v)-len("?=")])
	if err != nil {
		return v
	}
	return string(decoded)
}

// recordClient keeps what the client first says about itself.
func recordClient(e *entry, p *params) {
	if e.named {
		return
	}
	var info struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(p.Meta[metaClient], &info) != nil || info.Name == "" {
		return
	}
	e.named = true
	text := info.Name
	if info.Version != "" {
		text += "/" + info.Version
	}
	e.session.SetClientVersion(report.Clean(text, report.MaxClientVersion))
}

// recordCall returns what records a call of a tool and its client in the
// session: the name as the client wrote it, also of a tool that does not exist,
// and the start of its arguments. It also returns the arguments as an object,
// or nil if they are none.
func recordCall(p *params) (func(*entry), map[string]json.RawMessage) {
	var name string
	_ = json.Unmarshal(p.Name, &name)
	args := bytes.TrimSpace(p.Arguments)
	if len(args) == 0 {
		args = []byte("{}")
	}
	// The arguments come from a body that has been decoded, so they are valid JSON.
	var compact bytes.Buffer
	_ = json.Compact(&compact, args)
	called := report.ToolCall{
		ToolName:  report.Clean(name, report.MaxToolName),
		Arguments: report.Clean(compact.String(), report.MaxToolArguments),
	}
	var values map[string]json.RawMessage
	_ = json.Unmarshal(args, &values)
	return func(e *entry) {
		recordClient(e, p)
		e.session.AddToolCall(called)
	}, values
}

// call answers a call of a tool and, with the client, records it. A call of a
// tool that does not exist shows what the caller wanted as well, and so does one
// whose arguments are no object: the name is what matters.
func (s *Service) call(id json.RawMessage, p *params) (reply, func(*entry)) {
	record, values := recordCall(p)
	if values == nil {
		return rpcError(statusOK, id, codeInvalidParams, "Invalid params", nil), record
	}
	var name string
	_ = json.Unmarshal(p.Name, &name)
	tool, ok := s.tools[name]
	if !ok {
		return rpcError(statusOK, id, codeInvalidParams, "Unknown tool", nil), record
	}
	return rpcResult(id, encode(callResult{
		ResultType: "complete",
		Content:    []content{{Type: "text", Text: tool.answer(values)}},
		IsError:    tool.IsError,
		Meta:       s.meta,
	})), record
}

// refusedCall returns what records a call that was refused because its headers
// or its metadata do not fit: a client that does not know the headers of the
// revision still shows what it wanted. A call that names another revision does
// not count, as that client is not one of this revision, and neither does one
// without the name of a tool.
func refusedCall(req *request, method string, p *params) func(*entry) {
	var name string
	if method != "tools/call" || json.Unmarshal(p.Name, &name) != nil {
		return nil
	}
	var declared string
	_ = json.Unmarshal(p.Meta[metaVersion], &declared)
	for _, version := range []string{req.header["mcp-protocol-version"], declared} {
		if datePattern.MatchString(version) && version != protocolVersion {
			return nil
		}
	}
	record, _ := recordCall(p)
	return record
}

// answer returns the fixed text that a call selects.
func (t *Tool) answer(values map[string]json.RawMessage) string {
	if t.SelectBy == "" {
		return t.Response
	}
	raw := values[t.SelectBy]
	key := string(raw)
	var text string
	if json.Unmarshal(raw, &text) == nil {
		key = text
	}
	if page, ok := t.Responses[key]; ok {
		return page
	}
	return t.Response
}

// responseID returns the identifier of a request in the form it is sent back,
// and reports false if it is not one that is repeated: an integer, or a short
// printable string. The string is encoded anew, so that nothing of how the
// client wrote it returns.
func responseID(raw json.RawMessage) (json.RawMessage, bool) {
	if numericID.Match(raw) {
		return raw, true
	}
	var text string
	if json.Unmarshal(raw, &text) != nil || string(raw) == "null" || len(text) > maxIDBytes {
		return nil, false
	}
	for i := range len(text) {
		if text[i] < 0x20 || text[i] > 0x7e {
			return nil, false
		}
	}
	return encode(text), true
}

// unsupportedVersion refuses a request of a revision that is not spoken, and
// names the one that is. The requested version is repeated only in the form of
// a date.
func unsupportedVersion(id json.RawMessage, requested string) reply {
	data := map[string]any{"supported": []string{protocolVersion}}
	if datePattern.MatchString(requested) {
		data["requested"] = requested
	}
	return rpcError(statusBadRequest, id, codeUnsupportedVers, "Unsupported protocol version", data)
}

func rpcResult(id, result json.RawMessage) reply {
	return reply{status: statusOK, body: encode(response{JSONRPC: "2.0", ID: id, Result: result})}
}

func rpcError(status int, id json.RawMessage, code int, text string, data any) reply {
	return reply{status: status, body: encode(response{JSONRPC: "2.0", ID: id, Error: &errorObject{Code: code, Message: text, Data: data}})}
}

// encode returns v as JSON. Characters that matter only in HTML stay as they
// are: the escapes of the library would show in every answer and identify it.
func encode(v any) json.RawMessage {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic("mcp: encode an answer: " + err.Error())
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

// inputSchema builds the schema of a tool from its arguments.
func inputSchema(arguments []Argument) json.RawMessage {
	if len(arguments) == 0 {
		return encode(map[string]any{"type": "object", "additionalProperties": false})
	}
	properties := make(map[string]any, len(arguments))
	required := []string{}
	for _, a := range arguments {
		property := map[string]string{"type": a.Type}
		if a.Description != "" {
			property["description"] = a.Description
		}
		properties[a.Name] = property
		if a.Required {
			required = append(required, a.Name)
		}
	}
	schema := map[string]any{"type": "object", "properties": properties}
	if len(required) > 0 {
		schema["required"] = required
	}
	return encode(schema)
}

type params struct {
	Meta            map[string]json.RawMessage `json:"_meta"`
	Name            json.RawMessage            `json:"name"`
	Arguments       json.RawMessage            `json:"arguments"`
	ProtocolVersion string                     `json:"protocolVersion"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *errorObject    `json:"error,omitempty"`
}

type errorObject struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type listedTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type listResult struct {
	ResultType string          `json:"resultType"`
	Tools      []listedTool    `json:"tools"`
	TTLMs      int             `json:"ttlMs"`
	CacheScope string          `json:"cacheScope"`
	Meta       json.RawMessage `json:"_meta"`
}

type discoverResult struct {
	ResultType        string          `json:"resultType"`
	SupportedVersions []string        `json:"supportedVersions"`
	Capabilities      map[string]any  `json:"capabilities"`
	Instructions      string          `json:"instructions,omitempty"`
	TTLMs             int             `json:"ttlMs"`
	CacheScope        string          `json:"cacheScope"`
	Meta              json.RawMessage `json:"_meta"`
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type callResult struct {
	ResultType string          `json:"resultType"`
	Content    []content       `json:"content"`
	IsError    bool            `json:"isError,omitempty"`
	Meta       json.RawMessage `json:"_meta"`
}
