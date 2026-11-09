// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"nyktus.org/nyktus/sensor/internal/clock/clocktest"
	"nyktus.org/nyktus/sensor/internal/conntest"
	"nyktus.org/nyktus/sensor/internal/mcp"
	"nyktus.org/nyktus/sensor/internal/report"
	"nyktus.org/nyktus/sensor/internal/session"
)

const (
	// meta is the metadata that every request of this revision carries.
	meta       = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`
	version    = "2026-07-28"
	serverName = "acme-knowledge"
	pageText   = "# Runbook\nJump host: ssh admin@10.20.0.15 <see below> & more"
)

var (
	remote = netip.MustParseAddrPort("203.0.113.9:51000")
	local  = netip.MustParseAddrPort("10.0.0.5:8080")
)

func config() *mcp.Config {
	return &mcp.Config{
		Path: "/mcp", ServerName: serverName, ServerVersion: "3.1.4", Instructions: "Ask about runbooks.",
		Tools: []mcp.Tool{
			{Name: "get_status", Description: "Status of the wiki.", Response: "all systems nominal"},
			{Name: "admin_reset", Description: "Reset.", Response: "access denied", IsError: true},
			{
				Name: "get_page", Description: "Read a page by its id.", Response: "Page not found.", SelectBy: "page_id",
				Arguments: []mcp.Argument{{Name: "page_id", Type: "string", Description: "The id.", Required: true}},
				Responses: map[string]string{"1002": pageText, "1003": "second page"},
			},
			{
				Name: "get_numbered", Description: "Read by number.", Response: "none", SelectBy: "n",
				Arguments: []mcp.Argument{{Name: "n", Type: "integer", Required: true}, {Name: "verbose", Type: "boolean"}},
				Responses: map[string]string{"7": "seventh"},
			},
		},
	}
}

// harness is a honeypot whose finished sessions are collected.
type harness struct {
	service *mcp.Service
	clock   *clocktest.Fake

	mu   sync.Mutex
	done []*session.Session
}

func newHarness(t *testing.T, cfg *mcp.Config) *harness {
	t.Helper()
	h := &harness{clock: clocktest.New()}
	hp := &session.Honeypot{ID: "7d2a51c4-3b8e-4f0a-9c6d-1e2f3a4b5c6d", Service: "mcp"}
	h.service = mcp.New(mcp.Options{
		Config: cfg, Clock: h.clock,
		Start: func(r, l netip.AddrPort) (*session.Session, error) { return session.Start(h.clock, hp, r, l) },
		Submit: func(s *session.Session) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.done = append(h.done, s)
		},
	})
	return h
}

func (h *harness) finished() []*session.Session {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.done)
}

// one ends the sessions and returns the report of the only one.
func (h *harness) one(t *testing.T) report.Session {
	t.Helper()
	h.service.Flush()
	done := h.finished()
	if len(done) != 1 {
		t.Fatalf("%d sessions, want 1", len(done))
	}
	r, ok := done[0].Report(h.clock.Elapsed())
	if !ok {
		t.Fatal("the session is too old to report")
	}
	return r
}

// result is one response as a client reads it.
type result struct {
	status int
	header http.Header
	// closes reports whether the response announced the end of the connection,
	// which the reader of net/http takes out of the headers.
	closes bool
	body   []byte
}

func (r result) rpc(t *testing.T) rpcResponse {
	t.Helper()
	var out rpcResponse
	if err := json.Unmarshal(r.body, &out); err != nil {
		t.Fatalf("decode %q: %v", r.body, err)
	}
	return out
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
}

func responses(t *testing.T, written []byte) []result {
	t.Helper()
	r := bufio.NewReader(bytes.NewReader(written))
	var out []result
	for {
		if _, err := r.Peek(1); err != nil {
			return out
		}
		resp, err := http.ReadResponse(r, nil)
		if err != nil {
			t.Fatalf("read response of %q: %v", written, err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		out = append(out, result{status: resp.StatusCode, header: resp.Header, closes: resp.Close, body: body})
	}
}

// play serves a client that sends script from the source and returns what it
// received.
func (h *harness) play(t *testing.T, from netip.AddrPort, script ...[]byte) []result {
	t.Helper()
	conn := conntest.New(bytes.Join(script, nil))
	h.service.Serve(t.Context(), conn, from, local)
	return responses(t, conn.Written())
}

// call is the request of one method, with the headers and metadata that a client
// of this revision sends.
type call struct {
	method string
	id     any
	params map[string]any
	// edit changes the headers before they are written; a value of "" removes one.
	edit func(h map[string]string)
}

func (c call) bytes(t *testing.T) []byte {
	t.Helper()
	params := map[string]any{}
	maps.Copy(params, c.params)
	if _, ok := params["_meta"]; !ok {
		params["_meta"] = map[string]any{
			"io.modelcontextprotocol/protocolVersion":    version,
			"io.modelcontextprotocol/clientInfo":         map[string]string{"name": "ExampleAgent", "version": "1.4.0"},
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		}
	}
	body := map[string]any{"jsonrpc": "2.0", "method": c.method, "params": params}
	if c.id != nil {
		body["id"] = c.id
	} else {
		body["id"] = 1
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"MCP-Protocol-Version": version, "Mcp-Method": c.method}
	if name, ok := params["name"].(string); ok {
		headers["Mcp-Name"] = name
	}
	if c.edit != nil {
		c.edit(headers)
	}
	return raw(headers, b)
}

func raw(headers map[string]string, body []byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "POST /mcp HTTP/1.1\r\nHost: wiki\r\nContent-Type: application/json\r\nContent-Length: %d\r\n", len(body))
	for _, name := range slices.Sorted(maps.Keys(headers)) {
		if headers[name] != "" {
			fmt.Fprintf(&b, "%s: %s\r\n", name, headers[name])
		}
	}
	b.WriteString("\r\n")
	b.Write(body)
	return []byte(b.String())
}

func toolCall(name string, args map[string]any) call {
	params := map[string]any{"name": name}
	if args != nil {
		params["arguments"] = args
	}
	return call{method: "tools/call", params: params}
}

func field[T any](t *testing.T, raw json.RawMessage, name string) T {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	var v T
	if err := json.Unmarshal(m[name], &v); err != nil {
		t.Fatalf("member %s of %s: %v", name, raw, err)
	}
	return v
}

func text(t *testing.T, r result) string {
	t.Helper()
	content := field[[]struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}](t, r.rpc(t).Result, "content")
	if len(content) != 1 || content[0].Type != "text" {
		t.Fatalf("content = %+v, want one text", content)
	}
	return content[0].Text
}

// server/discover is the one method that this revision requires of every server.
func TestDiscover_NamesTheRevisionTheCapabilitiesAndTheServer(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	got := h.play(t, remote, call{method: "server/discover", id: "d-1"}.bytes(t))[0]
	if got.status != 200 || got.header.Get("Content-Type") != "application/json" || got.header.Get("Date") == "" {
		t.Fatalf("response = %+v", got)
	}
	r := got.rpc(t)
	if r.JSONRPC != "2.0" || string(r.ID) != `"d-1"` {
		t.Errorf("envelope = %+v", r)
	}
	if v := field[[]string](t, r.Result, "supportedVersions"); !slices.Equal(v, []string{version}) {
		t.Errorf("supportedVersions = %v", v)
	}
	if rt := field[string](t, r.Result, "resultType"); rt != "complete" {
		t.Errorf("resultType = %q", rt)
	}
	if !bytes.Contains(r.Result, []byte(`"capabilities":{"tools":{}}`)) || !bytes.Contains(r.Result, []byte(`"instructions":"Ask about runbooks."`)) {
		t.Errorf("result = %s", r.Result)
	}
	info := field[map[string]map[string]string](t, r.Result, "_meta")["io.modelcontextprotocol/serverInfo"]
	if info["name"] != serverName || info["version"] != "3.1.4" {
		t.Errorf("serverInfo = %v", info)
	}
	if cache := field[string](t, r.Result, "cacheScope"); cache == "" || field[int](t, r.Result, "ttlMs") <= 0 {
		t.Errorf("cache fields of %s", r.Result)
	}
}

// The list comes from the configuration, in its order, and the schema from the
// arguments of a tool.
func TestToolsList_IsTheConfiguredCatalog(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	r := h.play(t, remote, call{method: "tools/list"}.bytes(t))[0].rpc(t)
	type tool struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		InputSchema map[string]any `json:"inputSchema"`
	}
	tools := field[[]tool](t, r.Result, "tools")
	if len(tools) != 4 || tools[0].Name != "get_status" || tools[2].Name != "get_page" || tools[3].Name != "get_numbered" {
		t.Fatalf("tools = %+v", tools)
	}
	if tools[0].InputSchema["additionalProperties"] != false || tools[0].InputSchema["type"] != "object" {
		t.Errorf("schema without arguments = %v", tools[0].InputSchema)
	}
	schema := tools[2].InputSchema
	property, _ := schema["properties"].(map[string]any)["page_id"].(map[string]any)
	if property["type"] != "string" || property["description"] != "The id." || fmt.Sprint(schema["required"]) != "[page_id]" {
		t.Errorf("schema = %v", schema)
	}
	if _, required := tools[3].InputSchema["required"].([]any); !required || len(tools[3].InputSchema["required"].([]any)) != 1 {
		t.Errorf("schema = %v, want only the required argument listed", tools[3].InputSchema)
	}
	if rep := h.one(t); len(rep.ToolCalls) != 0 {
		t.Errorf("tool calls = %+v, a listing is no call", rep.ToolCalls)
	}
}

// A call selects a fixed text. Characters that matter only in HTML stay as they
// are, because the escapes of a library would show in every answer.
func TestToolsCall_AnswersWithTheFixedText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		call    call
		want    string
		isError bool
	}{
		{"one answer", toolCall("get_status", nil), "all systems nominal", false},
		{"refusal", toolCall("admin_reset", map[string]any{"user": "x"}), "access denied", true},
		{"page by a string", toolCall("get_page", map[string]any{"page_id": "1002"}), pageText, false},
		{"another page", toolCall("get_page", map[string]any{"page_id": "1003"}), "second page", false},
		{"page by a number", toolCall("get_numbered", map[string]any{"n": 7}), "seventh", false},
		{"no such page", toolCall("get_page", map[string]any{"page_id": "9"}), "Page not found.", false},
		{"no argument to select by", toolCall("get_page", map[string]any{}), "Page not found.", false},
		{"a value of another type", toolCall("get_page", map[string]any{"page_id": []int{1}}), "Page not found.", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, config())
			got := h.play(t, remote, tt.call.bytes(t))[0]
			if got.status != 200 || text(t, got) != tt.want {
				t.Errorf("status %d, text %s", got.status, got.body)
			}
			if field[string](t, got.rpc(t).Result, "resultType") != "complete" {
				t.Errorf("result = %s", got.rpc(t).Result)
			}
			if isErr := bytes.Contains(got.rpc(t).Result, []byte(`"isError":true`)); isErr != tt.isError {
				t.Errorf("isError = %v, want %v: %s", isErr, tt.isError, got.body)
			}
			if tt.want == pageText && !bytes.Contains(got.body, []byte("<see below> & more")) {
				t.Errorf("body = %s, want the text as it is configured", got.body)
			}
		})
	}
}

// What a client passes is recorded, and nothing of it returns: the answer is the
// same whatever the arguments or the name of an unknown tool say.
func TestToolsCall_RecordsTheCallAndSendsNothingOfItBack(t *testing.T) {
	t.Parallel()

	const marker = "typed-by-mallory"
	h := newHarness(t, config())
	got := h.play(t, remote,
		toolCall("get_status", map[string]any{"q": marker}).bytes(t),
		toolCall("get_page", map[string]any{"page_id": marker}).bytes(t),
		toolCall(marker, map[string]any{"a": 1}).bytes(t),
	)
	for i, r := range got {
		if bytes.Contains(r.body, []byte(marker)) {
			t.Errorf("response %d repeats the input: %s", i, r.body)
		}
	}
	if e := got[2].rpc(t).Error; got[2].status != 200 || e == nil || e.Code != -32602 || e.Message != "Unknown tool" {
		t.Errorf("unknown tool = %d %s", got[2].status, got[2].body)
	}
	rep := h.one(t)
	want := []report.ToolCall{
		{ToolName: "get_status", Arguments: `{"q":"typed-by-mallory"}`},
		{ToolName: "get_page", Arguments: `{"page_id":"typed-by-mallory"}`},
		{ToolName: marker, Arguments: `{"a":1}`},
	}
	if !slices.Equal(rep.ToolCalls, want) {
		t.Errorf("tool calls = %+v, want %+v", rep.ToolCalls, want)
	}
	if rep.ClientVersion != "ExampleAgent/1.4.0" || len(rep.Attempts) != 0 {
		t.Errorf("report = %+v", rep)
	}
}

func TestToolsCall_WithoutArguments_RecordsAnEmptyObject(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	h.play(t, remote, toolCall("get_status", nil).bytes(t))
	if rep := h.one(t); len(rep.ToolCalls) != 1 || rep.ToolCalls[0].Arguments != "{}" {
		t.Errorf("tool calls = %+v, want empty arguments", rep.ToolCalls)
	}
}

// A session keeps its first calls, and what it keeps is within the limits of a
// report, cut at a character.
func TestToolsCall_LimitsWhatIsKept(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	var script [][]byte
	for i := range 8 {
		script = append(script, toolCall("get_status", map[string]any{"i": i}).bytes(t))
	}
	if got := h.play(t, remote, script...); len(got) != 8 || got[7].status != 200 {
		t.Fatalf("%d responses, want every call answered", len(got))
	}
	rep := h.one(t)
	if len(rep.ToolCalls) != 6 || rep.ToolCalls[5].Arguments != `{"i":5}` {
		t.Errorf("tool calls = %+v, want the first 6", rep.ToolCalls)
	}

	h = newHarness(t, config())
	long := strings.Repeat("a", 3000) + string(rune(0xe9))
	h.play(t, remote, toolCall(strings.Repeat("n", 40), map[string]any{"q": long}).bytes(t))
	c := h.one(t).ToolCalls[0]
	if len(c.Arguments) > report.MaxToolArguments || !strings.HasPrefix(c.Arguments, `{"q":"aaa`) {
		t.Errorf("arguments of %d bytes: %.40q", len(c.Arguments), c.Arguments)
	}
	h = newHarness(t, config())
	h.play(t, remote, raw(map[string]string{
		"MCP-Protocol-Version": version, "Mcp-Method": "tools/call", "Mcp-Name": strings.Repeat("n", 200),
	}, fmt.Appendf(nil, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"_meta":{"io.modelcontextprotocol/protocolVersion":%q,"io.modelcontextprotocol/clientCapabilities":{}}}}`, strings.Repeat("n", 200), version)))
	if c := h.one(t).ToolCalls[0]; len(c.ToolName) != report.MaxToolName {
		t.Errorf("name of %d bytes, want it cut to %d", len(c.ToolName), report.MaxToolName)
	}
}

// Arguments that are not an object are refused, but the call is recorded: the
// name shows what the caller wanted.
func TestToolsCall_ArgumentsThatAreNoObject_AreRefusedAndRecorded(t *testing.T) {
	t.Parallel()

	for _, args := range []string{`[1]`, `"x"`, `7`, `null`} {
		h := newHarness(t, config())
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_status","arguments":%s,%s}}`, args, meta)
		got := h.play(t, remote, raw(map[string]string{"MCP-Protocol-Version": version, "Mcp-Method": "tools/call", "Mcp-Name": "get_status"}, []byte(body)))[0]
		if e := got.rpc(t).Error; got.status != 200 || e == nil || e.Code != -32602 {
			t.Errorf("%s: %d %s", args, got.status, got.body)
		}
		rep := h.one(t)
		if len(rep.ToolCalls) != 1 || rep.ToolCalls[0].ToolName != "get_status" || rep.ToolCalls[0].Arguments != args {
			t.Errorf("%s: tool calls = %+v, want the call with its arguments as written", args, rep.ToolCalls)
		}
	}
}

// The headers that the transport mirrors must agree with the body, as this
// revision requires, and each rule has a case of its own.
func TestHeaders_AreComparedWithTheBody(t *testing.T) {
	t.Parallel()

	set := func(name, value string) func(map[string]string) {
		return func(h map[string]string) { h[name] = value }
	}
	tests := []struct {
		name string
		edit func(map[string]string)
		code int
	}{
		{"no version", set("MCP-Protocol-Version", ""), -32020},
		{"version that is no date", set("MCP-Protocol-Version", "latest"), -32020},
		{"version that is not spoken", set("MCP-Protocol-Version", "2025-11-25"), -32022},
		{"no method", set("Mcp-Method", ""), -32020},
		{"another method", set("Mcp-Method", "tools/list"), -32020},
		{"no name", set("Mcp-Name", ""), -32020},
		{"another name", set("Mcp-Name", "admin_reset"), -32020},
		{"a name that is not base64", set("Mcp-Name", "=?base64?***?="), -32020},
	}
	for _, tt := range tests {
		h := newHarness(t, config())
		c := toolCall("get_status", nil)
		c.edit = tt.edit
		got := h.play(t, remote, c.bytes(t))[0]
		if e := got.rpc(t).Error; got.status != 400 || e == nil || e.Code != tt.code {
			t.Errorf("%s: %d %s, want 400 with %d", tt.name, got.status, got.body, tt.code)
		}
		if rep := h.one(t); len(rep.ToolCalls) != 0 {
			t.Errorf("%s: a refused call was recorded: %+v", tt.name, rep.ToolCalls)
		}
	}
}

func TestHeaders_NameInBase64_IsDecoded(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	c := toolCall("get_status", nil)
	c.edit = func(m map[string]string) {
		m["Mcp-Name"] = "=?base64?" + base64.StdEncoding.EncodeToString([]byte("get_status")) + "?="
	}
	if got := h.play(t, remote, c.bytes(t))[0]; got.status != 200 || text(t, got) != "all systems nominal" {
		t.Errorf("response = %d %s", got.status, got.body)
	}
}

// The version in the metadata of the request must be the one of the header. The
// capabilities of the client are not asked for.
func TestMetadata_VersionMustMatchTheHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		meta map[string]any
		want int
	}{
		{"another version", map[string]any{"io.modelcontextprotocol/protocolVersion": "2025-11-25"}, 400},
		{"no version", map[string]any{"io.modelcontextprotocol/clientCapabilities": map[string]any{}}, 400},
		{"version that is no text", map[string]any{"io.modelcontextprotocol/protocolVersion": 7}, 400},
		{"no metadata", map[string]any{}, 400},
		{"the version alone", map[string]any{"io.modelcontextprotocol/protocolVersion": version}, 200},
	}
	for _, tt := range tests {
		h := newHarness(t, config())
		got := h.play(t, remote, call{method: "tools/list", params: map[string]any{"_meta": tt.meta}}.bytes(t))[0]
		if e := got.rpc(t).Error; got.status != tt.want || (tt.want == 400 && (e == nil || e.Code != -32020)) {
			t.Errorf("%s: %d %s, want %d", tt.name, got.status, got.body, tt.want)
		}
	}

	// Members are matched as written: a strict server does not take "_META" for
	// "_meta", and neither "Method" nor "JSONRPC" for theirs.
	h := newHarness(t, config())
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_META":{"io.modelcontextprotocol/protocolVersion":"` + version + `","io.modelcontextprotocol/clientCapabilities":{}}}}`
	got := h.play(t, remote, raw(map[string]string{"MCP-Protocol-Version": version, "Mcp-Method": "tools/list"}, []byte(body)))[0]
	if e := got.rpc(t).Error; got.status != 400 || e == nil || e.Code != -32020 {
		t.Errorf("_META: %d %s", got.status, got.body)
	}
	for _, body := range []string{`{"JSONRPC":"2.0","id":1,"method":"tools/list"}`, `{"jsonrpc":"2.0","id":1,"Method":"tools/list"}`} {
		got := h.play(t, remote, raw(nil, []byte(body)))[0]
		if e := got.rpc(t).Error; got.status != 400 || e == nil || e.Code != -32600 {
			t.Errorf("%s: %d %s", body, got.status, got.body)
		}
	}
	// A notification needs its members as written as well.
	if got := h.play(t, remote, raw(nil, []byte(`{"jsonrpc":"2.0","METHOD":"notifications/x"}`)))[0]; got.status != 400 {
		t.Errorf("notification with a member in another case: %d", got.status)
	}
}

// A version that is not spoken is named in the answer only in the form of a date.
func TestUnsupportedVersion_NamesTheSupportedOne(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	c := call{method: "tools/list", edit: func(m map[string]string) { m["MCP-Protocol-Version"] = "1900-01-01" }}
	got := h.play(t, remote, c.bytes(t))[0].rpc(t)
	data := map[string]any{}
	if err := json.Unmarshal(got.Error.Data, &data); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(data["supported"]) != "["+version+"]" || data["requested"] != "1900-01-01" {
		t.Errorf("data = %v", data)
	}
}

// A client of an older revision has no way forward but the message, so its
// handshake names the revision that this server speaks. Text that is no date
// does not come back.
func TestInitialize_IsRefusedAndNamesTheRevision(t *testing.T) {
	t.Parallel()

	for _, requested := range []string{"2025-11-25", "typed-by-mallory"} {
		h := newHarness(t, config())
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":%q}}`, requested)
		got := h.play(t, remote, raw(nil, []byte(body)))[0]
		e := got.rpc(t).Error
		if got.status != 400 || e == nil || e.Code != -32022 || !bytes.Contains(e.Data, []byte(version)) {
			t.Errorf("initialize = %d %s", got.status, got.body)
		}
		if bytes.Contains(got.body, []byte("mallory")) {
			t.Errorf("the answer repeats the input: %s", got.body)
		}
		if named := bytes.Contains(e.Data, []byte(`"requested":"`+requested+`"`)); named != (requested == "2025-11-25") {
			t.Errorf("requested %q: the answer names it = %v, want it only in the form of a date", requested, named)
		}
		if got.header.Get("Mcp-Session-Id") != "" {
			t.Errorf("a session id was minted: %v", got.header)
		}
	}
}

// A method that the server does not implement is 404 with the code of JSON-RPC.
func TestUnknownMethod(t *testing.T) {
	t.Parallel()

	for _, method := range []string{"resources/list", "prompts/list", "subscriptions/listen", "ping"} {
		h := newHarness(t, config())
		got := h.play(t, remote, call{method: method}.bytes(t))[0]
		if e := got.rpc(t).Error; got.status != 404 || e == nil || e.Code != -32601 {
			t.Errorf("%s: %d %s", method, got.status, got.body)
		}
	}
}

func TestNotification_IsAcceptedWithoutABody(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	got := h.play(t, remote, raw(nil, []byte(`{"jsonrpc":"2.0","method":"notifications/example"}`)))[0]
	if got.status != 202 || len(got.body) != 0 {
		t.Errorf("notification = %d %q", got.status, got.body)
	}
}

// Only an integer or a short printable string comes back.
func TestRequestID(t *testing.T) {
	t.Parallel()

	accepted := map[string]string{
		`7`: `7`, `-3`: `-3`, `0`: `0`, `"abc"`: `"abc"`, `"\u0041"`: `"A"`, `"` + strings.Repeat("x", 64) + `"`: `"` + strings.Repeat("x", 64) + `"`,
	}
	for id, want := range accepted {
		h := newHarness(t, config())
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":%q,"io.modelcontextprotocol/clientCapabilities":{}}}}`, id, version)
		got := h.play(t, remote, raw(map[string]string{"MCP-Protocol-Version": version, "Mcp-Method": "tools/list"}, []byte(body)))[0]
		if string(got.rpc(t).ID) != want {
			t.Errorf("id %s came back as %s", id, got.rpc(t).ID)
		}
	}
	refused := []string{`null`, `{"a":1}`, `[1]`, `true`, `1.5`, `1e3`, `"` + strings.Repeat("x", 65) + `"`, `"a\nb"`, `"\u00e9"`, `12345678901234567890`}
	for _, id := range refused {
		h := newHarness(t, config())
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"tools/list"}`, id)
		got := h.play(t, remote, raw(nil, []byte(body)))[0]
		if e := got.rpc(t).Error; got.status != 400 || e == nil || e.Code != -32600 || string(got.rpc(t).ID) != "null" {
			t.Errorf("id %s: %d %s", id, got.status, got.body)
		}
	}
}

func TestBody_ThatIsNoRequest(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body string
		code int
	}{
		"no JSON":        {`{`, -32700},
		"a batch":        {`[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`, -32700},
		"no version":     {`{"id":1,"method":"tools/list"}`, -32600},
		"another":        {`{"jsonrpc":"1.0","id":1,"method":"tools/list"}`, -32600},
		"no method":      {`{"jsonrpc":"2.0","id":1}`, -32600},
		"empty method":   {`{"jsonrpc":"2.0","id":1,"method":""}`, -32600},
		"null":           {`null`, -32600},
		"bad parameters": {`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":[1]}`, -32602},
	}
	for name, tt := range tests {
		h := newHarness(t, config())
		got := h.play(t, remote, raw(nil, []byte(tt.body)))[0]
		if e := got.rpc(t).Error; got.status != 400 || e == nil || e.Code != tt.code {
			t.Errorf("%s: %d %s, want 400 with %d", name, got.status, got.body, tt.code)
		}
	}
}

// A name that is no text cannot be a tool.
func TestToolsCall_NameThatIsNoText_IsInvalid(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":7,"_meta":{"io.modelcontextprotocol/protocolVersion":%q,"io.modelcontextprotocol/clientCapabilities":{}}}}`, version)
	got := h.play(t, remote, raw(map[string]string{"MCP-Protocol-Version": version, "Mcp-Method": "tools/call", "Mcp-Name": "7"}, []byte(body)))[0]
	if e := got.rpc(t).Error; got.status != 200 || e == nil || e.Code != -32602 {
		t.Errorf("response = %d %s", got.status, got.body)
	}
	if rep := h.one(t); len(rep.ToolCalls) != 0 {
		t.Errorf("tool calls = %+v", rep.ToolCalls)
	}
}

// The revision has no streams at this endpoint and no sessions to end, and any
// other path does not exist.
func TestOtherRequests(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, request string
		status        int
		allow         string
	}{
		{"GET", "GET /mcp HTTP/1.1\r\nHost: w\r\n\r\n", 405, "POST"},
		{"DELETE", "DELETE /mcp HTTP/1.1\r\nHost: w\r\n\r\n", 405, "POST"},
		{"OPTIONS", "OPTIONS /mcp HTTP/1.1\r\nHost: w\r\n\r\n", 405, "POST"},
		{"other path", "POST /admin HTTP/1.1\r\nHost: w\r\nContent-Length: 0\r\n\r\n", 404, ""},
		{"root", "GET / HTTP/1.1\r\nHost: w\r\n\r\n", 404, ""},
		{"query", "GET /mcp?a=1 HTTP/1.1\r\nHost: w\r\n\r\n", 405, "POST"},
	}
	for _, tt := range tests {
		h := newHarness(t, config())
		got := h.play(t, remote, []byte(tt.request))[0]
		if got.status != tt.status || got.header.Get("Allow") != tt.allow || len(got.body) != 0 {
			t.Errorf("%s: %d %v %q", tt.name, got.status, got.header, got.body)
		}
	}
}

// A browser is never a client of this server, so a page cannot drive it.
func TestOrigin_IsRefused(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	c := toolCall("get_status", nil)
	c.edit = func(m map[string]string) { m["Origin"] = "https://wiki.example.com" }
	if got := h.play(t, remote, c.bytes(t))[0]; got.status != 403 || len(got.body) != 0 {
		t.Errorf("response = %d %q", got.status, got.body)
	}
	if rep := h.one(t); len(rep.ToolCalls) != 0 {
		t.Errorf("tool calls = %+v", rep.ToolCalls)
	}
}

// A session id from an older client is ignored and none is minted.
func TestSessionID_IsNeitherUsedNorMinted(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	c := call{method: "tools/list", edit: func(m map[string]string) { m["Mcp-Session-Id"] = "typed-by-mallory" }}
	got := h.play(t, remote, c.bytes(t))[0]
	if got.status != 200 || got.header.Get("Mcp-Session-Id") != "" || bytes.Contains(got.body, []byte("mallory")) {
		t.Errorf("response = %d %v", got.status, got.header)
	}
}

// Every framing that this reader does not take ends the connection with a status,
// so that no bytes of one request are read as the next.
func TestFraming_IsRefused(t *testing.T) {
	t.Parallel()

	var headers, longHeaders strings.Builder
	for i := range 33 {
		fmt.Fprintf(&headers, "X-%d: b\r\n", i)
	}
	for i := range 22 {
		fmt.Fprintf(&longHeaders, "X-%d: %s\r\n", i, strings.Repeat("b", 200))
	}
	tests := []struct {
		name, request string
		status        int
	}{
		{"no version", "GET /mcp\r\n\r\n", 400},
		{"too many parts", "GET /mcp x HTTP/1.1\r\n\r\n", 400},
		{"method that is no token", "G(T /mcp HTTP/1.1\r\nHost: w\r\n\r\n", 400},
		{"no HTTP", "GET /mcp SSH/2.0\r\n\r\n", 400},
		{"HTTP/1.0", "GET /mcp HTTP/1.0\r\n\r\n", 505},
		{"HTTP/2", "PRI * HTTP/2.0\r\n\r\n", 505},
		{"header without a colon", "GET /mcp HTTP/1.1\r\nHost\r\n\r\n", 400},
		{"folded header", "GET /mcp HTTP/1.1\r\nHost: a\r\n  b: c\r\n\r\n", 400},
		{"repeated length", "POST /mcp HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na", 400},
		{"repeated host", "POST /mcp HTTP/1.1\r\nHost: a\r\nHost: b\r\nContent-Length: 0\r\n\r\n", 400},
		{"repeated version", "POST /mcp HTTP/1.1\r\nHost: w\r\nMcp-Protocol-Version: a\r\nmcp-protocol-version: b\r\nContent-Length: 0\r\n\r\n", 400},
		{"repeated method", "POST /mcp HTTP/1.1\r\nHost: w\r\nMcp-Method: a\r\nMcp-Method: b\r\nContent-Length: 0\r\n\r\n", 400},
		{"repeated name", "POST /mcp HTTP/1.1\r\nHost: w\r\nMcp-Name: a\r\nMcp-Name: b\r\nContent-Length: 0\r\n\r\n", 400},
		{"name with a character that lowers to a letter", "GET /mcp HTTP/1.1\r\nHost: w\r\nX-\u212A: b\r\n\r\n", 400},
		{"too many headers", "GET /mcp HTTP/1.1\r\n" + headers.String() + "\r\n", 431},
		{"a line too long", "GET /mcp HTTP/1.1\r\nA: " + strings.Repeat("b", 5000) + "\r\n\r\n", 431},
		{"headers too long", "GET /mcp HTTP/1.1\r\n" + longHeaders.String() + "\r\n", 431},
		{"chunked", "POST /mcp HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 411},
		{"chunked with a length", "POST /mcp HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\nabc", 411},
		{"POST without a length", "POST /mcp HTTP/1.1\r\n\r\n", 411},
		{"length that is no number", "POST /mcp HTTP/1.1\r\nContent-Length: x\r\n\r\n", 400},
		{"negative length", "POST /mcp HTTP/1.1\r\nContent-Length: -1\r\n\r\n", 400},
		{"empty length", "POST /mcp HTTP/1.1\r\nContent-Length:\r\n\r\n", 400},
		{"length beyond its digits", "POST /mcp HTTP/1.1\r\nContent-Length: 1234567\r\n\r\n", 400},
		{"body too large", "POST /mcp HTTP/1.1\r\nContent-Length: 8193\r\n\r\n", 413},
	}
	for _, tt := range tests {
		h := newHarness(t, config())
		next := "POST /mcp HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
		conn := conntest.New([]byte(tt.request + next))
		h.service.Serve(t.Context(), conn, remote, local)
		got := responses(t, conn.Written())
		if len(got) != 1 || got[0].status != tt.status || !got[0].closes {
			t.Errorf("%s: %+v, want one response with %d that closes", tt.name, got, tt.status)
		}
	}
}

// The limits of the head are the ones in the check: what lies on the limit is
// read, and one more is refused.
func TestHead_LimitsAtTheBoundary(t *testing.T) {
	t.Parallel()

	sized := func(total int) string {
		head := "POST /mcp HTTP/1.1\r\nHost: w\r\nContent-Length: 0\r\nX: "
		return head + strings.Repeat("a", total-len(head)-len("\r\n\r\n")) + "\r\n\r\n"
	}
	counted := func(n int) string {
		var b strings.Builder
		b.WriteString("POST /mcp HTTP/1.1\r\nHost: w\r\nContent-Length: 0\r\n")
		for i := range n - 2 {
			fmt.Fprintf(&b, "X-%d: b\r\n", i)
		}
		b.WriteString("\r\n")
		return b.String()
	}
	tests := []struct {
		name, request string
		status        int
	}{
		// An empty body is no request, which is answered and not refused.
		{"head of 4096 bytes", sized(4096), 400},
		{"head of 4097 bytes", sized(4097), 431},
		{"32 headers", counted(32), 400},
		{"33 headers", counted(33), 431},
	}
	for _, tt := range tests {
		h := newHarness(t, config())
		got := h.play(t, remote, []byte(tt.request))
		if len(got) != 1 || got[0].status != tt.status || got[0].closes != (tt.status == 431) {
			t.Errorf("%s: %+v, want one response with %d", tt.name, got, tt.status)
		}
	}
}

// A header that a client repeats means one line with the values joined, so a
// client that sends Accept twice is answered like any other.
func TestHeaders_RepeatedOnesAreJoined(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	body := call{method: "tools/list"}.bytes(t)
	request := bytes.Replace(body, []byte("Content-Type"), []byte("Accept: application/json\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\nConnection: close\r\nContent-Type"), 1)
	got := h.play(t, remote, request, call{method: "tools/list"}.bytes(t))
	if len(got) != 1 || got[0].status != 200 || !got[0].closes {
		t.Errorf("responses = %+v, want one that answers and closes", got)
	}
}

// A body up to the limit is read, and the limit is the one in the check.
func TestBody_AtTheLimit_IsRead(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","pad":"` + strings.Repeat("x", 8192-53-2) + `"}`
	if len(body) != 8192 {
		t.Fatalf("body of %d bytes", len(body))
	}
	if got := h.play(t, remote, raw(nil, []byte(body)))[0]; got.status != 400 || got.rpc(t).Error.Code != -32020 {
		t.Errorf("response = %d %s, want it read and its headers refused", got.status, got.body)
	}
}

// A connection answers one request after the other and ends when it is asked to.
func TestConnection_KeepAliveAndClose(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	c := call{method: "tools/list", edit: func(m map[string]string) { m["Connection"] = "close" }}
	got := h.play(t, remote, call{method: "tools/list"}.bytes(t), c.bytes(t), call{method: "tools/list"}.bytes(t))
	if len(got) != 2 || got[0].closes || !got[1].closes {
		t.Errorf("%d responses: %+v", len(got), got)
	}
}

func TestConnection_EndsAfterItsRequests(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	empty := []byte("GET /x HTTP/1.1\r\nHost: w\r\n\r\n")
	got := h.play(t, remote, bytes.Repeat(empty, 20))
	if len(got) != 16 || !got[15].closes || got[14].closes {
		t.Errorf("%d responses, want 16 and the last one closing", len(got))
	}
}

// A client cannot make the honeypot send more than the limit on one connection.
func TestConnection_EndsAfterWhatItWasSent(t *testing.T) {
	t.Parallel()

	cfg := config()
	cfg.Tools[0].Description = strings.Repeat("d", 2048)
	for i := range 12 {
		cfg.Tools = append(cfg.Tools, mcp.Tool{Name: fmt.Sprintf("t%d", i), Description: strings.Repeat("d", 2048*8), Response: "r"})
	}
	h := newHarness(t, cfg)
	var script [][]byte
	for range 16 {
		script = append(script, call{method: "tools/list"}.bytes(t))
	}
	got := h.play(t, remote, script...)
	total := 0
	for _, r := range got {
		total += len(r.body)
	}
	if len(got) == 16 || total < 256<<10 || total > (256<<10)+(300<<10) {
		t.Errorf("%d responses of %d bytes, want it to stop at the limit", len(got), total)
	}
}

// The guard bounds what a connection may send in all.
func TestConnection_ReadsNoMoreThanTheGuardAllows(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	conn := conntest.New(bytes.Repeat(call{method: "tools/list"}.bytes(t), 200))
	h.service.Serve(t.Context(), conn, remote, local)
	if conn.BytesRead() > 16<<10 {
		t.Errorf("read %d bytes", conn.BytesRead())
	}
	if len(conn.ReadDeadlines()) == 0 || len(conn.WriteDeadlines()) == 0 {
		t.Errorf("deadlines read %d, write %d: the guard was not used", len(conn.ReadDeadlines()), len(conn.WriteDeadlines()))
	}
}

// A client that sends the interim expectation gets its answer before the body.
func TestExpect_IsAnswered(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	conn := conntest.New(raw(map[string]string{"Expect": "100-continue"}, []byte(`{"jsonrpc":"2.0","method":"x"}`)))
	h.service.Serve(t.Context(), conn, remote, local)
	if !bytes.HasPrefix(conn.Written(), []byte("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 202 ")) {
		t.Errorf("written = %q", conn.Written())
	}
}

// Requests of one source are one session across connections, because a client
// closes its connection while the model thinks: the event must show the call.
func TestSession_SpansConnectionsOfASource(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	h.play(t, remote, call{method: "tools/list"}.bytes(t))
	h.clock.Advance(45 * time.Second)
	other := netip.AddrPortFrom(remote.Addr(), 51001)
	h.play(t, other, toolCall("get_status", nil).bytes(t))
	rep := h.one(t)
	if len(rep.ToolCalls) != 1 || rep.DurationMS != 45000 {
		t.Errorf("report = %+v, want the call in the one session", rep)
	}
}

func TestSession_OfAnotherSourceIsItsOwn(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	h.play(t, remote, call{method: "tools/list"}.bytes(t))
	h.play(t, netip.MustParseAddrPort("203.0.113.10:51000"), call{method: "tools/list"}.bytes(t))
	h.play(t, netip.MustParseAddrPort("[2001:db8:1:2::1]:5"), call{method: "tools/list"}.bytes(t))
	h.play(t, netip.MustParseAddrPort("[2001:db8:1:2::9]:5"), call{method: "tools/list"}.bytes(t))
	h.service.Flush()
	if n := len(h.finished()); n != 3 {
		t.Errorf("%d sessions, want 3: two IPv4 sources and one IPv6 network", n)
	}
}

// expired runs the sweep once.
func (h *harness) expired(t *testing.T) []*session.Session {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	var running sync.WaitGroup
	pending := h.clock.Pending()
	running.Go(func() { h.service.Run(ctx) })
	h.clock.BlockUntil(pending + 1)
	h.clock.Advance(5 * time.Second)
	h.clock.BlockUntil(pending + 1)
	cancel()
	running.Wait()
	return h.finished()
}

func TestSession_EndsAfterAMinuteOfSilence(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	h.play(t, remote, call{method: "tools/list"}.bytes(t))
	h.clock.Advance(50 * time.Second)
	if got := h.expired(t); len(got) != 0 {
		t.Fatalf("%d sessions ended after 55 s", len(got))
	}
	h.clock.Advance(5 * time.Second)
	got := h.expired(t)
	if len(got) != 1 {
		t.Fatalf("%d sessions ended after 65 s, want 1", len(got))
	}
	// The minute of silence is not part of what the session lasted.
	if r, _ := got[0].Report(h.clock.Elapsed()); r.DurationMS != 0 {
		t.Errorf("duration = %d ms, want 0: one request and then silence", r.DurationMS)
	}
}

// A session lasted from its first to its last request.
func TestSession_DurationIsTheTimeOfItsTraffic(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	h.play(t, remote, call{method: "tools/list"}.bytes(t))
	h.clock.Advance(20 * time.Second)
	h.play(t, remote, toolCall("get_status", nil).bytes(t))
	h.clock.Advance(time.Minute)
	if r := h.one(t); r.DurationMS != 20_000 {
		t.Errorf("duration = %d ms, want 20000", r.DurationMS)
	}
}

// A request starts the silence again, but no session outlasts its limit.
func TestSession_EndsWithinTwoMinutesHoweverOftenItIsUsed(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	h.play(t, remote, call{method: "tools/list"}.bytes(t))
	for range 3 {
		h.clock.Advance(35 * time.Second)
		h.play(t, remote, call{method: "tools/list"}.bytes(t))
	}
	if n := len(h.finished()); n != 0 {
		t.Fatalf("%d sessions ended after 105 s", n)
	}
	h.clock.Advance(5 * time.Second)
	if got := h.expired(t); len(got) != 1 {
		t.Fatalf("%d sessions ended after 115 s, want 1", len(got))
	}
	rep, _ := h.finished()[0].Report(h.clock.Elapsed())
	if rep.DurationMS > 120000 {
		t.Errorf("session lasted %d ms", rep.DurationMS)
	}
}

// A request after the end of a session belongs to a new one, also when the sweep
// has not come by.
func TestSession_RequestAfterTheEndStartsANewOne(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	h.play(t, remote, toolCall("get_status", nil).bytes(t))
	h.clock.Advance(61 * time.Second)
	h.play(t, remote, toolCall("admin_reset", nil).bytes(t))
	if got := h.finished(); len(got) != 1 {
		t.Fatalf("%d sessions ended, want the first", len(got))
	}
	h.service.Flush()
	got := h.finished()
	first, _ := got[0].Report(h.clock.Elapsed())
	second, _ := got[1].Report(h.clock.Elapsed())
	if first.ToolCalls[0].ToolName != "get_status" || second.ToolCalls[0].ToolName != "admin_reset" {
		t.Errorf("first = %+v, second = %+v", first.ToolCalls, second.ToolCalls)
	}
}

// The first thing that a client says about itself is kept.
func TestSession_KeepsTheFirstClientName(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	second := call{method: "tools/list", params: map[string]any{"_meta": map[string]any{
		"io.modelcontextprotocol/protocolVersion":    version,
		"io.modelcontextprotocol/clientInfo":         map[string]string{"name": "Other"},
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
	}}}
	h.play(t, remote, call{method: "tools/list"}.bytes(t), second.bytes(t))
	if rep := h.one(t); rep.ClientVersion != "ExampleAgent/1.4.0" {
		t.Errorf("client = %q", rep.ClientVersion)
	}

	h = newHarness(t, config())
	h.play(t, remote, second.bytes(t))
	if rep := h.one(t); rep.ClientVersion != "Other" {
		t.Errorf("client without a version = %q", rep.ClientVersion)
	}
}

// A connection without a request is a session like with every other service.
func TestSession_AConnectionAloneIsReported(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	h.play(t, remote)
	if rep := h.one(t); len(rep.ToolCalls) != 0 || len(rep.Attempts) != 0 {
		t.Errorf("report = %+v", rep)
	}
}

// The table of sessions is bounded. A source that finds it full takes the place
// of the oldest one that has only connected, so that connections alone cannot
// keep a client from being recorded.
func TestSession_TableFull_PrefersAClientToAConnection(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	for i := range 128 {
		h.play(t, source(i))
		h.clock.Advance(time.Second)
	}
	if n := h.service.TakeDropped(); n != 0 {
		t.Fatalf("dropped %d of the sources that fit", n)
	}
	got := h.play(t, source(128), toolCall("get_status", nil).bytes(t))
	if len(got) != 1 || got[0].status != 200 {
		t.Fatalf("response = %+v, want the source served", got)
	}
	if n := h.service.TakeDropped(); n != 0 {
		t.Errorf("dropped %d: the client was not recorded", n)
	}
	// The oldest connection was reported when it made room.
	done := h.finished()
	if len(done) != 1 {
		t.Fatalf("%d sessions finished, want the oldest connection", len(done))
	}
	// It ended with its traffic, not when it made room or is read.
	h.clock.Advance(10 * time.Second)
	r, _ := done[0].Report(h.clock.Elapsed())
	if r.ClientIP != source(0).Addr().String() {
		t.Errorf("the session of %s made room, want the oldest source %s", r.ClientIP, source(0).Addr())
	}
	if r.DurationMS != 0 {
		t.Errorf("duration = %d ms, want 0: it only connected", r.DurationMS)
	}
	h.service.Flush()
	var calls int
	for _, s := range h.finished() {
		r, _ := s.Report(h.clock.Elapsed())
		calls += len(r.ToolCalls)
	}
	if n := len(h.finished()); n != 129 || calls != 1 {
		t.Errorf("%d sessions with %d calls, want 129 with 1", n, calls)
	}
}

// When every place holds a client, a source is served but not recorded, and
// counted once for its connection and once for its request.
func TestSession_TableFullOfClients_DropsTheNext(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	for i := range 128 {
		h.play(t, source(i), call{method: "tools/list"}.bytes(t))
	}
	if n := h.service.TakeDropped(); n != 0 {
		t.Fatalf("dropped %d of the sources that fit", n)
	}
	got := h.play(t, source(128), toolCall("get_status", nil).bytes(t))
	if len(got) != 1 || got[0].status != 200 {
		t.Fatalf("response = %+v, want the source served", got)
	}
	if n := h.service.TakeDropped(); n != 2 {
		t.Errorf("dropped %d, want 2: the connection and the request", n)
	}
	if n := h.service.TakeDropped(); n != 0 {
		t.Errorf("TakeDropped() = %d after it was taken", n)
	}
	h.service.Flush()
	if n := len(h.finished()); n != 128 {
		t.Errorf("%d sessions, want 128", n)
	}
}

// A session that cannot be started does not keep a request from being answered,
// and is counted.
func TestSession_ThatCannotBeStarted_IsCounted(t *testing.T) {
	t.Parallel()

	clk := clocktest.New()
	svc := mcp.New(mcp.Options{
		Config: config(), Clock: clk,
		Start:  func(netip.AddrPort, netip.AddrPort) (*session.Session, error) { return nil, io.ErrUnexpectedEOF },
		Submit: func(*session.Session) { t.Error("a session that was never started was submitted") },
	})
	conn := conntest.New(call{method: "tools/list"}.bytes(t))
	svc.Serve(t.Context(), conn, remote, local)
	if got := responses(t, conn.Written()); len(got) != 1 || got[0].status != 200 {
		t.Errorf("responses = %+v, want the request answered", got)
	}
	if n := svc.TakeDropped(); n != 2 {
		t.Errorf("dropped %d, want 2: the connection and the request", n)
	}
}

func source(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}), 5) //nolint:gosec // G115: the test numbers are small.
}

// HTTP/1.1 requires the Host header, and a server that answers without it is
// not one that clients know.
func TestHost_IsRequired(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	body := []byte(`{"jsonrpc":"2.0","method":"x"}`)
	request := fmt.Sprintf("POST /mcp HTTP/1.1\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	got := h.play(t, remote, []byte(request))
	if len(got) != 1 || got[0].status != 400 || !got[0].closes {
		t.Errorf("response = %+v, want 400 that closes", got)
	}
}

// The values of Expect and Connection are tokens that HTTP compares without
// regard to case, and Connection is a list.
func TestHeaders_TokensAreComparedWithoutCase(t *testing.T) {
	t.Parallel()

	h := newHarness(t, config())
	conn := conntest.New(raw(map[string]string{"Expect": "100-Continue"}, []byte(`{"jsonrpc":"2.0","method":"x"}`)))
	h.service.Serve(t.Context(), conn, remote, local)
	if !bytes.HasPrefix(conn.Written(), []byte("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 202 ")) {
		t.Errorf("written = %q", conn.Written())
	}

	for _, value := range []string{"Close", "keep-alive, close", "TE,  CLOSE"} {
		c := call{method: "tools/list", edit: func(m map[string]string) { m["Connection"] = value }}
		got := h.play(t, remote, c.bytes(t), call{method: "tools/list"}.bytes(t))
		if len(got) != 1 || !got[0].closes {
			t.Errorf("Connection: %s: %d responses, want one that closes", value, len(got))
		}
	}
	c := call{method: "tools/list", edit: func(m map[string]string) { m["Connection"] = "keep-alive" }}
	if got := h.play(t, remote, c.bytes(t), call{method: "tools/list"}.bytes(t)); len(got) != 2 || got[0].closes {
		t.Errorf("Connection: keep-alive: %d responses", len(got))
	}
}

// With a certificate the port speaks TLS and offers only HTTP/1.1, as nothing
// else is read.
func TestTLS(t *testing.T) {
	t.Parallel()

	cfg := config()
	cfg.Certificate = testCertificate(t)
	h := newHarness(t, cfg)
	server, client := net.Pipe()
	var serving sync.WaitGroup
	serving.Go(func() {
		defer server.Close() //nolint:errcheck // nothing to do about a failed close in a test.
		h.service.Serve(t.Context(), server, remote, local)
	})
	defer serving.Wait()

	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12}) //nolint:gosec // G402: the certificate of the test is its own.
	defer tc.Close()                                                                                                                      //nolint:errcheck // nothing to do about a failed close in a test.
	if err := tc.HandshakeContext(t.Context()); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if p := tc.ConnectionState().NegotiatedProtocol; p != "http/1.1" {
		t.Errorf("protocol = %q", p)
	}
	c := call{method: "tools/list", edit: func(m map[string]string) { m["Connection"] = "close" }}
	if _, err := tc.Write(c.bytes(t)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("response = %+v, %v", resp, err)
	}
	_ = resp.Body.Close()
}

// A client that does not speak TLS to a port with a certificate gets nothing in
// the clear.
func TestTLS_PlainClientGetsNoHTTP(t *testing.T) {
	t.Parallel()

	cfg := config()
	cfg.Certificate = testCertificate(t)
	h := newHarness(t, cfg)
	conn := conntest.New(call{method: "tools/list"}.bytes(t))
	h.service.Serve(t.Context(), conn, remote, local)
	if bytes.Contains(conn.Written(), []byte("HTTP/1.1")) {
		t.Errorf("written = %q", conn.Written())
	}
}

func testCertificate(t *testing.T) *tls.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func TestNew_PanicsWithoutADependency(t *testing.T) {
	t.Parallel()

	start := func(netip.AddrPort, netip.AddrPort) (*session.Session, error) { return nil, nil } //nolint:nilnil // never called.
	submit := func(*session.Session) {}
	for name, o := range map[string]mcp.Options{
		"config": {Clock: clocktest.New(), Start: start, Submit: submit},
		"clock":  {Config: config(), Start: start, Submit: submit},
		"start":  {Config: config(), Clock: clocktest.New(), Submit: submit},
		"submit": {Config: config(), Clock: clocktest.New(), Start: start},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("New without %s did not panic", name)
				}
			}()
			mcp.New(o)
		}()
	}
}

// Whatever a client sends, the honeypot stays within its limits, and a report
// that results can be sent.
func FuzzServe(f *testing.F) {
	headers := map[string]string{"MCP-Protocol-Version": version, "Mcp-Method": "tools/call", "Mcp-Name": "get_page"}
	f.Add(raw(headers, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_page","arguments":{"page_id":"1002"},`+meta+`}}`)))
	f.Add(raw(map[string]string{"MCP-Protocol-Version": version, "Mcp-Method": "tools/list"}, []byte(`{"jsonrpc":"2.0","id":"a","method":"tools/list","params":{`+meta+`}}`)))
	f.Add(raw(map[string]string{"MCP-Protocol-Version": version, "Mcp-Method": "server/discover"}, []byte(`{"jsonrpc":"2.0","id":2,"method":"server/discover","params":{`+meta+`}}`)))
	f.Add(raw(nil, []byte(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`)))
	f.Add(raw(nil, []byte(`{"jsonrpc":"2.0","method":"x"}`)))
	f.Add(raw(map[string]string{"Mcp-Name": "=?base64?=", "Origin": "x"}, []byte(`[`)))
	f.Add([]byte("GET /mcp HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\na"))
	f.Add([]byte("POST /mcp HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"))
	f.Add([]byte("\x16\x03\x01\x00\x05hello"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, script []byte) {
		h := newHarness(t, config())
		conn := conntest.New(script)
		h.service.Serve(t.Context(), conn, remote, local)
		if conn.BytesRead() > 16<<10 {
			t.Fatalf("read %d bytes", conn.BytesRead())
		}
		if n := len(conn.Written()); n > 512<<10 {
			t.Fatalf("wrote %d bytes", n)
		}
		rep := h.one(t)
		b, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > 64<<10 || len(rep.ToolCalls) > report.MaxToolCalls || len(rep.ClientVersion) > report.MaxClientVersion {
			t.Fatalf("report = %s", b)
		}
		for _, c := range rep.ToolCalls {
			if len(c.ToolName) > report.MaxToolName || len(c.Arguments) > report.MaxToolArguments {
				t.Fatalf("tool call = %+v", c)
			}
		}
	})
}
