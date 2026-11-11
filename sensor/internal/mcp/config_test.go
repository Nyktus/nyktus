// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"nyktus.org/nyktus/sensor/internal/mcp"
)

func problemsOf(c *mcp.Config) string {
	var b strings.Builder
	for _, err := range c.Validate() {
		b.WriteString(err.Error())
		b.WriteString("\n")
	}
	return b.String()
}

func TestValidate_AcceptsAComplete(t *testing.T) {
	t.Parallel()

	if p := problemsOf(config()); p != "" {
		t.Errorf("Validate() = %s", p)
	}
}

// Each rule has a case of its own, and the case names the field it expects.
func TestValidate_Refuses(t *testing.T) {
	t.Parallel()

	long := func(n int) string { return strings.Repeat("a", n) }
	tests := []struct {
		name  string
		edit  func(c *mcp.Config)
		field string
	}{
		{"no path", func(c *mcp.Config) { c.Path = "" }, "path:"},
		{"relative path", func(c *mcp.Config) { c.Path = "mcp" }, "path:"},
		{"path with a query", func(c *mcp.Config) { c.Path = "/a?b" }, "path:"},
		{"path with a fragment", func(c *mcp.Config) { c.Path = "/a#b" }, "path:"},
		{"path with a space", func(c *mcp.Config) { c.Path = "/a b" }, "path:"},
		{"path too long", func(c *mcp.Config) { c.Path = "/" + long(128) }, "path:"},
		{"no server name", func(c *mcp.Config) { c.ServerName = "" }, "server_name:"},
		{"server name too long", func(c *mcp.Config) { c.ServerName = long(129) }, "server_name:"},
		{"server name with a line break", func(c *mcp.Config) { c.ServerName = "a\nb" }, "server_name:"},
		{"no server version", func(c *mcp.Config) { c.ServerVersion = "" }, "server_version:"},
		{"server version too long", func(c *mcp.Config) { c.ServerVersion = long(65) }, "server_version:"},
		{"instructions too long", func(c *mcp.Config) { c.Instructions = long(4097) }, "instructions:"},
		{"instructions with a control character", func(c *mcp.Config) { c.Instructions = "a\x1bb" }, "instructions:"},
		{"no tools", func(c *mcp.Config) { c.Tools = nil }, "tools:"},
		{"too many tools", func(c *mcp.Config) {
			for i := range 16 {
				c.Tools = append(c.Tools, mcp.Tool{Name: fmt.Sprintf("x%d", i), Description: "d", Response: "r"})
			}
		}, "tools:"},
		{"tool without a name", func(c *mcp.Config) { c.Tools[0].Name = "" }, "tools[0].name:"},
		{"tool name with a space", func(c *mcp.Config) { c.Tools[0].Name = "a b" }, "tools[0].name:"},
		{"tool name too long", func(c *mcp.Config) { c.Tools[0].Name = long(65) }, "tools[0].name:"},
		{"tool name twice", func(c *mcp.Config) { c.Tools[1].Name = c.Tools[0].Name }, "tools[1].name:"},
		{"no description", func(c *mcp.Config) { c.Tools[0].Description = "" }, "tools[0].description:"},
		{"description too long", func(c *mcp.Config) { c.Tools[0].Description = long(2049) }, "tools[0].description:"},
		{"no response", func(c *mcp.Config) { c.Tools[0].Response = "" }, "tools[0].response:"},
		{"response too long", func(c *mcp.Config) { c.Tools[0].Response = long(16385) }, "tools[0].response:"},
		{"response that is not UTF-8", func(c *mcp.Config) { c.Tools[0].Response = "\xff" }, "tools[0].response:"},
		{"too many arguments", func(c *mcp.Config) {
			for i := range 9 {
				c.Tools[0].Arguments = append(c.Tools[0].Arguments, mcp.Argument{Name: fmt.Sprintf("a%d", i), Type: "string"})
			}
		}, "tools[0].arguments:"},
		{"argument without a name", func(c *mcp.Config) { c.Tools[0].Arguments = []mcp.Argument{{Type: "string"}} }, "tools[0].arguments[0].name:"},
		{"argument twice", func(c *mcp.Config) {
			c.Tools[0].Arguments = []mcp.Argument{{Name: "a", Type: "string"}, {Name: "a", Type: "string"}}
		}, "tools[0].arguments[1].name:"},
		{"argument of no type", func(c *mcp.Config) { c.Tools[0].Arguments = []mcp.Argument{{Name: "a"}} }, "tools[0].arguments[0].type:"},
		{"argument of another type", func(c *mcp.Config) { c.Tools[0].Arguments = []mcp.Argument{{Name: "a", Type: "number"}} }, "tools[0].arguments[0].type:"},
		{"argument description too long", func(c *mcp.Config) {
			c.Tools[0].Arguments = []mcp.Argument{{Name: "a", Type: "string", Description: long(513)}}
		}, "tools[0].arguments[0].description:"},
		{"pages without select_by", func(c *mcp.Config) { c.Tools[0].Responses = map[string]string{"1": "a"} }, "tools[0].responses:"},
		{"select_by without pages", func(c *mcp.Config) { c.Tools[2].Responses = nil }, "tools[2].responses:"},
		{"select_by of no argument", func(c *mcp.Config) { c.Tools[2].SelectBy = "other" }, "tools[2].select_by:"},
		{"select_by of a boolean", func(c *mcp.Config) { c.Tools[3].SelectBy = "verbose" }, "tools[3].select_by:"},
		{"too many pages", func(c *mcp.Config) {
			for i := range 33 {
				c.Tools[2].Responses[strconv.Itoa(i)] = "p"
			}
		}, "tools[2].responses:"},
		{"page key too long", func(c *mcp.Config) { c.Tools[2].Responses[long(129)] = "p" }, "tools[2].responses:"},
		{"empty page key", func(c *mcp.Config) { c.Tools[2].Responses[""] = "p" }, "tools[2].responses:"},
		{"empty page", func(c *mcp.Config) { c.Tools[2].Responses["1"] = "" }, "tools[2].responses:"},
		{"page too long", func(c *mcp.Config) { c.Tools[2].Responses["1"] = long(16385) }, "tools[2].responses:"},
	}
	for _, tt := range tests {
		c := config()
		tt.edit(c)
		if p := problemsOf(c); !strings.Contains(p, tt.field) {
			t.Errorf("%s: Validate() = %q, want a problem of %s", tt.name, p, tt.field)
		}
	}
}

// The limits are inclusive, and text in any language and with line breaks is
// fine where a text may have them.
func TestValidate_AcceptsWhatIsWithinTheLimits(t *testing.T) {
	t.Parallel()

	long := func(n int) string { return strings.Repeat("a", n) }
	c := config()
	c.Path = "/" + long(127)
	c.ServerName = long(128)
	c.ServerVersion = long(64)
	c.Instructions = long(4096)
	c.Tools[0].Name = long(64)
	c.Tools[0].Description = "Sucht in \u00dcbergabe-Notizen\nund\tTabellen"
	c.Tools[0].Response = long(16384)
	c.Tools[2].Responses["1"] = long(16384)
	c.Tools[2].Responses[long(128)] = "p"
	if p := problemsOf(c); p != "" {
		t.Errorf("Validate() = %s", p)
	}
}
