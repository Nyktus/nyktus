// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package version

import (
	"runtime/debug"
	"testing"
)

func TestResolve(t *testing.T) {
	t.Parallel()

	stamped := &debug.BuildInfo{Main: debug.Module{Version: "v0.2.0"}}
	pseudo := &debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20261105193927-7f9b7ec2530d"}}

	tests := []struct {
		name   string
		linked string
		info   *debug.BuildInfo
		ok     bool
		want   string
	}{
		{name: "the linker wins over a pseudo-version", linked: "v0.1.0", info: pseudo, ok: true, want: "0.1.0"},
		{name: "the linker wins over another tag", linked: "v0.1.0", info: stamped, ok: true, want: "0.1.0"},
		{name: "the linker without build information", linked: "v0.1.0", want: "0.1.0"},
		{name: "a linked version that the server refuses", linked: "v0.1.0 beta", info: stamped, ok: true, want: Development},
		{name: "nothing linked uses the stamped tag", info: stamped, ok: true, want: "0.2.0"},
		{name: "nothing linked and a pseudo-version", info: pseudo, ok: true, want: Development},
		{name: "nothing linked and no build information", want: Development},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := resolve(tt.linked, tt.info, tt.ok); got != tt.want {
				t.Errorf("resolve(%q, ...) = %q, want %q", tt.linked, got, tt.want)
			}
		})
	}
}
