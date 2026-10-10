// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package buildinfo

import (
	"runtime/debug"
	"testing"
)

func TestVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version string
		want    string
	}{
		{name: "tagged build", version: "v0.1.0", want: "v0.1.0"},
		{name: "untagged build", version: "v0.0.0-20261009224706-f7ad5ccac2ac", want: "v0.0.0-20261009224706-f7ad5ccac2ac"},
		{name: "build with local changes", version: "v0.1.1-0.20261009224706-f7ad5ccac2ac+dirty", want: "v0.1.1-0.20261009224706-f7ad5ccac2ac+dirty"},
		{name: "build without version control information", version: "(devel)", want: "devel"},
		{name: "no main module version", version: "", want: "devel"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			info := debug.BuildInfo{Main: debug.Module{Version: tt.version}}
			if got := version(&info); got != tt.want {
				t.Errorf("version() = %q, want %q", got, tt.want)
			}
		})
	}
}
