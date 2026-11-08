// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"strings"
	"testing"
)

// The licenses of the libraries in the binary require that their text
// accompanies every copy, so the archive and the image both carry the notices.
func TestRelease_ShipsTheThirdPartyNotices(t *testing.T) {
	t.Parallel()

	const notices = "sensor/THIRD-PARTY-NOTICES.md"
	const root = "../../../"

	cases := []struct {
		file string
		want string
	}{
		{".goreleaser.sensor.yaml", "- src: " + notices + "\n        dst: THIRD-PARTY-NOTICES.md\n"},
		{".goreleaser.sensor.yaml", "extra_files:\n      - LICENSE\n      - NOTICE\n      - " + notices + "\n"},
		{"deploy/release/Dockerfile.sensor", "COPY LICENSE NOTICE " + notices + " /licenses/\n"},
	}
	for _, tc := range cases {
		data, err := os.ReadFile(root + tc.file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), tc.want) {
			t.Errorf("%s does not hold %q", tc.file, tc.want)
		}
	}

	info, err := os.Stat(root + notices)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Errorf("%s is empty", notices)
	}
}
