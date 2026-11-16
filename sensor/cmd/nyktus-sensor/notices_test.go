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
		{".goreleaser.yaml", "- src: " + notices + "\n        dst: THIRD-PARTY-NOTICES.md\n"},
		{".goreleaser.yaml", "extra_files:\n      - LICENSE\n      - NOTICE\n      - " + notices + "\n"},
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

// The toolchain stamps no version for a module in a subdirectory, so the release
// links it in. A rename of the variable or of the flag would make every released
// sensor report a development version.
func TestRelease_LinksTheVersionOfTheSensor(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../../.goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	const flag = "-X nyktus.org/nyktus/sensor/internal/version.linked={{ .Version }}"
	if !strings.Contains(string(data), flag) {
		t.Errorf(".goreleaser.yaml does not link the version with %q", flag)
	}
}
