// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package version_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The release builds set the version with a linker flag that names the variable
// by its path. A flag that misses the variable is ignored without a message, so
// only a real build proves that the name is right.
func TestLinkerFlag_SetsTheVersionOfTheBinary(t *testing.T) {
	t.Parallel()

	binary := filepath.Join(t.TempDir(), "nyktus-sensor")
	const flag = "-X nyktus.org/nyktus/sensor/internal/version.linked=v1.2.3"
	build := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-ldflags", flag, "-o", binary, "./cmd/nyktus-sensor") //nolint:gosec // G204: the arguments are constants and the output is a temporary directory of the test.
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	out, err := exec.CommandContext(t.Context(), binary, "version").Output() //nolint:gosec // G204: binary is the binary that the test has built.
	if err != nil {
		t.Fatalf("nyktus-sensor version: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "1.2.3" {
		t.Errorf("version = %q, want %q", got, "1.2.3")
	}
}
