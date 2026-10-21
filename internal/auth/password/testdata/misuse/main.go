// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command misuse builds a weak password hasher outside of a test binary. The test
// of package password runs it and expects it to be refused.
package main

import "nyktus.org/nyktus/internal/auth/password"

func main() {
	password.NewHasherWithCost(256, 1, 1)
}
