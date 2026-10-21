// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package passwordtest provides a password hasher for tests.
package passwordtest

import "nyktus.org/nyktus/internal/auth/password"

// NewHasher returns a Hasher with the cheapest parameters worth the name. A hash
// costs about a millisecond, also under the race detector, where the default
// parameters cost almost half a second, so that tests which create accounts and
// sign in need not wait for Argon2. It differs from the default parameters and
// from the outdated ones that tests write on purpose, so rehashing is observable.
// Tests of the parameters themselves use password.NewHasher.
func NewHasher() *password.Hasher {
	return password.NewHasherWithCost(256, 1, 1)
}
