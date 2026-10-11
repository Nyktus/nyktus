// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package apikey

// Format builds a key of the key id with secret, so that tests can present a
// well-formed key with a wrong secret.
var Format = format

// TouchInterval is how often a key records its use.
const TouchInterval = touchInterval
