// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// The pages are loaded when the router first needs them. Loading them all once before
// the tests keeps the first test from racing the transform of their shared components;
// a page that is added later is included without a list to keep.
import.meta.glob('../views/*.vue', { eager: true });
