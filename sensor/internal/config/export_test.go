// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import "errors"

// Parse decodes and validates a configuration without reading a file, so that
// tests can name every case in a literal. The secrets that name a file stay
// unresolved; Load reads them.
func Parse(data []byte) (*Config, error) {
	cfg, err := decode(data)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(cfg.validate(), cfg.checkDistinctSecrets()); err != nil {
		return nil, err
	}
	return cfg, nil
}
