// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package attack holds the techniques of a pinned version of MITRE ATT&CK
// Enterprise, which describe attacker behavior.
//
// The list is generated from the STIX bundle of MITRE by tools/attackgen and
// embedded at build time, so that nothing is loaded at runtime. It contains
// techniques and sub-techniques that are neither revoked nor deprecated.
//
// ATT&CK is a registered trademark of The MITRE Corporation. The list is
// reproduced and distributed with the permission of The MITRE Corporation; see
// the file NOTICE.
package attack

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
)

// Technique is a technique or sub-technique of ATT&CK.
type Technique struct {
	// ID identifies the technique, such as T1003, or the sub-technique, such as
	// T1003.001.
	ID string `json:"id"`
	// Name is the name as ATT&CK shows it, with the name of the parent before
	// that of a sub-technique, such as "OS Credential Dumping: LSASS Memory".
	Name string `json:"name"`
	// Tactics name the tactics of the technique, in the order of the matrix.
	Tactics []string `json:"tactics"`
}

//go:embed techniques.json
var data []byte

type list struct {
	Version    string      `json:"version"`
	Techniques []Technique `json:"techniques"`
}

// The list is parsed once when the program starts. Tests check the embedded
// data, so a failure here is a build mistake. version is the version of ATT&CK
// Enterprise that the list comes from, such as "20.0".
var version, techniques = mustLoad(data)

func mustLoad(b []byte) (string, map[string]Technique) {
	var l list
	if err := json.Unmarshal(b, &l); err != nil {
		panic(fmt.Sprintf("attack: parse embedded techniques: %v", err))
	}
	m := make(map[string]Technique, len(l.Techniques))
	for _, t := range l.Techniques {
		m[t.ID] = t
	}
	return l.Version, m
}

// Lookup returns the technique id. It reports false for an identifier that the
// pinned version does not contain, or that it revoked or deprecated.
func Lookup(id string) (Technique, bool) {
	t, ok := techniques[id]
	t.Tactics = slices.Clone(t.Tactics)
	return t, ok
}

// Version returns the version of ATT&CK Enterprise that the list comes from,
// such as "20.0".
func Version() string {
	return version
}
