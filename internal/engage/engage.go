// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package engage holds the engagement activities of a pinned version of MITRE
// Engage, which describe what a defender does to an adversary. Deceptions and
// scenarios name the activities they carry out.
//
// The list is generated from the data of MITRE by tools/engagegen and embedded
// at build time, so that nothing is loaded at runtime. It contains the
// engagement activities, not the strategic ones, which plan and review an
// operation instead of acting on an adversary.
//
// MITRE Engage is a trademark of The MITRE Corporation. The data is licensed
// under the Apache License 2.0; see the file NOTICE.
package engage

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
)

// Activity is an engagement activity of Engage.
type Activity struct {
	// ID identifies the activity, such as EAC0005.
	ID string `json:"id"`
	// Name is the name as Engage shows it, such as "Lures".
	Name string `json:"name"`
	// Approaches name the approaches that the activity belongs to, such as
	// "Detect", in the order of the matrix.
	Approaches []string `json:"approaches"`
}

//go:embed activities.json
var data []byte

type list struct {
	Version    string     `json:"version"`
	Activities []Activity `json:"activities"`
}

// The list is parsed once when the program starts. Tests check the embedded
// data, so a failure here is a build mistake. version is the version of Engage
// that the list comes from, such as "1.0". all keeps the order of the list,
// which the tests hold ascending by identifier.
var version, activities, all = mustLoad(data)

func mustLoad(b []byte) (string, map[string]Activity, []Activity) {
	var l list
	if err := json.Unmarshal(b, &l); err != nil {
		panic(fmt.Sprintf("engage: parse embedded activities: %v", err))
	}
	m := make(map[string]Activity, len(l.Activities))
	for _, a := range l.Activities {
		m[a.ID] = a
	}
	return l.Version, m, l.Activities
}

// Lookup returns the activity id. It reports false for an identifier that the
// pinned version does not contain, and for strategic activities.
func Lookup(id string) (Activity, bool) {
	a, ok := activities[id]
	a.Approaches = slices.Clone(a.Approaches)
	return a, ok
}

// All returns the activities ordered by identifier. The caller may change the
// result.
func All() []Activity {
	out := make([]Activity, len(all))
	for i, a := range all {
		a.Approaches = slices.Clone(a.Approaches)
		out[i] = a
	}
	return out
}

// Version returns the version of Engage that the list comes from, such as
// "1.0".
func Version() string {
	return version
}
