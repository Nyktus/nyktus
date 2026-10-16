// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command engagegen writes the list of MITRE Engage activities that Nyktus
// embeds, from the data of a pinned version of MITRE Engage.
//
// The data files are downloaded from the repository of MITRE, or read from a
// directory with -in, and verified against pinned SHA-256 digests, so that the
// list can be regenerated and reviewed exactly. Nyktus itself never loads
// Engage data at runtime. To move to a newer version, change the constants
// below and run
//
//	go run ./tools/engagegen
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// The pinned release of MITRE Engage. Its data carries no version of its own,
// so the tag in the URL names it and the digests hold its content.
const (
	version = "1.0"
	dataURL = "https://raw.githubusercontent.com/mitre/engage/v" + version + "/Data/json/"
)

// The data files that the list is made of, with their pinned digests.
const (
	activitiesFile = "activities.json"
	approachesFile = "approaches.json"
	mappingsFile   = "approach_activity_mappings.json"
)

var digests = map[string]string{
	activitiesFile: "19c8788bdd8615a0d5dddf8046c902c00b453c1b0247e35c9ca610a99ad98e07",
	approachesFile: "da2e09ad8c93f4aa463afaa9c5b1ef27eae91b444b580c4af432ae4ba05dadb7",
	mappingsFile:   "604f9e9e38431ec83a0fdcaa0c7d2f88c4b5d20a4f2ff4c94e497a78c6ccbe06",
}

// maxFileBytes bounds each download. The largest file of version 1.0 has 38 KB.
const maxFileBytes = 4 << 20

func main() {
	in := flag.String("in", "", "read the data files from this directory instead of downloading them")
	out := flag.String("out", "internal/engage/activities.json", "write the list of activities to this file")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, *in, *out)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "engagegen:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, in, out string) error {
	files := map[string][]byte{}
	for _, name := range []string{activitiesFile, approachesFile, mappingsFile} {
		var (
			b   []byte
			err error
		)
		if in != "" {
			b, err = os.ReadFile(filepath.Join(in, name)) //nolint:gosec // The developer who runs the tool names the directory.
		} else {
			b, err = download(ctx, dataURL+name)
		}
		if err != nil {
			return err
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != digests[name] {
			return fmt.Errorf("%s has the SHA-256 digest %x, want %s", name, sum, digests[name])
		}
		files[name] = b
	}
	list, err := generate(files[activitiesFile], files[approachesFile], files[mappingsFile], version)
	if err != nil {
		return err
	}
	return os.WriteFile(out, list, 0o644) //nolint:gosec // A source file of the repository, readable by everyone.
}

func download(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	if len(b) > maxFileBytes {
		return nil, fmt.Errorf("download %s: larger than expected", url)
	}
	return b, nil
}

// The parts of the data files that the list needs.
type (
	engageItem struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	engageMapping struct {
		ApproachID string `json:"approach_id"`
		ActivityID string `json:"activity_id"`
	}
)

// activity is an entry of the generated list.
type activity struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Approaches []string `json:"approaches"`
}

// Engage has engagement activities (EAC), which act on an adversary, and
// strategic activities (SAC), which plan and review an operation. Deceptions
// and scenarios are engagement activities; the strategic ones describe the
// work of a team around them, so they are left out.
var (
	activityID = regexp.MustCompile(`^EAC[0-9]{4}$`)
	approachID = regexp.MustCompile(`^EAP[0-9]{4}$`)
	strategic  = regexp.MustCompile(`^SA[CP][0-9]{4}$`)
)

// generate returns the list of the engagement activities, ordered by
// identifier, each with the names of its approaches in the order of their
// identifiers, as JSON with one activity per line, so that a new version shows
// as a readable diff.
func generate(activitiesJSON, approachesJSON, mappingsJSON []byte, version string) ([]byte, error) {
	var (
		activities []engageItem
		approaches []engageItem
		mappings   []engageMapping
	)
	for _, f := range []struct {
		name string
		data []byte
		into any
	}{
		{activitiesFile, activitiesJSON, &activities},
		{approachesFile, approachesJSON, &approaches},
		{mappingsFile, mappingsJSON, &mappings},
	} {
		if err := json.Unmarshal(f.data, f.into); err != nil {
			return nil, fmt.Errorf("parse %s: %w", f.name, err)
		}
	}

	names := map[string]string{}
	for _, a := range approaches {
		switch {
		case strategic.MatchString(a.ID):
			continue
		case !approachID.MatchString(a.ID):
			return nil, fmt.Errorf("approach %q has a malformed identifier", a.ID)
		}
		if _, ok := names[a.ID]; ok {
			return nil, fmt.Errorf("approach %s appears twice", a.ID)
		}
		if name := strings.TrimSpace(a.Name); name == "" || name != a.Name {
			return nil, fmt.Errorf("approach %s has no clean name", a.ID)
		}
		names[a.ID] = a.Name
	}

	byActivity := map[string][]string{}
	for _, m := range mappings {
		if strategic.MatchString(m.ApproachID) || strategic.MatchString(m.ActivityID) {
			continue
		}
		if _, ok := names[m.ApproachID]; !ok {
			return nil, fmt.Errorf("activity %s maps to the unknown approach %s", m.ActivityID, m.ApproachID)
		}
		if slices.Contains(byActivity[m.ActivityID], m.ApproachID) {
			return nil, fmt.Errorf("activity %s maps to approach %s twice", m.ActivityID, m.ApproachID)
		}
		byActivity[m.ActivityID] = append(byActivity[m.ActivityID], m.ApproachID)
	}

	list := make([]activity, 0, len(activities))
	seen := map[string]bool{}
	for _, a := range activities {
		switch {
		case strategic.MatchString(a.ID):
			continue
		case !activityID.MatchString(a.ID):
			return nil, fmt.Errorf("activity %q has a malformed identifier", a.ID)
		case seen[a.ID]:
			return nil, fmt.Errorf("activity %s appears twice", a.ID)
		}
		seen[a.ID] = true
		if name := strings.TrimSpace(a.Name); name == "" || name != a.Name {
			return nil, fmt.Errorf("activity %s has no clean name", a.ID)
		}
		ids := byActivity[a.ID]
		if len(ids) == 0 {
			return nil, fmt.Errorf("activity %s has no approach", a.ID)
		}
		slices.Sort(ids)
		e := activity{ID: a.ID, Name: a.Name}
		for _, id := range ids {
			e.Approaches = append(e.Approaches, names[id])
		}
		list = append(list, e)
	}
	for id := range byActivity {
		if !seen[id] {
			return nil, fmt.Errorf("a mapping names the unknown activity %s", id)
		}
	}
	if len(list) == 0 {
		return nil, errors.New("the data has no engagement activities")
	}
	slices.SortFunc(list, func(a, b activity) int { return strings.Compare(a.ID, b.ID) })
	return encode(version, list)
}

func encode(version string, list []activity) ([]byte, error) {
	var buf bytes.Buffer
	v, err := json.Marshal(version)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(&buf, "{\n\"version\": %s,\n\"activities\": [\n", v)
	for i, a := range list {
		line, err := json.Marshal(a)
		if err != nil {
			return nil, err
		}
		buf.Write(line)
		if i < len(list)-1 {
			buf.WriteByte(',')
		}
		buf.WriteByte('\n')
	}
	buf.WriteString("]\n}\n")
	return buf.Bytes(), nil
}
