// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command attackgen writes the list of MITRE ATT&CK techniques that Nyktus
// embeds, from the STIX bundle of a pinned version of ATT&CK Enterprise.
//
// The bundle is downloaded from the repository of MITRE, or read from a file
// with -in, and verified against a pinned SHA-256 digest, so that the list can
// be regenerated and reviewed exactly. Nyktus itself never loads ATT&CK data at
// runtime. To move to a newer version, change the constants below and run
//
//	go run ./tools/attackgen
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
	"regexp"
	"slices"
	"strings"
	"time"
)

// The pinned release of ATT&CK Enterprise.
const (
	version   = "19.2"
	bundleURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v" + version +
		"/enterprise-attack/enterprise-attack-" + version + ".json"
	bundleSHA256 = "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"
)

// maxBundleBytes bounds the download. The bundle of version 19.2 has 54 MB.
const maxBundleBytes = 256 << 20

func main() {
	in := flag.String("in", "", "read the STIX bundle from this file instead of downloading it")
	out := flag.String("out", "internal/attack/techniques.json", "write the list of techniques to this file")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, *in, *out)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "attackgen:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, in, out string) error {
	var (
		bundle []byte
		err    error
	)
	if in != "" {
		bundle, err = os.ReadFile(in) //nolint:gosec // The developer who runs the tool names the file.
	} else {
		bundle, err = download(ctx)
	}
	if err != nil {
		return err
	}
	if sum := sha256.Sum256(bundle); hex.EncodeToString(sum[:]) != bundleSHA256 {
		return fmt.Errorf("the bundle has the SHA-256 digest %x, want %s", sum, bundleSHA256)
	}
	list, err := generate(bundle, version)
	if err != nil {
		return err
	}
	return os.WriteFile(out, list, 0o644) //nolint:gosec // A source file of the repository, readable by everyone.
}

func download(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bundleURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download bundle: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download bundle: %s", resp.Status)
	}
	bundle, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("download bundle: %w", err)
	}
	if len(bundle) > maxBundleBytes {
		return nil, errors.New("download bundle: larger than expected")
	}
	return bundle, nil
}

// The parts of the STIX objects that the list needs.
type (
	stixBundle struct {
		Objects []stixObject `json:"objects"`
	}
	stixObject struct {
		Type               string               `json:"type"`
		ID                 string               `json:"id"`
		Name               string               `json:"name"`
		Revoked            bool                 `json:"revoked"`
		Deprecated         bool                 `json:"x_mitre_deprecated"`
		IsSubtechnique     bool                 `json:"x_mitre_is_subtechnique"`
		Version            string               `json:"x_mitre_version"`
		Shortname          string               `json:"x_mitre_shortname"`
		TacticRefs         []string             `json:"tactic_refs"`
		ExternalReferences []stixReference      `json:"external_references"`
		KillChainPhases    []stixKillChainPhase `json:"kill_chain_phases"`
	}
	stixReference struct {
		SourceName string `json:"source_name"`
		ExternalID string `json:"external_id"`
	}
	stixKillChainPhase struct {
		KillChainName string `json:"kill_chain_name"`
		PhaseName     string `json:"phase_name"`
	}
)

// technique is an entry of the generated list.
type technique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics"`
}

var techniqueID = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)

// generate returns the list of the techniques of bundle that are neither
// revoked nor deprecated, ordered by identifier, as JSON with one technique per
// line, so that a new version shows as a readable diff. A sub-technique is named
// after its parent, as ATT&CK shows it, such as "OS Credential Dumping: LSASS
// Memory". Tactics are named and ordered as in the matrix.
func generate(bundle []byte, wantVersion string) ([]byte, error) {
	var b stixBundle
	if err := json.Unmarshal(bundle, &b); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}

	var (
		collectionVersion string
		matrix            *stixObject
		tactics           = map[string]stixObject{}
		active            = map[string]stixObject{}
	)
	for i, o := range b.Objects {
		switch o.Type {
		case "x-mitre-collection":
			collectionVersion = o.Version
		case "x-mitre-matrix":
			if matrix != nil {
				return nil, errors.New("the bundle has more than one matrix")
			}
			matrix = &b.Objects[i]
		case "x-mitre-tactic":
			tactics[o.ID] = o
		case "attack-pattern":
			if o.Revoked || o.Deprecated {
				continue
			}
			id, err := attackID(o)
			if err != nil {
				return nil, err
			}
			if _, ok := active[id]; ok {
				return nil, fmt.Errorf("technique %s appears twice", id)
			}
			active[id] = o
		}
	}
	if collectionVersion != wantVersion {
		return nil, fmt.Errorf("the bundle is ATT&CK %q, want %q", collectionVersion, wantVersion)
	}
	if matrix == nil {
		return nil, errors.New("the bundle has no matrix")
	}

	// Tactics by their short name, in the order of the matrix.
	order := map[string]int{}
	names := map[string]string{}
	for i, ref := range matrix.TacticRefs {
		t, ok := tactics[ref]
		if !ok {
			return nil, fmt.Errorf("the matrix names the unknown tactic %s", ref)
		}
		order[t.Shortname] = i
		names[t.Shortname] = t.Name
	}

	list := make([]technique, 0, len(active))
	for id, o := range active {
		parentID, _, sub := strings.Cut(id, ".")
		if sub != o.IsSubtechnique {
			return nil, fmt.Errorf("technique %s: the identifier and x_mitre_is_subtechnique disagree", id)
		}
		name := strings.TrimSpace(o.Name)
		if sub {
			parent, ok := active[parentID]
			if !ok {
				return nil, fmt.Errorf("sub-technique %s: no active parent %s", id, parentID)
			}
			name = strings.TrimSpace(parent.Name) + ": " + name
		}
		var shortnames []string
		for _, p := range o.KillChainPhases {
			if p.KillChainName != "mitre-attack" {
				continue
			}
			if _, ok := names[p.PhaseName]; !ok {
				return nil, fmt.Errorf("technique %s: unknown tactic %s", id, p.PhaseName)
			}
			if !slices.Contains(shortnames, p.PhaseName) {
				shortnames = append(shortnames, p.PhaseName)
			}
		}
		if name == "" || len(shortnames) == 0 {
			return nil, fmt.Errorf("technique %s has no name or no tactic", id)
		}
		slices.SortFunc(shortnames, func(a, b string) int { return order[a] - order[b] })
		t := technique{ID: id, Name: name}
		for _, s := range shortnames {
			t.Tactics = append(t.Tactics, names[s])
		}
		list = append(list, t)
	}
	if len(list) == 0 {
		return nil, errors.New("the bundle has no techniques")
	}
	slices.SortFunc(list, func(a, b technique) int { return strings.Compare(a.ID, b.ID) })
	return encode(wantVersion, list)
}

// attackID returns the ATT&CK identifier of a technique, such as T1003.001.
func attackID(o stixObject) (string, error) {
	var ids []string
	for _, r := range o.ExternalReferences {
		if r.SourceName == "mitre-attack" {
			ids = append(ids, r.ExternalID)
		}
	}
	if len(ids) != 1 || !techniqueID.MatchString(ids[0]) {
		return "", fmt.Errorf("%s has no single ATT&CK identifier: %q", o.ID, ids)
	}
	return ids[0], nil
}

func encode(version string, list []technique) ([]byte, error) {
	var buf bytes.Buffer
	v, err := json.Marshal(version)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(&buf, "{\n\"version\": %s,\n\"techniques\": [\n", v)
	for i, t := range list {
		line, err := json.Marshal(t)
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
