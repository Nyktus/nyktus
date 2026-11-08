#!/bin/sh
# SPDX-FileCopyrightText: The Nyktus Authors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Attaches a signed SBOM to every platform of a pushed image.
#
#   attest-sbom.sh ghcr.io/nyktus/nyktus@sha256:<digest of the image index>
#
# GoReleaser runs it after the push, as an entry of docker_signs. For each image of
# the index, syft reads the SBOM from the registry, and cosign signs it as an
# attestation for the digest of that image and stores it next to the image. The
# signature is keyless, with the identity of the workflow, like the signature of
# the image. The versions of both tools come from the environment, where the
# Makefile pins them.

set -eu

index=$1
repository=${index%@*}

: "${SYFT_VERSION:?}" "${COSIGN_VERSION:?}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The platforms of the index. The attestations that the build adds to the index
# have the platform "unknown" and are left out.
digests=$(docker buildx imagetools inspect "$index" --raw |
	jq -r '.manifests[] | select(.platform.os == "linux") | .digest')
[ -n "$digests" ] || { echo "attest-sbom: no image in $index" >&2; exit 1; }

for digest in $digests; do
	image="$repository@$digest"
	go run "github.com/anchore/syft/cmd/syft@$SYFT_VERSION" scan "registry:$image" \
		--output "spdx-json=$work/sbom.spdx.json"
	go run "github.com/sigstore/cosign/v3/cmd/cosign@$COSIGN_VERSION" attest --yes \
		--type spdxjson --predicate "$work/sbom.spdx.json" "$image"
done
