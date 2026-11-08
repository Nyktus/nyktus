# SPDX-FileCopyrightText: The Nyktus Authors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Release image of the server. GoReleaser builds the binary once, with the web
# console embedded, puts it into the build context under the directory of its
# platform and builds this file for every platform. The archive of a release and
# this image therefore hold the same signed binary, and the version that the
# binary reports comes from the tag, which a build inside the image could not
# read because the context has no Git history.
#
# The base image has no shell, no package manager and a user without a home
# directory. It carries the root certificates that outgoing requests (alert
# channels, mail, the identity provider) verify against.
#
# To build it by hand, put a binary at linux/amd64/nyktus in an otherwise empty
# directory next to a copy of this file and run "docker build" there.

FROM gcr.io/distroless/static:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329

ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/nyktus /usr/local/bin/nyktus
# The licenses of Nyktus and of the software in the binary require that their text
# accompanies a copy.
COPY LICENSE NOTICE THIRD-PARTY-NOTICES.md /licenses/

# The numeric user of "nonroot" in the base image, so that an orchestrator can
# check that the user is not root without reading /etc/passwd.
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/nyktus"]
