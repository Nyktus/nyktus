# SPDX-FileCopyrightText: The Nyktus Authors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Image of the development environment. It builds the web console and the server
# from the working tree; it is not the release image.

FROM node:24-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json web/.npmrc ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS server
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist web/dist
RUN CGO_ENABLED=0 go build -trimpath -o /out/nyktus ./cmd/nyktus

FROM alpine:3.22
RUN adduser -D -u 10001 nyktus
COPY --from=server /out/nyktus /usr/local/bin/nyktus
USER nyktus
ENTRYPOINT ["nyktus"]
