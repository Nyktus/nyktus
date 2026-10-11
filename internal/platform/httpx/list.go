// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Cursor marks the position after the last item of a page in a list that is
// ordered by a time and an identifier.
type Cursor struct {
	Time time.Time
	ID   string
}

// ListQuery is the query of a request for a page of a list.
type ListQuery struct {
	// Limit is the page size, between 1 and the maximum of the list.
	Limit int
	// After is the cursor of the previous page, or nil for the first page.
	After *Cursor
}

var (
	limitFormat = regexp.MustCompile(`^[1-9][0-9]{0,8}$`)
	uuidFormat  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

var errInvalidCursor = errors.New("cursor is invalid; use the next_cursor of a previous response")

// DecodeListQuery reads the parameters limit and cursor of a list request. A
// missing limit is defaultLimit; a limit outside [1, maxLimit] is rejected.
// Unknown and repeated parameters are rejected, as unknown fields of a request
// body are, and so is a query that cannot be parsed, which url.URL.Query would
// silently drop. On failure it writes the error response and returns false; the
// handler must then return.
func DecodeListQuery(w http.ResponseWriter, r *http.Request, defaultLimit, maxLimit int) (ListQuery, bool) {
	q, err := parseListQuery(r.URL.RawQuery, defaultLimit, maxLimit)
	if err != nil {
		WriteError(w, r, http.StatusBadRequest, CodeInvalidRequest, err.Error())
		return ListQuery{}, false
	}
	return q, true
}

func parseListQuery(raw string, defaultLimit, maxLimit int) (ListQuery, error) {
	query, err := url.ParseQuery(raw)
	if err != nil {
		return ListQuery{}, errors.New("query string is invalid")
	}
	// The messages do not repeat the parameter names, which the client chose.
	for name, values := range query {
		if name != "limit" && name != "cursor" {
			return ListQuery{}, errors.New("unknown query parameter; use limit and cursor")
		}
		if len(values) != 1 {
			return ListQuery{}, errors.New("query parameters must be given once")
		}
	}

	q := ListQuery{Limit: defaultLimit}
	if s, ok := query["limit"]; ok {
		// One spelling per number: no sign and no leading zeros, which
		// strconv.Atoi would accept.
		n, err := strconv.Atoi(s[0])
		if !limitFormat.MatchString(s[0]) || err != nil || n > maxLimit {
			return ListQuery{}, errors.New("limit must be a number from 1 to " + strconv.Itoa(maxLimit))
		}
		q.Limit = n
	}
	if s, ok := query["cursor"]; ok {
		c, err := decodeCursor(s[0])
		if err != nil {
			return ListQuery{}, err
		}
		q.After = &c
	}
	return q, nil
}

// EncodeCursor returns c in the form that DecodeListQuery accepts. A cursor is
// opaque to clients.
func EncodeCursor(c Cursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(c.Time.UTC().Format(time.RFC3339Nano) + "|" + c.ID))
}

func decodeCursor(s string) (Cursor, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return Cursor{}, errInvalidCursor
	}
	at, id, ok := strings.Cut(string(raw), "|")
	if !ok || !uuidFormat.MatchString(id) {
		return Cursor{}, errInvalidCursor
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return Cursor{}, errInvalidCursor
	}
	return Cursor{Time: t, ID: id}, nil
}
