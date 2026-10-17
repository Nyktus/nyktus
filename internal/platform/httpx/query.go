// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package httpx

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// DecodeQuery reads the query parameters names of a request, each at most
// once, and returns their values by name. Unknown and repeated parameters are
// rejected, as unknown fields of a request body are, and so is a query that
// cannot be parsed, which url.URL.Query would silently drop. The handler
// validates the values. On failure it writes the error response and returns
// false; the handler must then return.
func DecodeQuery(w http.ResponseWriter, r *http.Request, names ...string) (map[string]string, bool) {
	values, err := parseQuery(r.URL.RawQuery, names)
	if err != nil {
		WriteError(w, r, http.StatusBadRequest, CodeInvalidRequest, err.Error())
		return nil, false
	}
	return values, true
}

func parseQuery(raw string, names []string) (map[string]string, error) {
	query, err := url.ParseQuery(raw)
	if err != nil {
		return nil, errors.New("query string is invalid")
	}
	values := make(map[string]string, len(query))
	// The messages do not repeat the parameter names, which the client chose.
	for name, v := range query {
		if !slices.Contains(names, name) {
			return nil, errors.New(unknownParameter(names))
		}
		if len(v) != 1 {
			return nil, errors.New("query parameters must be given once")
		}
		values[name] = v[0]
	}
	return values, nil
}

// unknownParameter names the parameters that a request accepts.
func unknownParameter(names []string) string {
	switch len(names) {
	case 0:
		return "unknown query parameter; this request accepts none"
	case 1:
		return "unknown query parameter; use " + names[0]
	default:
		return "unknown query parameter; use " + strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
}
