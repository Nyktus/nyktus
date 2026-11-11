// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
)

// Limits of a request, within those of the connection. A real request of an MCP
// client takes well under a KiB of headers and a few KiB of body.
const (
	maxHeaderBytes = 4 << 10
	maxHeaderLines = 32
	maxBodyBytes   = 8 << 10
)

// dateFormat is the form of the date of an HTTP response (RFC 9110, section
// 5.6.7).
const dateFormat = "Mon, 02 Jan 2006 15:04:05 GMT"

// refusal ends a connection with a status: what came is not an HTTP request that
// this server reads.
type refusal int

func (refusal) Error() string { return "mcp: request refused" }

// HTTP status codes of the answers.
const (
	statusOK                 = 200
	statusAccepted           = 202
	statusBadRequest         = 400
	statusForbidden          = 403
	statusNotFound           = 404
	statusMethodNotAllowed   = 405
	statusLengthRequired     = 411
	statusTooLarge           = 413
	statusHeadersTooLarge    = 431
	statusVersionUnsupported = 505
)

var reasons = map[int]string{
	statusOK:                 "OK",
	statusAccepted:           "Accepted",
	statusBadRequest:         "Bad Request",
	statusForbidden:          "Forbidden",
	statusNotFound:           "Not Found",
	statusMethodNotAllowed:   "Method Not Allowed",
	statusLengthRequired:     "Length Required",
	statusTooLarge:           "Content Too Large",
	statusHeadersTooLarge:    "Request Header Fields Too Large",
	statusVersionUnsupported: "HTTP Version Not Supported",
}

// single names the headers that a request may carry only once because the
// server compares their value with the body or needs it to be one. Joined, a
// second value would match what one reader sees and not what another does. The
// others that decide something need no entry: a joined Content-Length is no
// number, and any value of Transfer-Encoding or Origin ends the request.
var single = map[string]bool{
	"host": true, "mcp-protocol-version": true, "mcp-method": true, "mcp-name": true,
}

// request is one HTTP request. The names of the headers are in lower case.
type request struct {
	method string
	// path is the target without its query.
	path   string
	header map[string]string
	body   []byte
}

// readRequest reads one request. It returns a refusal for one that this server
// does not read and any other error for a client that has gone. net/http is not
// used: it opens connections of its own, reads without the limits above and
// answers some requests itself, in words that identify it.
func readRequest(r *bufio.Reader, w io.Writer) (*request, error) {
	budget := maxHeaderBytes
	line, err := readLine(r, &budget)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(line, " ")
	if len(parts) != 3 || !isToken(parts[0]) || !strings.HasPrefix(parts[2], "HTTP/") {
		return nil, refusal(statusBadRequest)
	}
	if parts[2] != "HTTP/1.1" {
		return nil, refusal(statusVersionUnsupported)
	}
	path, _, _ := strings.Cut(parts[1], "?")
	req := &request{method: parts[0], path: path, header: map[string]string{}}
	for range maxHeaderLines + 1 {
		line, err := readLine(r, &budget)
		if err != nil {
			return nil, err
		}
		if line == "" {
			if err := readBody(r, w, req); err != nil {
				return nil, err
			}
			// HTTP/1.1 requires the header, and every server that a client meets
			// refuses a request without it.
			if _, ok := req.header["host"]; !ok {
				return nil, refusal(statusBadRequest)
			}
			return req, nil
		}
		name, value, ok := strings.Cut(line, ":")
		// The name is checked as it was written: lower-casing first would turn
		// characters that are no token, such as the Kelvin sign, into letters.
		if !ok || !isToken(name) {
			return nil, refusal(statusBadRequest)
		}
		name = strings.ToLower(name)
		value = strings.Trim(value, " \t")
		if before, repeated := req.header[name]; repeated {
			// Clients repeat a header such as Accept, which means the same as one
			// line with the values joined (RFC 9110, section 5.3). What decides
			// the framing, the origin or the revision must not be said twice.
			if single[name] {
				return nil, refusal(statusBadRequest)
			}
			value = before + ", " + value
		}
		req.header[name] = value
	}
	return nil, refusal(statusHeadersTooLarge)
}

// readLine reads a line within the bytes that are left for the headers. A cut at
// the end of the input is a client that has gone.
func readLine(r *bufio.Reader, budget *int) (string, error) {
	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", refusal(statusHeadersTooLarge)
	}
	if err != nil {
		return "", err
	}
	if *budget -= len(line); *budget < 0 {
		return "", refusal(statusHeadersTooLarge)
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r"), nil
}

// readBody reads the body. Only a length that was announced is read: a client
// that sends another framing is refused, so that no bytes of one request are
// taken for the next.
func readBody(r *bufio.Reader, w io.Writer, req *request) error {
	if _, chunked := req.header["transfer-encoding"]; chunked {
		return refusal(statusLengthRequired)
	}
	text, ok := req.header["content-length"]
	if !ok {
		if req.method == "POST" {
			return refusal(statusLengthRequired)
		}
		return nil
	}
	if len(text) > 6 || strings.Trim(text, "0123456789") != "" {
		return refusal(statusBadRequest)
	}
	n, err := strconv.Atoi(text)
	if err != nil {
		return refusal(statusBadRequest)
	}
	if n > maxBodyBytes {
		return refusal(statusTooLarge)
	}
	if strings.EqualFold(req.header["expect"], "100-continue") && n > 0 {
		if _, err := io.WriteString(w, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
			return err
		}
	}
	req.body = make([]byte, n)
	_, err = io.ReadFull(r, req.body)
	return err
}

// hasToken reports whether the comma-separated list value holds token, which
// HTTP compares without regard to case.
func hasToken(value, token string) bool {
	for part := range strings.SplitSeq(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

// isToken reports whether s is an HTTP token (RFC 9110, section 5.6.2).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// reply is one HTTP response.
type reply struct {
	status int
	// allow is the value of the header Allow of a refused method.
	allow string
	body  []byte
}

// encode returns the response as it is sent at the time now. A server with a
// clock sends the date, and its absence would stand out.
func (r reply) encode(now time.Time, closing bool) []byte {
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + strconv.Itoa(r.status) + " " + reasons[r.status] + "\r\n")
	b.WriteString("Date: " + now.UTC().Format(dateFormat) + "\r\n")
	if r.allow != "" {
		b.WriteString("Allow: " + r.allow + "\r\n")
	}
	if len(r.body) > 0 {
		b.WriteString("Content-Type: application/json\r\n")
	}
	b.WriteString("Content-Length: " + strconv.Itoa(len(r.body)) + "\r\n")
	if closing {
		b.WriteString("Connection: close\r\n")
	}
	b.WriteString("\r\n")
	b.Write(r.body)
	return []byte(b.String())
}
