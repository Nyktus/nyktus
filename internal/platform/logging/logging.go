// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package logging creates the structured logger and carries request-scoped log
// attributes in contexts.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sync"
)

type attrsKey struct{}

type scopeKey struct{}

// scope holds attributes that become known after a context has been passed on,
// such as the principal that the authorizer determines inside the router.
type scope struct {
	mu    sync.Mutex
	attrs []slog.Attr
}

// WithScope returns a copy of ctx with an empty scope. Attributes added to the
// scope with AddToScope appear in every later log record written with ctx or a
// context derived from it, including records of middleware that received ctx
// before the attributes were known, such as the access log.
func WithScope(ctx context.Context) context.Context {
	return context.WithValue(ctx, scopeKey{}, &scope{})
}

// AddToScope adds attrs to the scope of ctx. Without a scope, it does nothing.
func AddToScope(ctx context.Context, attrs ...slog.Attr) {
	s, ok := ctx.Value(scopeKey{}).(*scope)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attrs = append(s.attrs, attrs...)
}

func scopeAttrs(ctx context.Context) []slog.Attr {
	s, ok := ctx.Value(scopeKey{}).(*scope)
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.attrs)
}

// WithAttrs returns a copy of ctx whose log records carry attrs in addition to the
// attributes already attached to ctx.
func WithAttrs(ctx context.Context, attrs ...slog.Attr) context.Context {
	existing, _ := ctx.Value(attrsKey{}).([]slog.Attr)
	merged := make([]slog.Attr, 0, len(existing)+len(attrs))
	merged = append(merged, existing...)
	merged = append(merged, attrs...)
	return context.WithValue(ctx, attrsKey{}, merged)
}

// New returns a logger that writes JSON records at or above level to w. Records
// written through the Context variants of the logging methods include the
// attributes attached to the context with WithAttrs.
func New(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(contextHandler{slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})})
}

// ParseLevel parses a level name such as "debug", "info", "warn" or "error".
func ParseLevel(s string) (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(s)); err != nil {
		return 0, fmt.Errorf("parse log level %q: %w", s, err)
	}
	return level, nil
}

// contextHandler adds the context and scope attributes to every record. A logger derived with
// WithGroup nests these attributes in its group as well, so request-scoped loggers
// should not be grouped.
type contextHandler struct {
	slog.Handler
}

func (h contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if attrs, ok := ctx.Value(attrsKey{}).([]slog.Attr); ok {
		r.AddAttrs(attrs...)
	}
	r.AddAttrs(scopeAttrs(ctx)...)
	return h.Handler.Handle(ctx, r)
}

func (h contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return contextHandler{h.Handler.WithAttrs(attrs)}
}

func (h contextHandler) WithGroup(name string) slog.Handler {
	return contextHandler{h.Handler.WithGroup(name)}
}
