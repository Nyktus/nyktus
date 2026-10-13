// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dns

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limits of queries over UDP per source network. The source address of a UDP
// query can be forged, so an unlimited name server would answer a flood
// towards whoever owns the forged address. Resolvers of one provider share a
// network, so the limit is generous: queries for the names of a few
// honeytokens never come close.
const (
	sourceRate  = rate.Limit(20)
	sourceBurst = 50
	// Networks of the limit: the /24 of an IPv4 address and the /56 of an IPv6
	// address, the smallest networks that providers commonly assign.
	sourceBitsIPv4 = 24
	sourceBitsIPv6 = 56
	// maxSources bounds the memory of the limit. A flood from forged random
	// sources fills it; the queries of sources that find no room are treated
	// as over their limit together, so that a real client asks again over
	// TCP, which is not limited and cannot be forged.
	maxSources = 65536
	// sourceIdle is how long a source is remembered after its last query.
	sourceIdle = 2 * time.Minute
)

// verdict says how to treat a query over UDP.
type verdict int

const (
	verdictAllow verdict = iota
	// verdictTruncate answers with an empty, truncated message, so that a real
	// client asks again over TCP.
	verdictTruncate
	// verdictDrop sends nothing.
	verdictDrop
)

// sourceLimiter limits the queries over UDP per source network. Every second
// query beyond the limit is answered truncated and every other one dropped,
// so that a real client still gets through over TCP while a forged flood
// receives at most half its size in small answers.
type sourceLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	sources map[netip.Prefix]*source
	// overflow counts the queries of sources that found the table full.
	overflow int
}

type source struct {
	limiter  *rate.Limiter
	lastSeen time.Time
	refused  int
}

func newSourceLimiter() *sourceLimiter {
	return &sourceLimiter{limit: sourceRate, sources: map[netip.Prefix]*source{}}
}

func (l *sourceLimiter) allow(addr netip.Addr, now time.Time) verdict {
	key := sourceNetwork(addr)
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.sources[key]
	if !ok {
		if len(l.sources) >= maxSources {
			l.overflow++
			return slip(l.overflow)
		}
		s = &source{limiter: rate.NewLimiter(l.limit, sourceBurst)}
		l.sources[key] = s
	}
	s.lastSeen = now
	if s.limiter.AllowN(now, 1) {
		return verdictAllow
	}
	s.refused++
	return slip(s.refused)
}

// slip answers every second refused query truncated and drops the others.
func slip(refused int) verdict {
	if refused%2 == 1 {
		return verdictTruncate
	}
	return verdictDrop
}

// forget removes the sources that have been idle for sourceIdle. A source that
// returns starts with a full bucket, as it would after that time anyway.
func (l *sourceLimiter) forget(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, s := range l.sources {
		if now.Sub(s.lastSeen) > sourceIdle {
			delete(l.sources, key)
		}
	}
}

func sourceNetwork(addr netip.Addr) netip.Prefix {
	bits := sourceBitsIPv6
	if addr.Is4() {
		bits = sourceBitsIPv4
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		// The zero Addr: queries without a known source share one bucket.
		return netip.Prefix{}
	}
	return p
}
