// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// recordTimeout bounds the wait for the database. The answer has already
	// been written, so it only bounds how long a recording takes.
	recordTimeout = 2 * time.Second
	// maxRecordDelay is how long a query may wait to be recorded. The database
	// accepts no longer delay, so that a recording cannot move an event far
	// into the past; an older query is dropped and counted in the log.
	maxRecordDelay = 5 * time.Minute
	// maxQueued bounds the queries that wait to be recorded, so that a burst
	// is recorded in full while a flood cannot grow the memory without bound.
	// A query that finds the queue full is answered as always but not
	// recorded, and counted in the log.
	maxQueued = 1024
	// logInterval is how often the queries that were not recorded are logged.
	logInterval = time.Minute
)

// Sizes of answers in bytes. An answer over UDP is never larger than the
// buffer the client announced, at most ednsUDPSize, and never more than
// amplification times the query, so that the DNS role cannot amplify an
// attack with a forged source address. A larger answer is truncated, and the
// client asks again over TCP, which a forged source cannot complete.
const (
	minUDPSize    = 512
	ednsUDPSize   = 1232
	amplification = 3
)

// maxPrefixLength bounds the labels in front of a trigger value that are
// recorded, in bytes.
const maxPrefixLength = 200

// Timers of the SOA record. Common values, because the zone has no secondary
// servers that would use them.
const (
	soaRefresh = 7200
	soaRetry   = 3600
	soaExpire  = 1209600
)

// Options configure the DNS role.
type Options struct {
	Logger   *slog.Logger
	Recorder Recorder
	// Zones are the zones to answer, in lower case without a trailing dot.
	Zones []string
	// Nameservers are the name servers of the zones, outside of them, in lower
	// case without a trailing dot.
	Nameservers []string
	// AnswerIPv4 and AnswerIPv6 are the addresses with which every name
	// resolves, or the zero Addr for no address of that family.
	AnswerIPv4, AnswerIPv6 netip.Addr
	// TTL is the time to live of every record, in whole seconds.
	TTL time.Duration
	// Recorders is the number of queries recorded at a time, at most the
	// connections of the database pool.
	Recorders int
	// Serial is the serial number of the SOA records.
	Serial uint32
}

// Handler answers the queries of the DNS role.
type Handler struct {
	logger      *slog.Logger
	recorder    Recorder
	zones       []string
	nameservers []string
	ipv4, ipv6  netip.Addr
	ttl         uint32
	serial      uint32
	limiter     *sourceLimiter
	recorders   int
	now         func() time.Time

	// queue holds the queries to record. closed, under mu, keeps a handler
	// that outlives the shutdown of the servers from sending on the closed
	// queue.
	mu      sync.RWMutex
	queue   chan Query
	closed  bool
	limited counter
	dropped counter
}

// New returns the handler of the DNS role. Run must run alongside it, so that
// unrecorded queries are logged and the rate limits forget idle sources. The
// queries are recorded while Serve runs.
func New(o Options) *Handler {
	if o.Logger == nil || o.Recorder == nil || len(o.Zones) == 0 || len(o.Nameservers) == 0 || o.Recorders < 1 {
		panic("dns: missing logger, recorder, zones, name servers or recorders")
	}
	if o.TTL < 0 || o.TTL%time.Second != 0 || o.TTL > time.Hour {
		panic("dns: TTL must be whole seconds up to an hour")
	}
	h := &Handler{
		logger:    o.Logger,
		recorder:  o.Recorder,
		ipv4:      o.AnswerIPv4,
		ipv6:      o.AnswerIPv6,
		ttl:       uint32(o.TTL / time.Second),
		serial:    o.Serial,
		limiter:   newSourceLimiter(),
		recorders: o.Recorders,
		now:       time.Now,
		queue:     make(chan Query, maxQueued),
		limited:   counter{counts: map[string]int{}},
		dropped:   counter{counts: map[string]int{}},
	}
	for _, z := range o.Zones {
		h.zones = append(h.zones, dns.Fqdn(z))
	}
	// The longest zone wins, although the configuration rejects zones that
	// contain each other.
	slices.SortFunc(h.zones, func(a, b string) int { return len(b) - len(a) })
	for _, n := range o.Nameservers {
		h.nameservers = append(h.nameservers, dns.Fqdn(n))
	}
	return h
}

// Run logs the queries that were not recorded, at most once per interval, and
// lets the rate limits forget idle sources, until ctx is canceled.
func (h *Handler) Run(ctx context.Context) {
	ticker := time.NewTicker(logInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.flush(ctx)
			h.limiter.forget(time.Now())
		case <-ctx.Done():
			h.flush(context.WithoutCancel(ctx))
			return
		}
	}
}

// startRecording starts the goroutines that record the queued queries. Each
// recording runs with a deadline of its own, detached from the cancellation of
// ctx, so that the queue is recorded in full when the servers stop. The
// returned function must be called once ServeDNS is no longer called: it
// records what is still queued and waits for it.
func (h *Handler) startRecording(ctx context.Context) (stop func()) {
	ctx = context.WithoutCancel(ctx)
	var wg sync.WaitGroup
	for range h.recorders {
		wg.Go(func() {
			for q := range h.queue {
				h.record(ctx, q)
			}
		})
	}
	return func() {
		h.mu.Lock()
		h.closed = true
		close(h.queue)
		h.mu.Unlock()
		wg.Wait()
	}
}

func (h *Handler) flush(ctx context.Context) {
	for id, n := range h.limited.take() {
		h.logger.WarnContext(ctx, "dns: queries not recorded",
			slog.String("honeytoken_id", id), slog.Int("queries", n), slog.String("reason", "limit"))
	}
	for reason, n := range h.dropped.take() {
		h.logger.WarnContext(ctx, "dns: queries not recorded", slog.Int("queries", n), slog.String("reason", reason))
	}
}

// ServeDNS implements dns.Handler. The answer depends only on the form of the
// query and on the rate of its source, and is written before the query is
// recorded.
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	// The server of the DNS library does not recover panics, so one would end
	// the process. The query stays unanswered, as it would for every name.
	defer h.recoverPanic()

	transport, source := "udp", addrOf(w.RemoteAddr())
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		transport = "tcp"
	}
	if transport == "udp" {
		switch h.limiter.allow(source, time.Now()) {
		case verdictAllow:
		case verdictTruncate:
			// A client that really sent the query asks again over TCP.
			_ = w.WriteMsg(truncated(r))
			return
		default:
			return
		}
	}

	received := h.now()
	m, query, ok := h.answer(r)
	if transport == "udp" {
		limitSize(m, r)
	}
	if err := w.WriteMsg(m); err != nil {
		h.logger.Debug("dns: writing the answer failed", slog.Any("error", err))
	}
	if !ok {
		h.logger.Debug("dns: query", slog.String("rcode", dns.RcodeToString[m.Rcode]),
			slog.String("transport", transport), slog.String("resolver_ip", source.String()))
		return
	}
	query.Transport = transport
	query.Resolver = source
	query.ReceivedAt = received
	h.recordLater(query)
}

// recoverPanic must be deferred directly, because recover only stops a panic
// when it is called by the deferred function itself.
func (h *Handler) recoverPanic() {
	if v := recover(); v != nil {
		h.logger.Error("dns: handler panicked",
			slog.String("panic", fmt.Sprint(v)), slog.String("stack", string(debug.Stack())))
	}
}

// answer returns the answer to r and, if the name holds a trigger value under
// one of the zones, the query to record. The answer depends only on the form of
// the query: every name under a zone receives the same records, whether or not
// it holds a value.
func (h *Handler) answer(r *dns.Msg) (*dns.Msg, Query, bool) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = false
	m.Compress = true
	if opt := r.IsEdns0(); opt != nil {
		m.SetEdns0(ednsUDPSize, false)
		if opt.Version() != 0 {
			m.Rcode = dns.RcodeBadVers
			return m, Query{}, false
		}
	}
	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		return m, Query{}, false
	}
	q := r.Question[0]
	// Resolvers randomize the case of the name (DNS 0x20) and expect it back
	// in the question; the name is compared in lower case.
	name := strings.ToLower(q.Name)
	zone := h.zoneOf(name)
	if q.Qclass != dns.ClassINET || zone == "" {
		// Only names under the zones are answered, in the class IN, so that
		// the DNS role is no open resolver and answers no CHAOS queries such
		// as version.bind.
		m.Rcode = dns.RcodeRefused
		return m, Query{}, false
	}
	query, ok := h.queryOf(name, zone, q.Qtype)
	if q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
		m.Rcode = dns.RcodeRefused
		return m, query, ok
	}

	m.Authoritative = true
	apex := name == zone
	switch {
	case apex && q.Qtype == dns.TypeSOA:
		m.Answer = []dns.RR{h.soa(zone)}
	case apex && q.Qtype == dns.TypeNS:
		for _, ns := range h.nameservers {
			m.Answer = append(m.Answer, &dns.NS{Hdr: h.header(zone, dns.TypeNS), Ns: ns})
		}
	case q.Qtype == dns.TypeA && h.ipv4.IsValid():
		m.Answer = []dns.RR{h.a(q.Name)}
	case q.Qtype == dns.TypeAAAA && h.ipv6.IsValid():
		m.Answer = []dns.RR{h.aaaa(q.Name)}
	case q.Qtype == dns.TypeANY:
		// RFC 8482: one record set instead of all of them.
		switch {
		case h.ipv4.IsValid():
			m.Answer = []dns.RR{h.a(q.Name)}
		case h.ipv6.IsValid():
			m.Answer = []dns.RR{h.aaaa(q.Name)}
		default:
			m.Answer = []dns.RR{&dns.HINFO{Hdr: h.header(q.Name, dns.TypeHINFO), Cpu: "RFC8482"}}
		}
	default:
		// The name exists, but has no records of this type. The SOA record
		// tells resolvers how long they may cache that.
		m.Ns = []dns.RR{h.soa(zone)}
	}
	return m, query, ok
}

// zoneOf returns the zone that holds name, both in lower case with a trailing
// dot, or "" if no zone holds it.
func (h *Handler) zoneOf(name string) string {
	for _, z := range h.zones {
		if name == z || strings.HasSuffix(name, "."+z) {
			return z
		}
	}
	return ""
}

// queryOf returns the query to record if the label directly below the zone is
// a trigger value. Further labels in front of it count as well: a resolver that
// minimizes the name it sends asks for "<value>.<zone>" first anyway.
func (h *Handler) queryOf(name, zone string, qtype uint16) (Query, bool) {
	// The apex holds no value, even if a label of the zone looks like one.
	if name == zone {
		return Query{}, false
	}
	labels := dns.SplitDomainName(strings.TrimSuffix(name, "."+zone))
	if len(labels) == 0 || !isTriggerValue(labels[len(labels)-1]) {
		return Query{}, false
	}
	return Query{
		Value:  labels[len(labels)-1],
		Zone:   strings.TrimSuffix(zone, "."),
		Prefix: prefixOf(labels[:len(labels)-1]),
		QType:  qtypeName(qtype),
	}, true
}

func (h *Handler) header(name string, rrtype uint16) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: rrtype, Class: dns.ClassINET, Ttl: h.ttl}
}

func (h *Handler) soa(zone string) dns.RR {
	return &dns.SOA{
		Hdr:     h.header(zone, dns.TypeSOA),
		Ns:      h.nameservers[0],
		Mbox:    "hostmaster." + zone,
		Serial:  h.serial,
		Refresh: soaRefresh,
		Retry:   soaRetry,
		Expire:  soaExpire,
		Minttl:  h.ttl,
	}
}

func (h *Handler) a(name string) dns.RR {
	return &dns.A{Hdr: h.header(name, dns.TypeA), A: h.ipv4.AsSlice()}
}

func (h *Handler) aaaa(name string) dns.RR {
	return &dns.AAAA{Hdr: h.header(name, dns.TypeAAAA), AAAA: h.ipv6.AsSlice()}
}

// recordLater queues q to be recorded in the background, with a deadline of
// its own, so that neither the client nor a slow database delays the answer.
func (h *Handler) recordLater(q Query) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.closed {
		h.dropped.add(reasonQueueFull)
		return
	}
	select {
	case h.queue <- q:
	default:
		h.dropped.add(reasonQueueFull)
	}
}

func (h *Handler) record(ctx context.Context, q Query) {
	defer h.recoverPanic()
	start := h.now()
	if start.Sub(q.ReceivedAt) > maxRecordDelay {
		h.dropped.add(reasonStale)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, recordTimeout)
	defer cancel()
	res, err := h.recorder.Record(ctx, q)

	// The name holds the trigger value, so it stays out of the log.
	attrs := []slog.Attr{
		slog.String("qtype", q.QType),
		slog.String("transport", q.Transport),
		slog.Duration("duration", h.now().Sub(start)),
	}
	if q.Resolver.IsValid() {
		attrs = append(attrs, slog.String("resolver_ip", q.Resolver.String()))
	}
	if err != nil {
		h.logger.ErrorContext(ctx, "dns: recording failed", slog.Any("error", err))
		attrs = append(attrs, slog.String("outcome", "failed"))
	} else {
		attrs = append(attrs, slog.String("outcome", string(res.Outcome)))
	}
	if res.HoneytokenID != "" {
		attrs = append(attrs, slog.String("honeytoken_id", res.HoneytokenID))
	}
	if res.Outcome == OutcomeLimited {
		h.limited.add(res.HoneytokenID)
	}
	h.logger.LogAttrs(ctx, slog.LevelInfo, "dns: query", attrs...)
}

// limitSize truncates an answer over UDP that is larger than the client can
// take or than amplification times the query.
func limitSize(m, r *dns.Msg) {
	size := minUDPSize
	if opt := r.IsEdns0(); opt != nil {
		size = min(max(int(opt.UDPSize()), minUDPSize), ednsUDPSize)
	}
	size = min(size, amplification*r.Len())
	if m.Len() <= size {
		return
	}
	m.Truncated = true
	m.Answer, m.Ns = nil, nil
	m.Extra = slices.DeleteFunc(m.Extra, func(rr dns.RR) bool { return rr.Header().Rrtype != dns.TypeOPT })
}

// truncated returns the answer to a query whose source exceeds its rate: only
// the question, marked as truncated.
func truncated(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = false
	m.Truncated = true
	return m
}

// addrOf returns the IP address of a, or the zero Addr.
func addrOf(a net.Addr) netip.Addr {
	switch a := a.(type) {
	case *net.UDPAddr:
		return a.AddrPort().Addr().Unmap()
	case *net.TCPAddr:
		return a.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

// triggerValueLength is the length of a trigger value: 128 bits in lowercase
// base32 without padding, which is a valid DNS label.
const triggerValueLength = 26

func isTriggerValue(s string) bool {
	if len(s) != triggerValueLength {
		return false
	}
	for i := range len(s) {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}

// qtypeName returns the name of a type of query, such as "A", or "TYPE"
// followed by its number for a type without a name in upper case, such as 0,
// which the DNS library calls "None".
func qtypeName(t uint16) string {
	if name := dns.Type(t).String(); name == strings.ToUpper(name) {
		return name
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// prefixOf joins the labels in front of a trigger value for the database. The
// labels are in presentation format, where a byte that is no printable
// character is written as \DDD and a dot within a label as \.; every byte other
// than a lowercase letter, a digit, '-' or '_' becomes '?', so that whoever
// sends the query cannot write control characters or markup into a report.
// The result is cut to maxPrefixLength.
func prefixOf(labels []string) string {
	var b strings.Builder
	for i, label := range labels {
		if i > 0 {
			b.WriteByte('.')
		}
		for _, c := range unescapeLabel(label) {
			switch {
			case c >= 'A' && c <= 'Z':
				b.WriteByte(c + 'a' - 'A')
			case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_':
				b.WriteByte(c)
			default:
				b.WriteByte('?')
			}
		}
	}
	s := b.String()
	if len(s) > maxPrefixLength {
		s = strings.TrimRight(s[:maxPrefixLength], ".")
	}
	return s
}

// unescapeLabel returns the bytes of a label in presentation format.
func unescapeLabel(label string) []byte {
	out := make([]byte, 0, len(label))
	for i := 0; i < len(label); i++ {
		c := label[i]
		if c != '\\' || i+1 >= len(label) {
			out = append(out, c)
			continue
		}
		if i+3 < len(label) && isDigit(label[i+1]) && isDigit(label[i+2]) && isDigit(label[i+3]) {
			out = append(out, (label[i+1]-'0')*100+(label[i+2]-'0')*10+(label[i+3]-'0'))
			i += 3
			continue
		}
		out = append(out, label[i+1])
		i++
	}
	return out
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// Reasons why a query was not recorded, besides the limit of its honeytoken.
const (
	// reasonQueueFull means that too many queries were waiting to be
	// recorded, or that the recording had stopped.
	reasonQueueFull = "queue_full"
	// reasonStale means that the query waited longer than maxRecordDelay.
	reasonStale = "stale"
)

// counter counts queries by a key between two logs.
type counter struct {
	mu     sync.Mutex
	counts map[string]int
}

func (c *counter) add(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[key]++
}

func (c *counter) take() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	counts := c.counts
	c.counts = map[string]int{}
	return counts
}
