// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dns

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

const (
	zone = "d.example.com"
	// value is a trigger value; the fake recorder decides what it stands for.
	value = "q3xwz7a2kfm4ub6tyc5nre2lpa"
)

// fakeRecorder records the queries it receives and answers them with
// behavior, which may also fail or panic.
type fakeRecorder struct {
	mu       sync.Mutex
	queries  []Query
	behavior func(Query) (Result, error)
}

func (r *fakeRecorder) Record(_ context.Context, q Query) (Result, error) {
	r.mu.Lock()
	r.queries = append(r.queries, q)
	r.mu.Unlock()
	if r.behavior == nil {
		return Result{Outcome: OutcomeRecorded, HoneytokenID: "00000000-0000-4000-8000-000000000001"}, nil
	}
	return r.behavior(q)
}

func (r *fakeRecorder) recorded() []Query {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Query(nil), r.queries...)
}

func testOptions(rec Recorder) Options {
	return Options{
		Logger:      slog.New(slog.DiscardHandler),
		Recorder:    rec,
		Zones:       []string{zone, "e.example.org"},
		Nameservers: []string{"ns1.example.net", "ns2.example.net"},
		AnswerIPv4:  netip.MustParseAddr("203.0.113.7"),
		AnswerIPv6:  netip.MustParseAddr("2001:db8::7"),
		TTL:         time.Minute,
		Serial:      1760000000,
	}
}

// server is a DNS role on loopback, over UDP and TCP.
type server struct {
	udp, tcp string
	handler  *Handler
	stop     func()
}

func startServer(t *testing.T, o Options) server {
	t.Helper()
	lc := net.ListenConfig{}
	pc, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := New(o)
	// All queries of a test come from loopback; TestSourceLimiter and
	// TestDNS_UDPRateLimit cover the limit.
	h.limiter.limit = rate.Inf
	ctx, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
	started, done := make(chan struct{}), make(chan error, 1)
	go func() { done <- Serve(ctx, h, pc, ln, func() { close(started) }) }()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("Serve() = %v before it started", err)
	case <-time.After(10 * time.Second):
		t.Fatal("Serve() did not start")
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Serve() = %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("Serve() did not stop")
			}
		})
	}
	t.Cleanup(stop)
	return server{udp: pc.LocalAddr().String(), tcp: ln.Addr().String(), handler: h, stop: stop}
}

func (s server) addr(network string) string {
	if network == "tcp" {
		return s.tcp
	}
	return s.udp
}

func exchange(t *testing.T, s server, network string, m *dns.Msg) *dns.Msg {
	t.Helper()
	client := &dns.Client{Net: network, Timeout: 5 * time.Second, UDPSize: 4096}
	res, _, err := client.ExchangeContext(t.Context(), m, s.addr(network))
	if err != nil {
		t.Fatalf("%s %v: %v", network, m.Question, err)
	}
	return res
}

func question(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	return m
}

// normalized packs an answer with the queried name replaced by a placeholder
// and the identifier set to zero, so that answers to different names can be
// compared byte for byte.
func normalized(t *testing.T, m *dns.Msg, name string) []byte {
	t.Helper()
	m = m.Copy()
	m.Id = 0
	const placeholder = "name.invalid."
	for i := range m.Question {
		if strings.EqualFold(m.Question[i].Name, name) {
			m.Question[i].Name = placeholder
		}
	}
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			if strings.EqualFold(rr.Header().Name, name) {
				rr.Header().Name = placeholder
			}
		}
	}
	m.Compress = false
	b, err := m.Pack()
	if err != nil {
		t.Fatalf("pack %v: %v", m, err)
	}
	return b
}

// The invariant: a client cannot tell from the answer whether a name holds the
// value of an enabled honeytoken, an unknown, disabled or limited one, one of
// another type, or one whose recording failed or panicked. Rcode, flags, every
// section and the TTLs are compared, over UDP and TCP, for several types of
// query, with and without EDNS.
func TestDNS_IdenticalAnswers(t *testing.T) {
	t.Parallel()

	values := map[string]func(Query) (Result, error){
		"recorded":      func(Query) (Result, error) { return Result{Outcome: OutcomeRecorded, HoneytokenID: "x"}, nil },
		"unknown":       func(Query) (Result, error) { return Result{Outcome: OutcomeUnknown}, nil },
		"disabled":      func(Query) (Result, error) { return Result{Outcome: OutcomeDisabled, HoneytokenID: "x"}, nil },
		"limited":       func(Query) (Result, error) { return Result{Outcome: OutcomeLimited, HoneytokenID: "x"}, nil },
		"wrong type":    func(Query) (Result, error) { return Result{Outcome: OutcomeRecorded, HoneytokenID: "x"}, nil },
		"database fail": func(Query) (Result, error) { return Result{}, errors.New("connection refused") },
		"panic":         func(Query) (Result, error) { panic("recorder broke") },
	}
	// Every case gets a value of its own, which the recorder maps to its
	// behavior.
	behaviors := map[string]func(Query) (Result, error){}
	names := map[string]string{}
	i := 0
	for name, b := range values {
		v := strings.Repeat(string(rune('a'+i)), triggerValueLength)
		behaviors[v] = b
		names[name] = v
		i++
	}
	rec := &fakeRecorder{behavior: func(q Query) (Result, error) { return behaviors[q.Value](q) }}
	s := startServer(t, testOptions(rec))

	for _, network := range []string{"udp", "tcp"} {
		for _, edns := range []bool{false, true} {
			for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT, dns.TypeMX, dns.TypeANY, dns.TypeSOA, dns.TypeNS, dns.TypeCAA, 65280} {
				for _, prefix := range []string{"", "vpn."} {
					ask := func(label string) []byte {
						name := prefix + label + "." + zone + "."
						m := question(name, qtype)
						if edns {
							m.SetEdns0(1232, false)
						}
						return normalized(t, exchange(t, s, network, m), name)
					}
					want := ask("notavalue")
					for name, v := range names {
						if got := ask(v); !bytes.Equal(got, want) {
							t.Errorf("%s edns=%v %s %q, %s: answer differs from an unknown name", network, edns, dns.TypeToString[qtype], prefix, name)
						}
					}
				}
			}
		}
	}

	s.stop()
	if n := len(rec.recorded()); n == 0 {
		t.Error("no query was recorded")
	}
}

// Every name under a zone receives the same records: the configured
// addresses, nothing for other types, and the SOA record that bounds negative
// caching.
func TestDNS_AnswersByForm(t *testing.T) {
	t.Parallel()
	s := startServer(t, testOptions(&fakeRecorder{}))
	name := "host." + zone + "."

	res := exchange(t, s, "udp", question(name, dns.TypeA))
	if res.Rcode != dns.RcodeSuccess || !res.Authoritative || res.RecursionAvailable || len(res.Answer) != 1 {
		t.Fatalf("A = %v", res)
	}
	if a := res.Answer[0].(*dns.A); a.A.String() != "203.0.113.7" || a.Hdr.Ttl != 60 {
		t.Errorf("A = %v, want the configured address with a TTL of 60", a)
	}
	res = exchange(t, s, "udp", question(name, dns.TypeAAAA))
	if len(res.Answer) != 1 || res.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::7" {
		t.Errorf("AAAA = %v", res)
	}
	res = exchange(t, s, "udp", question(name, dns.TypeTXT))
	if res.Rcode != dns.RcodeSuccess || len(res.Answer) != 0 || len(res.Ns) != 1 {
		t.Fatalf("TXT = %v, want no data with the SOA record", res)
	}
	soa := res.Ns[0].(*dns.SOA)
	if soa.Hdr.Name != zone+"." || soa.Ns != "ns1.example.net." || soa.Mbox != "hostmaster."+zone+"." || soa.Minttl != 60 || soa.Hdr.Ttl != 60 || soa.Serial != 1760000000 {
		t.Errorf("SOA = %v", soa)
	}

	// The apex names the name servers of the zone.
	res = exchange(t, s, "udp", question(zone+".", dns.TypeNS))
	if len(res.Answer) != 2 || res.Answer[0].(*dns.NS).Ns != "ns1.example.net." || res.Answer[1].(*dns.NS).Ns != "ns2.example.net." {
		t.Errorf("NS = %v", res)
	}
	// Resolvers send EDNS; without it, this short query would receive a
	// truncated answer, which TestDNS_LimitsTheSizeOfAnswersOverUDP covers.
	m := question("E.Example.ORG.", dns.TypeSOA)
	m.SetEdns0(1232, false)
	res = exchange(t, s, "udp", m)
	if len(res.Answer) != 1 || res.Answer[0].Header().Name != "e.example.org." {
		t.Errorf("SOA of the second zone = %v", res)
	}

	// ANY receives one record set (RFC 8482).
	res = exchange(t, s, "udp", question(name, dns.TypeANY))
	if len(res.Answer) != 1 || res.Answer[0].Header().Rrtype != dns.TypeA {
		t.Errorf("ANY = %v, want the A record only", res)
	}

	// Resolvers randomize the case of the name and expect it back.
	res = exchange(t, s, "udp", question("HoSt.D.eXaMpLe.CoM.", dns.TypeA))
	if res.Question[0].Name != "HoSt.D.eXaMpLe.CoM." || len(res.Answer) != 1 || res.Answer[0].Header().Name != "HoSt.D.eXaMpLe.CoM." {
		t.Errorf("mixed case = %v, want the name as asked", res)
	}
}

// Without configured addresses, every name exists but has no address, and ANY
// receives the synthesized record of RFC 8482.
func TestDNS_WithoutAddresses(t *testing.T) {
	t.Parallel()
	o := testOptions(&fakeRecorder{})
	o.AnswerIPv4, o.AnswerIPv6 = netip.Addr{}, netip.Addr{}
	s := startServer(t, o)

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		res := exchange(t, s, "udp", question(value+"."+zone+".", qtype))
		if res.Rcode != dns.RcodeSuccess || len(res.Answer) != 0 || len(res.Ns) != 1 {
			t.Errorf("%s = %v, want no data", dns.TypeToString[qtype], res)
		}
	}
	res := exchange(t, s, "udp", question(value+"."+zone+".", dns.TypeANY))
	if len(res.Answer) != 1 || res.Answer[0].(*dns.HINFO).Cpu != "RFC8482" {
		t.Errorf("ANY = %v, want HINFO RFC8482", res)
	}
}

// The DNS role is no resolver: names outside its zones are refused, without
// recursion and without a record.
func TestDNS_NoRecursion(t *testing.T) {
	t.Parallel()
	rec := &fakeRecorder{}
	s := startServer(t, testOptions(rec))

	for _, name := range []string{"example.com.", "www.example.org.", value + ".example.com.", "xd.example.com.", "."} {
		for _, network := range []string{"udp", "tcp"} {
			m := question(name, dns.TypeA)
			m.RecursionDesired = true
			res := exchange(t, s, network, m)
			if res.Rcode != dns.RcodeRefused || res.RecursionAvailable || res.Authoritative || len(res.Answer)+len(res.Ns) != 0 {
				t.Errorf("%s %s = %v, want REFUSED without records", network, name, res)
			}
		}
	}
	s.stop()
	if q := rec.recorded(); len(q) != 0 {
		t.Errorf("recorded %v, want nothing", q)
	}
}

// Queries in the class CHAOS, such as version.bind, would reveal the server
// software. They are refused like every name outside the zones, also for a name
// under a zone.
func TestDNS_NoAnswerToChaosQueries(t *testing.T) {
	t.Parallel()
	rec := &fakeRecorder{}
	s := startServer(t, testOptions(rec))

	for _, name := range []string{"version.bind.", "hostname.bind.", "id.server.", "version.server.", value + "." + zone + "."} {
		m := question(name, dns.TypeTXT)
		m.Question[0].Qclass = dns.ClassCHAOS
		res := exchange(t, s, "udp", m)
		if res.Rcode != dns.RcodeRefused || len(res.Answer)+len(res.Ns)+len(res.Extra) != 0 {
			t.Errorf("CH TXT %s = %v, want REFUSED without records", name, res)
		}
	}
	s.stop()
	if q := rec.recorded(); len(q) != 0 {
		t.Errorf("recorded %v, want nothing", q)
	}
}

// Zone transfers would list every name, and dynamic updates or notifications
// are not offered.
func TestDNS_RefusesTransfersAndOtherOpcodes(t *testing.T) {
	t.Parallel()
	s := startServer(t, testOptions(&fakeRecorder{}))

	for _, qtype := range []uint16{dns.TypeAXFR, dns.TypeIXFR} {
		res := exchange(t, s, "tcp", question(zone+".", qtype))
		if res.Rcode != dns.RcodeRefused || len(res.Answer) != 0 {
			t.Errorf("%s = %v, want REFUSED", dns.TypeToString[qtype], res)
		}
	}
	for _, opcode := range []int{dns.OpcodeNotify, dns.OpcodeUpdate, dns.OpcodeStatus, dns.OpcodeIQuery} {
		m := question(zone+".", dns.TypeSOA)
		m.Opcode = opcode
		if res := exchange(t, s, "udp", m); res.Rcode != dns.RcodeNotImplemented {
			t.Errorf("opcode %d = %v, want NOTIMP", opcode, res)
		}
	}
	m := question(zone+".", dns.TypeSOA)
	m.Question = append(m.Question, m.Question[0])
	if res := exchange(t, s, "udp", m); res.Rcode != dns.RcodeFormatError {
		t.Errorf("two questions = %v, want FORMERR", res)
	}
	m = question(zone+".", dns.TypeSOA)
	m.SetEdns0(1232, false)
	m.IsEdns0().SetVersion(1)
	if res := exchange(t, s, "udp", m); res.Rcode != dns.RcodeBadVers {
		t.Errorf("EDNS version 1 = %v, want BADVERS", res)
	}
}

// A response sent to the DNS role receives no answer, so that two servers
// cannot be made to answer each other.
func TestDNS_IgnoresResponses(t *testing.T) {
	t.Parallel()
	s := startServer(t, testOptions(&fakeRecorder{}))

	m := question(zone+".", dns.TypeSOA)
	m.Response = true
	client := &dns.Client{Net: "udp", Timeout: 300 * time.Millisecond}
	if res, _, err := client.ExchangeContext(t.Context(), m, s.udp); err == nil {
		t.Errorf("response received an answer: %v", res)
	}
}

// A query is recorded with the zone, the labels in front of the value, its
// type and transport and the address of the resolver, whatever the case of the
// name.
func TestDNS_RecordsTheQueriesOfValues(t *testing.T) {
	t.Parallel()
	rec := &fakeRecorder{}
	s := startServer(t, testOptions(rec))

	exchange(t, s, "udp", question(strings.ToUpper(value)+".D.Example.Com.", dns.TypeA))
	exchange(t, s, "tcp", question("VPN.Db01."+value+".e.example.org.", dns.TypeMX))
	exchange(t, s, "udp", question(`a\000b.`+value+"."+zone+".", 65280))
	// Not a value: the label below the zone decides.
	exchange(t, s, "udp", question(value+".x."+zone+".", dns.TypeA))
	exchange(t, s, "udp", question(zone+".", dns.TypeSOA))
	s.stop()

	got := map[string]Query{}
	for _, q := range rec.recorded() {
		got[q.Transport+" "+q.QType] = q
	}
	loopback := netip.MustParseAddr("127.0.0.1")
	for key, want := range map[string]Query{
		"udp A":         {Value: value, Zone: zone, Prefix: "", QType: "A", Transport: "udp", Resolver: loopback},
		"tcp MX":        {Value: value, Zone: "e.example.org", Prefix: "vpn.db01", QType: "MX", Transport: "tcp", Resolver: loopback},
		"udp TYPE65280": {Value: value, Zone: zone, Prefix: "a?b", QType: "TYPE65280", Transport: "udp", Resolver: loopback},
	} {
		if got[key] != want {
			t.Errorf("%s: recorded %+v, want %+v", key, got[key], want)
		}
	}
	if n := len(rec.recorded()); n != 3 {
		t.Errorf("%d queries recorded, want 3: %+v", n, rec.recorded())
	}
}

// A zone may have a label that looks like a trigger value; its apex is still
// no value.
func TestDNS_ApexIsNoValue(t *testing.T) {
	t.Parallel()
	rec := &fakeRecorder{}
	o := testOptions(rec)
	o.Zones = []string{"x." + value}
	s := startServer(t, o)

	exchange(t, s, "udp", question("x."+value+".", dns.TypeSOA))
	exchange(t, s, "udp", question("host.x."+value+".", dns.TypeA))
	s.stop()
	if q := rec.recorded(); len(q) != 0 {
		t.Errorf("recorded %+v, want nothing", q)
	}
}

// The answer is written before the query is recorded, and the recording runs
// with a deadline of its own, detached from the query: a client that does not
// wait cannot keep its query from being recorded, and a slow database does not
// delay the answer.
func TestDNS_RecordingIsDetachedAndHasItsOwnDeadline(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	deadline := make(chan time.Duration, 1)
	rec := &fakeRecorder{behavior: func(Query) (Result, error) {
		<-release
		return Result{Outcome: OutcomeRecorded}, nil
	}}
	o := testOptions(&ctxRecorder{inner: rec, deadline: deadline})
	s := startServer(t, o)

	start := time.Now()
	exchange(t, s, "udp", question(value+"."+zone+".", dns.TypeA))
	if d := time.Since(start); d > recordTimeout {
		t.Errorf("the answer took %v, want it before the recording", d)
	}
	select {
	case d := <-deadline:
		if d <= 0 || d > recordTimeout {
			t.Errorf("recording deadline in %v, want at most %v", d, recordTimeout)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the query was not recorded")
	}
	close(release)
	s.stop()
	if n := len(rec.recorded()); n != 1 {
		t.Errorf("%d queries recorded, want 1", n)
	}
}

// ctxRecorder reports the deadline of the context it is called with.
type ctxRecorder struct {
	inner    Recorder
	deadline chan time.Duration
}

func (r *ctxRecorder) Record(ctx context.Context, q Query) (Result, error) {
	if d, ok := ctx.Deadline(); ok {
		r.deadline <- time.Until(d)
	} else {
		r.deadline <- -1
	}
	return r.inner.Record(ctx, q)
}

// fakeWriter is a ResponseWriter for calls of ServeDNS without a network.
type fakeWriter struct {
	dns.ResponseWriter
	remote net.Addr
	msgs   []*dns.Msg
}

func (w *fakeWriter) RemoteAddr() net.Addr { return w.remote }
func (w *fakeWriter) LocalAddr() net.Addr  { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }

func (w *fakeWriter) WriteMsg(m *dns.Msg) error {
	w.msgs = append(w.msgs, m)
	return nil
}

// The queries that wait to be recorded are bounded. A query that finds the
// queue full is answered as always, not recorded, and counted in the log.
func TestDNS_BoundsTheQueueOfRecordings(t *testing.T) {
	t.Parallel()
	rec := &fakeRecorder{}
	var logs bytes.Buffer
	o := testOptions(rec)
	o.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	h := New(o)

	// Nothing records yet, so the queue fills.
	tcp := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4000}
	var first []byte
	for i := range maxQueued + 5 {
		w := &fakeWriter{remote: tcp}
		h.ServeDNS(w, question(value+"."+zone+".", dns.TypeA))
		if len(w.msgs) != 1 {
			t.Fatalf("ServeDNS wrote %d answers, want 1", len(w.msgs))
		}
		got := normalized(t, w.msgs[0], "")
		if i == 0 {
			first = got
		} else if !bytes.Equal(got, first) {
			t.Fatalf("answer %d differs from the first", i)
		}
	}
	h.startRecording(t.Context())()
	if n := len(rec.recorded()); n != maxQueued {
		t.Errorf("%d queries recorded, want %d", n, maxQueued)
	}
	h.flush(t.Context())
	if !strings.Contains(logs.String(), `"queries":5,"reason":"queue_full"`) {
		t.Errorf("log = %s, want 5 queries not recorded", logs.String())
	}
}

// A panic in the handler must not end the process, because the server of the
// DNS library does not recover it.
func TestDNS_RecoversPanics(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	o := testOptions(&fakeRecorder{})
	o.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	h := New(o)

	// A nil message stands in for any bug in the handler.
	h.ServeDNS(&fakeWriter{remote: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1)}}, nil)
	if !strings.Contains(logs.String(), "dns: handler panicked") {
		t.Errorf("log = %s, want the panic logged", logs.String())
	}
}

// The log names the honeytoken, the outcome and the resolver, but never the
// name, which holds the trigger value.
func TestDNS_LogsWithoutTheName(t *testing.T) {
	t.Parallel()
	var logs syncBuffer
	o := testOptions(&fakeRecorder{})
	o.Logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s := startServer(t, o)

	exchange(t, s, "udp", question("vpn."+value+"."+zone+".", dns.TypeA))
	exchange(t, s, "udp", question("other."+zone+".", dns.TypeA))
	s.stop()
	out := logs.String()
	for _, want := range []string{`"msg":"dns: query"`, `"outcome":"recorded"`, `"honeytoken_id":"00000000-0000-4000-8000-000000000001"`, `"resolver_ip":"127.0.0.1"`, `"qtype":"A"`} {
		if !strings.Contains(out, want) {
			t.Errorf("log does not contain %s: %s", want, out)
		}
	}
	for _, leak := range []string{value, "vpn", "other", zone} {
		if strings.Contains(out, leak) {
			t.Errorf("log contains %q: %s", leak, out)
		}
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// An answer over UDP is never larger than three times the query, so that the
// DNS role cannot amplify a flood with a forged source. A larger answer is
// truncated, and the client asks again over TCP, where it is complete.
func TestDNS_LimitsTheSizeOfAnswersOverUDP(t *testing.T) {
	t.Parallel()
	o := testOptions(&fakeRecorder{})
	o.Nameservers = []string{
		"ns1.a-long-name-of-a-name-server.example.net", "ns2.a-long-name-of-a-name-server.example.net",
		"ns3.a-long-name-of-a-name-server.example.net", "ns4.a-long-name-of-a-name-server.example.net",
		"ns5.a-long-name-of-a-name-server.example.net", "ns6.a-long-name-of-a-name-server.example.net",
	}
	s := startServer(t, o)

	m := question(zone+".", dns.TypeNS)
	res := exchange(t, s, "udp", m)
	if !res.Truncated || len(res.Answer) != 0 {
		t.Errorf("UDP NS = %v, want a truncated answer", res)
	}
	if res.Len() > amplification*m.Len() {
		t.Errorf("answer of %d bytes to a query of %d", res.Len(), m.Len())
	}
	res = exchange(t, s, "tcp", m)
	if res.Truncated || len(res.Answer) != 6 {
		t.Errorf("TCP NS = %v, want every name server", res)
	}
}

// Over UDP, a source network that exceeds its rate receives every second
// answer truncated, so that a real client continues over TCP, and nothing for
// the others. TCP is not limited: its source cannot be forged.
func TestSourceLimiter(t *testing.T) {
	t.Parallel()
	l := newSourceLimiter()
	now := time.Now()
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.200")

	for i := range sourceBurst {
		if v := l.allow(a, now); v != verdictAllow {
			t.Fatalf("query %d = %v, want allowed within the burst", i, v)
		}
	}
	// The same /24 shares the bucket.
	if v := l.allow(b, now); v != verdictTruncate {
		t.Errorf("first query beyond the limit = %v, want truncate", v)
	}
	if v := l.allow(a, now); v != verdictDrop {
		t.Errorf("second query beyond the limit = %v, want drop", v)
	}
	if v := l.allow(netip.MustParseAddr("192.0.3.1"), now); v != verdictAllow {
		t.Errorf("another network = %v, want allowed", v)
	}
	if v := l.allow(a, now.Add(time.Second)); v != verdictAllow {
		t.Errorf("a second later = %v, want allowed again", v)
	}

	// IPv6 networks are /56.
	if sourceNetwork(netip.MustParseAddr("2001:db8:0:ff::1")) != sourceNetwork(netip.MustParseAddr("2001:db8:0:1::1")) {
		t.Error("addresses of one /56 fall into different networks")
	}
	l.forget(now.Add(sourceIdle + 2*time.Second))
	if len(l.sources) != 0 {
		t.Errorf("%d sources remembered after they were idle, want none", len(l.sources))
	}

	// A full table treats new sources as over their limit, together.
	for i := range maxSources {
		l.sources[netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)] = &source{}
	}
	if v := l.allow(netip.MustParseAddr("198.51.100.1"), now); v != verdictTruncate {
		t.Errorf("new source with a full table = %v, want truncate", v)
	}
	if v := l.allow(netip.MustParseAddr("203.0.113.1"), now); v != verdictDrop {
		t.Errorf("second new source with a full table = %v, want drop", v)
	}
}

func TestDNS_UDPRateLimit(t *testing.T) {
	t.Parallel()
	h := New(testOptions(&fakeRecorder{}))
	udp := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4000}
	var truncated, dropped int
	for range sourceBurst + 10 {
		w := &fakeWriter{remote: udp}
		h.ServeDNS(w, question("host."+zone+".", dns.TypeA))
		switch {
		case len(w.msgs) == 0:
			dropped++
		case w.msgs[0].Truncated:
			if len(w.msgs[0].Answer) != 0 {
				t.Errorf("truncated answer carries records: %v", w.msgs[0])
			}
			truncated++
		}
	}
	if truncated != 5 || dropped != 5 {
		t.Errorf("%d truncated, %d dropped, want 5 each", truncated, dropped)
	}
	tcp := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4000}
	w := &fakeWriter{remote: tcp}
	h.ServeDNS(w, question("host."+zone+".", dns.TypeA))
	if len(w.msgs) != 1 || w.msgs[0].Truncated || len(w.msgs[0].Answer) != 1 {
		t.Errorf("TCP beyond the UDP limit = %v, want a full answer", w.msgs)
	}
}

func TestPrefixOf(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		labels []string
		want   string
	}{
		{nil, ""},
		{[]string{"vpn"}, "vpn"},
		{[]string{"VPN", "db-01", "_srv"}, "vpn.db-01._srv"},
		{[]string{`a\000b`, `c\.d`, `e\ f`, `<x>`}, "a?b.c?d.e?f.?x?"},
		{[]string{`\255\065`}, "?a"},
		{[]string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 63)}, strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 8)},
		{[]string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 72), "d"}, strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 72)},
	} {
		got := prefixOf(tt.labels)
		if got != tt.want {
			t.Errorf("prefixOf(%q) = %q, want %q", tt.labels, got, tt.want)
		}
		if len(got) > maxPrefixLength || !prefixPattern.MatchString(got) {
			t.Errorf("prefixOf(%q) = %q, which the schema rejects", tt.labels, got)
		}
	}
}

// The patterns of the schema for the prefix and the type of a query, in Go
// syntax. The store tests write what the code produces to the database.
var (
	prefixPattern = regexp.MustCompile(`^([a-z0-9_?-]+(\.[a-z0-9_?-]+)*)?$`)
	qtypePattern  = regexp.MustCompile(`^[A-Z0-9-]{1,16}$`)
)

// Every type of query has a name that the schema accepts.
func TestQTypeName_FitsTheSchema(t *testing.T) {
	t.Parallel()
	if got := qtypeName(dns.TypeA); got != "A" {
		t.Errorf("qtypeName(A) = %q", got)
	}
	if got := qtypeName(0); got != "TYPE0" {
		t.Errorf("qtypeName(0) = %q, want TYPE0", got)
	}
	for i := range 1 << 16 {
		if name := qtypeName(uint16(i)); !qtypePattern.MatchString(name) {
			t.Fatalf("qtypeName(%d) = %q, which the schema rejects", i, name)
		}
	}
}

// A handler that still runs when the recording stops, because the servers did
// not stop in time, neither panics nor records.
func TestDNS_QueriesAfterTheRecordingStopped(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	rec := &fakeRecorder{}
	o := testOptions(rec)
	o.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
	h := New(o)
	h.startRecording(t.Context())()

	w := &fakeWriter{remote: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4000}}
	h.ServeDNS(w, question(value+"."+zone+".", dns.TypeA))
	if len(w.msgs) != 1 || strings.Contains(logs.String(), "panicked") || len(rec.recorded()) != 0 {
		t.Errorf("answers %d, recorded %d, log %s; want one answer, no record, no panic", len(w.msgs), len(rec.recorded()), logs.String())
	}
}

// When the servers stop, the queries that wait in the queue are still
// recorded, with a context that the stop does not cancel.
func TestDNS_RecordsTheQueueWhenTheServerStops(t *testing.T) {
	t.Parallel()
	var canceled []bool
	var mu sync.Mutex
	rec := &fakeRecorder{behavior: func(Query) (Result, error) { return Result{Outcome: OutcomeRecorded}, nil }}
	h := New(testOptions(&checkingRecorder{inner: rec, check: func(ctx context.Context) {
		mu.Lock()
		defer mu.Unlock()
		canceled = append(canceled, ctx.Err() != nil)
	}}))
	for range 3 {
		h.ServeDNS(&fakeWriter{remote: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4000}}, question(value+"."+zone+".", dns.TypeA))
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	h.startRecording(ctx)()
	if len(canceled) != 3 || slices.Contains(canceled, true) {
		t.Errorf("recordings with a canceled context: %v, want three that were not canceled", canceled)
	}
}

type checkingRecorder struct {
	inner Recorder
	check func(context.Context)
}

func (r *checkingRecorder) Record(ctx context.Context, q Query) (Result, error) {
	r.check(ctx)
	return r.inner.Record(ctx, q)
}
