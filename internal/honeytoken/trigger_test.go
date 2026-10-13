// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeytoken

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	miekgdns "github.com/miekg/dns"

	"nyktus.org/nyktus/internal/dns"
	"nyktus.org/nyktus/internal/trigger"
)

type valueRecorder struct{ values []string }

func (r *valueRecorder) Record(_ context.Context, req trigger.Request) (trigger.Result, error) {
	r.values = append(r.values, req.Value)
	return trigger.Result{Outcome: trigger.OutcomeRecorded}, nil
}

// The trigger reads the value from the URL that the console hands out, and
// answers it with what its type needs: an image for web_image, a redirect for
// web_url. The two packages may not import each other's code, so this test
// keeps their formats in step.
func TestTriggerPath_IsAnsweredByTheTrigger(t *testing.T) {
	t.Parallel()

	want := map[Type]int{TypeWebURL: http.StatusFound, TypeWebImage: http.StatusOK}
	for _, typ := range Types {
		if typ == TypeDNS {
			if path := (Honeytoken{Type: typ, TriggerValue: newTriggerValue()}).TriggerPath(); path != "" {
				t.Errorf("%s: path %q, want none", typ, path)
			}
			continue
		}
		rec := &valueRecorder{}
		h := trigger.New(trigger.Options{Logger: slog.New(slog.DiscardHandler), Recorder: rec, DefaultRedirect: "https://www.example.com/"})
		ht := Honeytoken{Type: typ, TriggerValue: newTriggerValue()}

		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, ht.TriggerPath(), nil))
		if len(rec.values) != 1 || rec.values[0] != ht.TriggerValue {
			t.Errorf("%s: the trigger looked up %q, want %q", typ, rec.values, ht.TriggerValue)
		}
		if w.Code != want[typ] {
			t.Errorf("%s: status = %d, want %d", typ, w.Code, want[typ])
		}
	}
}

type queryRecorder struct {
	mu      sync.Mutex
	queries []dns.Query
}

func (r *queryRecorder) Record(_ context.Context, q dns.Query) (dns.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries = append(r.queries, q)
	return dns.Result{Outcome: dns.OutcomeRecorded}, nil
}

// The DNS role reads the value from a name that the console hands out, under
// every zone. The two packages may not import each other's code, so this test
// keeps their formats in step.
func TestTriggerNames_AreRecordedByTheDNSRole(t *testing.T) {
	t.Parallel()

	zones := []string{"d.example.com", "e.example.org"}
	ht := Honeytoken{Type: TypeDNS, TriggerValue: newTriggerValue()}
	names := ht.TriggerNames(zones)
	if len(names) != len(zones) {
		t.Fatalf("TriggerNames() = %v, want one name per zone", names)
	}
	for _, typ := range Types {
		if got := (Honeytoken{Type: typ}).TriggerNames(zones); typ != TypeDNS && (got == nil || len(got) != 0) {
			t.Errorf("%s: TriggerNames() = %#v, want an empty list", typ, got)
		}
	}

	rec := &queryRecorder{}
	h := dns.New(dns.Options{
		Logger: slog.New(slog.DiscardHandler), Recorder: rec, Zones: zones,
		Nameservers: []string{"ns1.example.net"}, TTL: time.Minute,
	})
	lc := net.ListenConfig{}
	pc, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	started, done := make(chan struct{}), make(chan error, 1)
	go func() { done <- dns.Serve(ctx, h, pc, ln, func() { close(started) }) }()
	<-started
	for _, name := range names {
		m := new(miekgdns.Msg)
		m.SetQuestion(miekgdns.Fqdn(name), miekgdns.TypeA)
		if _, err := miekgdns.ExchangeContext(t.Context(), m, pc.LocalAddr().String()); err != nil {
			t.Fatalf("query %s: %v", name, err)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve() = %v", err)
	}
	if len(rec.queries) != len(names) {
		t.Fatalf("recorded %+v, want every name", rec.queries)
	}
	for i, q := range rec.queries {
		if q.Value != ht.TriggerValue || q.Prefix != "" {
			t.Errorf("query %d recorded value %q, prefix %q; want %q", i, q.Value, q.Prefix, ht.TriggerValue)
		}
	}
}
