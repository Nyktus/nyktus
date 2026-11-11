// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package incident

import (
	"sync"
	"testing"
	"time"

	"nyktus.org/nyktus/internal/honeytoken"
	"nyktus.org/nyktus/internal/platform/schematest"
	"nyktus.org/nyktus/internal/scenario"
	"nyktus.org/nyktus/internal/severity"
)

// scenario creates a scenario and returns its identifier.
func (f fixture) scenario(t *testing.T) string {
	t.Helper()
	var id string
	if err := f.owner.QueryRow(t.Context(), `INSERT INTO scenarios (name) VALUES ('s') RETURNING id`).Scan(&id); err != nil {
		t.Fatalf("create scenario: %v", err)
	}
	return id
}

// scenarioEvent writes an event of the URL honeytoken resource that froze the
// scenario scenarioID, with its job, and returns its identifier.
func (f fixture) scenarioEvent(t *testing.T, resource, scenarioID string) string {
	t.Helper()
	id := f.event(t, resource, "web_url", nil, time.Now())
	f.exec(t, "UPDATE events SET scenario_id = $2, scenario_name = 'Scenario' WHERE id = $1", id, scenarioID)
	return id
}

// The events of every honeytoken of a scenario join one incident of the
// scenario with one alert, which holds the highest severity and every
// technique of them; a honeytoken that stands alone keeps an incident of its
// own.
func TestStore_EventsOfAScenarioShareOneIncident(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	sc := f.scenario(t)
	image, imageValue := f.honeytoken(t, "web_image", []string{"T1213"})
	url, urlValue := f.honeytoken(t, "web_url", []string{"T1083"})
	alone, aloneValue := f.honeytoken(t, "web_url", nil)
	f.exec(t, "UPDATE honeytokens SET scenario_id = $1 WHERE id = ANY($2)", sc, []string{image, url})
	for _, v := range []string{imageValue, urlValue, aloneValue, imageValue} {
		f.exec(t, "SELECT * FROM record_honeytoken_request($1, 'GET', NULL, '', '', '', '')", v)
	}

	first := f.process(t)
	if !first.Opened || first.ResourceType != scenario.ResourceType || first.ResourceID != sc || first.ResourceName != "s" || first.Severity != severity.Low {
		t.Fatalf("first event = %+v, want an opened incident of the scenario with severity low", first)
	}
	second := f.process(t)
	if second.Opened || second.IncidentID != first.IncidentID || second.Severity != severity.Medium {
		t.Errorf("event of another honeytoken of the scenario = %+v, want it in %s with severity medium", second, first.IncidentID)
	}
	own := f.process(t)
	if !own.Opened || own.ResourceType != honeytoken.ResourceType || own.ResourceID != alone || own.ResourceName != "h" || own.IncidentID == first.IncidentID {
		t.Errorf("event of a honeytoken that stands alone = %+v, want an incident of its own", own)
	}
	if again := f.process(t); again.Opened || again.IncidentID != first.IncidentID {
		t.Errorf("further event of the scenario = %+v, want it in %s", again, first.IncidentID)
	}

	got := f.incident(t, first.IncidentID)
	if got.status != StatusOpen || got.severity != severity.Medium || got.count != 3 || len(got.techniques) != 2 {
		t.Errorf("incident of the scenario = %+v, want open, medium, 3 events, 2 techniques", got)
	}
	if n := f.count(t, "SELECT count(*) FROM alerts"); n != 2 {
		t.Errorf("%d alerts, want one of the scenario and one of the honeytoken that stands alone", n)
	}
	if n := f.count(t, "SELECT count(*) FROM alerts WHERE incident_id = $1 AND severity = 'low'", first.IncidentID); n != 1 {
		t.Errorf("%d alerts of the scenario with the state at opening, want 1", n)
	}
}

// honeypot creates an enabled honeypot of service ssh with a new secret and
// returns its identifier and the SQL that records a session of it.
func (f fixture) honeypot(t *testing.T, severity string, techniques []string) (id, record string) {
	t.Helper()
	if techniques == nil {
		techniques = []string{}
	}
	err := f.owner.QueryRow(t.Context(), `
INSERT INTO honeypots (service, name, severity, techniques, secret_hash, secret_sealed)
VALUES ('ssh', 'h', $1, $2, sha256(convert_to(gen_random_uuid()::text, 'UTF8')), sha256('s')) RETURNING id`, severity, techniques).Scan(&id)
	if err != nil {
		t.Fatalf("create honeypot: %v", err)
	}
	return id, `SELECT * FROM public.record_honeypot_session((SELECT secret_hash FROM honeypots WHERE id = '` + id + `'),
	gen_random_uuid(), interval '0', 10, '192.0.2.1', 22, 'login_attempt', NULL, NULL, NULL, NULL, NULL, '[{"username":"root"}]', '[]')`
}

// A honeytoken and a honeypot of one scenario share one incident with one
// alert, whatever raised the event; a honeypot that stands alone keeps an
// incident of its own, of its own kind.
func TestStore_HoneytokenAndHoneypotOfAScenarioShareOneIncident(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	sc := f.scenario(t)
	url, urlValue := f.honeytoken(t, "web_image", []string{"T1083"})
	pot, inScenario := f.honeypot(t, "high", []string{"T1078"})
	alone, standalone := f.honeypot(t, "medium", nil)
	f.exec(t, "UPDATE honeytokens SET scenario_id = $1 WHERE id = $2", sc, url)
	f.exec(t, "UPDATE honeypots SET scenario_id = $1 WHERE id = $2", sc, pot)

	f.exec(t, "SELECT * FROM record_honeytoken_request($1, 'GET', NULL, '', '', '', '')", urlValue)
	f.exec(t, inScenario)
	f.exec(t, standalone)
	f.exec(t, inScenario)

	first := f.process(t)
	if !first.Opened || first.ResourceType != scenario.ResourceType || first.ResourceID != sc || first.Severity != severity.Low {
		t.Fatalf("event of the honeytoken = %+v, want an opened incident of the scenario with severity low", first)
	}
	session := f.process(t)
	if session.Opened || session.IncidentID != first.IncidentID || session.Severity != severity.High {
		t.Errorf("session of the honeypot of the scenario = %+v, want it in %s with severity high", session, first.IncidentID)
	}
	own := f.process(t)
	if !own.Opened || own.ResourceType != "honeypot" || own.ResourceID != alone || own.IncidentID == first.IncidentID {
		t.Errorf("session of a honeypot that stands alone = %+v, want an incident of its own", own)
	}
	if again := f.process(t); again.Opened || again.IncidentID != first.IncidentID {
		t.Errorf("further session of the scenario = %+v, want it in %s", again, first.IncidentID)
	}

	got := f.incident(t, first.IncidentID)
	if got.status != StatusOpen || got.severity != severity.High || got.count != 3 || len(got.techniques) != 4 {
		t.Errorf("incident of the scenario = %+v, want open, high, 3 events, 4 techniques", got)
	}
	if n := f.count(t, "SELECT count(*) FROM alerts"); n != 2 {
		t.Errorf("%d alerts, want one of the scenario and one of the honeypot that stands alone", n)
	}
	if n := f.count(t, "SELECT count(*) FROM incidents"); n != 2 {
		t.Errorf("%d incidents, want 2", n)
	}
}

// A honeytoken that joins a scenario keeps its open incident: its later events
// go to the incident of the scenario, which opens with its own alert, and the
// incident of the honeytoken stays open. Events that it raised before it
// joined stay with the honeytoken, also when they are processed afterwards.
func TestStore_HoneytokenThatJoinsAScenarioKeepsItsOpenIncident(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	sc := f.scenario(t)
	h, _ := f.honeytoken(t, "web_url", nil)
	f.event(t, h, "web_url", nil, time.Now())
	before := f.process(t)
	late := f.event(t, h, "web_url", nil, time.Now())
	f.exec(t, "UPDATE honeytokens SET scenario_id = $1 WHERE id = $2", sc, h)
	f.process(t)
	if f.eventIncident(t, late) != before.IncidentID {
		t.Errorf("an event raised before the honeytoken joined went to %s, want %s", f.eventIncident(t, late), before.IncidentID)
	}

	after := f.scenarioEvent(t, h, sc)
	p := f.process(t)
	if !p.Opened || p.ResourceType != scenario.ResourceType || p.ResourceID != sc || f.eventIncident(t, after) != p.IncidentID {
		t.Errorf("event after joining = %+v, want an opened incident of the scenario", p)
	}
	if got := f.incident(t, before.IncidentID); got.status != StatusOpen || got.count != 2 {
		t.Errorf("incident of the honeytoken = %+v, want it open with its 2 events", got)
	}
}

// Events of a scenario that was deleted meanwhile still share one incident of
// the scenario, which outlives it like any resource.
func TestStore_EventsOfADeletedScenarioShareOneIncident(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	sc := f.scenario(t)
	a, _ := f.honeytoken(t, "web_url", nil)
	b, _ := f.honeytoken(t, "web_url", nil)
	f.scenarioEvent(t, a, sc)
	f.scenarioEvent(t, b, sc)
	f.exec(t, "DELETE FROM scenarios WHERE id = $1", sc)

	first, second := f.process(t), f.process(t)
	if !first.Opened || first.ResourceID != sc || second.Opened || second.IncidentID != first.IncidentID {
		t.Errorf("events = %+v, %+v; want one incident of the deleted scenario", first, second)
	}
}

// A closed incident of a scenario is never opened again: the next event of
// any of its honeytokens opens a new incident with a new alert.
func TestStore_ClosedIncidentOfAScenarioStaysClosed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	sc := f.scenario(t)
	a, _ := f.honeytoken(t, "web_url", nil)
	b, _ := f.honeytoken(t, "web_url", nil)
	f.scenarioEvent(t, a, sc)
	first := f.process(t)
	f.exec(t, "UPDATE incidents SET status = 'closed' WHERE id = $1", first.IncidentID)

	f.scenarioEvent(t, b, sc)
	p := f.process(t)
	if !p.Opened || p.IncidentID == first.IncidentID || p.ResourceID != sc {
		t.Errorf("event after closing = %+v, want a new incident of the scenario", p)
	}
	if got := f.incident(t, first.IncidentID); got.status != StatusClosed || got.count != 1 {
		t.Errorf("closed incident = %+v, want closed with its one event", got)
	}
	if n := f.count(t, "SELECT count(*) FROM alerts"); n != 2 {
		t.Errorf("%d alerts, want one per incident", n)
	}
}

// A worker that processes an event of one honeytoken of a scenario while
// another worker has opened the incident of the scenario for another
// honeytoken, but not yet committed, waits for it and joins that incident
// instead of opening a second one. The other transaction stands for that
// worker; the test waits until the worker blocks on it, so it depends on no
// timing.
func TestStore_ConcurrentEventsOfAScenarioOpenOneIncident(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	sc := f.scenario(t)
	other, _ := f.honeytoken(t, "web_url", nil)
	h, _ := f.honeytoken(t, "web_url", nil)
	eventID := f.scenarioEvent(t, h, sc)

	tx, err := f.owner.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	var opened string
	err = tx.QueryRow(t.Context(), `
INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at, resource_name)
VALUES ('scenario', $1, 'medium', now(), now(), 'Name') RETURNING id`, sc).Scan(&opened)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `
INSERT INTO events (resource_type, resource_id, scenario_id, honeytoken_type, severity, occurred_at, recorded_at, channel,
	method, incident_id, resource_name, scenario_name)
VALUES ('honeytoken', $1, $2, 'web_url', 'medium', now(), now(), 'http', 'GET', $3, 'Name', 'Scenario')`, other, sc, opened); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	var p Processed
	go func() {
		var err error
		p, _, err = f.store.ProcessNext(t.Context(), func() {})
		done <- err
	}()
	waitForLockWaiter(t, f.owner, done)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("ProcessNext() error = %v", err)
	}

	if p.Opened || p.IncidentID != opened || f.eventIncident(t, eventID) != opened {
		t.Errorf("ProcessNext() = %+v, want the event in the incident %s", p, opened)
	}
	if n := f.count(t, "SELECT count(*) FROM incidents WHERE status <> 'closed'"); n != 1 {
		t.Errorf("%d open incidents, want 1", n)
	}
}

// Workers that process many events of the honeytokens of a scenario side by
// side assign every event once, open one incident of the scenario and raise
// one alert.
func TestStore_ConcurrentWorkersOpenOneIncidentPerScenario(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	sc := f.scenario(t)
	honeytokens := make([]string, 4)
	for i := range honeytokens {
		honeytokens[i], _ = f.honeytoken(t, "web_url", nil)
	}
	const perHoneytoken = 8
	for range perHoneytoken {
		for _, h := range honeytokens {
			f.scenarioEvent(t, h, sc)
		}
	}

	const workers = 4
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		store := NewStore(schematest.Open(t, f.workerURL))
		wg.Go(func() {
			for {
				_, found, err := store.ProcessNext(t.Context(), func() {})
				if err != nil {
					errs <- err
					return
				}
				if !found {
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("ProcessNext() error = %v", err)
	}

	if n := f.count(t, "SELECT count(*) FROM events WHERE incident_id IS NULL"); n != 0 {
		t.Errorf("%d events without an incident", n)
	}
	if n := f.count(t, "SELECT count(*) FROM incidents WHERE resource_type = 'scenario' AND resource_id = $1 AND event_count = $2",
		sc, perHoneytoken*len(honeytokens)); n != 1 {
		t.Errorf("%d incidents of the scenario with every event, want 1", n)
	}
	if n := f.count(t, "SELECT count(*) FROM incidents"); n != 1 {
		t.Errorf("%d incidents, want 1", n)
	}
	if n := f.count(t, "SELECT count(*) FROM alerts"); n != 1 {
		t.Errorf("%d alerts, want 1", n)
	}
}

// The schema accepts every kind of resource that an incident correlates, as
// the code names them.
func TestResourceTypes_MatchTheSchema(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	for _, typ := range ResourceTypes {
		if _, err := f.owner.Exec(t.Context(), `
INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at, resource_name)
VALUES ($1, gen_random_uuid(), 'low', now(), now(), 'Name')`, typ); err != nil {
			t.Errorf("resource type %s: %v", typ, err)
		}
	}
	if _, err := f.owner.Exec(t.Context(), `
INSERT INTO incidents (resource_type, resource_id, severity, first_event_at, last_event_at, resource_name)
VALUES ('artifact', gen_random_uuid(), 'low', now(), now(), 'Name')`); err == nil {
		t.Error("the schema accepts incidents of artifacts, which raise no events")
	}
}
