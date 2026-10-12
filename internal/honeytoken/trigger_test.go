// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package honeytoken

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

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
