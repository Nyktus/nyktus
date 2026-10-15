// SPDX-FileCopyrightText: The Nyktus Authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package alertingapi

import (
	"errors"
	"net/http"
	"time"

	"nyktus.org/nyktus/internal/alerting"
	"nyktus.org/nyktus/internal/auth/access"
	"nyktus.org/nyktus/internal/platform/httpx"
)

// Error codes of the deliveries.
const (
	codeTestPending = "test_pending"
	codeNotDead     = "delivery_not_dead"
)

// deliveryResponse is the representation of a delivery. It holds the class of
// a failure and the status code of a response, never the response or the
// error itself, which could name the URL of the channel.
type deliveryResponse struct {
	ID             string            `json:"id"`
	IncidentID     *string           `json:"incident_id"`
	ChannelID      string            `json:"channel_id"`
	ChannelType    alerting.Type     `json:"channel_type"`
	ChannelName    string            `json:"channel_name"`
	Status         alerting.Status   `json:"status"`
	Attempts       int               `json:"attempts"`
	NextAttemptAt  *time.Time        `json:"next_attempt_at"`
	LastAttemptAt  *time.Time        `json:"last_attempt_at"`
	LastStatusCode *int              `json:"last_status_code"`
	LastError      *alerting.Failure `json:"last_error"`
	LastDurationMs *int              `json:"last_duration_ms"`
	DeliveredAt    *time.Time        `json:"delivered_at"`
	CreatedAt      time.Time         `json:"created_at"`
}

func newDeliveryResponse(d alerting.Delivery) deliveryResponse {
	var next *time.Time
	if d.Status == alerting.StatusPending {
		next = &d.NotBefore
	}
	return deliveryResponse{
		ID: d.ID, IncidentID: d.AlertID, ChannelID: d.ChannelID, ChannelType: d.ChannelType, ChannelName: d.ChannelName,
		Status: d.Status, Attempts: d.Attempts, NextAttemptAt: next, LastAttemptAt: d.LastAttemptAt,
		LastStatusCode: d.LastStatusCode, LastError: d.LastError, LastDurationMs: d.LastDurationMs,
		DeliveredAt: d.DeliveredAt, CreatedAt: d.CreatedAt,
	}
}

type deliveryListResponse struct {
	Deliveries []deliveryResponse `json:"deliveries"`
}

// Test handles POST /api/v1/alert-channels/{id}/test. The worker sends the
// test; the response names the delivery, whose outcome the caller reads later.
// Nothing about the target is answered here, so the route reveals nothing
// about the network.
func (h *Handler) Test(w http.ResponseWriter, r *http.Request) {
	p, ok := h.sessionPrincipal(w, r, "alerting: test channel")
	if !ok {
		return
	}
	d, err := alerting.RecordTest(r.Context(), h.db, p.Actor(), r.PathValue("id"))
	switch {
	case errors.Is(err, alerting.ErrTestPending):
		httpx.WriteError(w, r, http.StatusConflict, codeTestPending, "a test of this alert channel waits for the worker")
		return
	case err != nil:
		h.writeError(w, r, "alerting: test channel", err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, newDeliveryResponse(d))
}

// GetDelivery handles GET /api/v1/alert-deliveries/{id}.
func (h *Handler) GetDelivery(w http.ResponseWriter, r *http.Request) {
	d, err := alerting.GetDelivery(r.Context(), h.db, r.PathValue("id"))
	if errors.Is(err, alerting.ErrDeliveryNotFound) {
		httpx.NotFound(w, r)
		return
	}
	if err != nil {
		httpx.ServerError(w, r, h.logger, "alerting: get delivery", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, newDeliveryResponse(d))
}

// RetryDelivery handles POST /api/v1/alert-deliveries/{id}/retry.
func (h *Handler) RetryDelivery(w http.ResponseWriter, r *http.Request) {
	p, ok := h.sessionPrincipal(w, r, "alerting: retry delivery")
	if !ok {
		return
	}
	d, err := alerting.RecordRetry(r.Context(), h.db, p.Actor(), r.PathValue("id"))
	switch {
	case errors.Is(err, alerting.ErrDeliveryNotFound):
		httpx.NotFound(w, r)
	case errors.Is(err, alerting.ErrNotDead):
		httpx.WriteError(w, r, http.StatusConflict, codeNotDead, "only a dead delivery of an alert can be retried")
	case err != nil:
		httpx.ServerError(w, r, h.logger, "alerting: retry delivery", err)
	default:
		httpx.WriteJSON(w, http.StatusOK, newDeliveryResponse(d))
	}
}

// IncidentDeliveries handles GET /api/v1/incidents/{id}/deliveries. Every reader
// of incidents may see whether their alerts were delivered.
func (h *Handler) IncidentDeliveries(w http.ResponseWriter, r *http.Request) {
	if _, ok := access.PrincipalFrom(r.Context()); !ok {
		httpx.ServerError(w, r, h.logger, "alerting: list deliveries", errors.New("no principal in the request context"))
		return
	}
	list, err := alerting.IncidentDeliveries(r.Context(), h.db, r.PathValue("id"))
	if errors.Is(err, alerting.ErrIncidentNotFound) {
		httpx.NotFound(w, r)
		return
	}
	if err != nil {
		httpx.ServerError(w, r, h.logger, "alerting: list deliveries", err)
		return
	}
	resp := deliveryListResponse{Deliveries: make([]deliveryResponse, 0, len(list))}
	for _, d := range list {
		resp.Deliveries = append(resp.Deliveries, newDeliveryResponse(d))
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}
