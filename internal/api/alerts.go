// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/PharosVPN/coxswain/internal/analytics"
)

// alertsEnvelope wraps the alerts list with engine status, so a caller learns
// about the backend-suitability warning without a second request. backend is the
// state-store kind; backend_warning is non-empty only on SQLite.
type alertsEnvelope struct {
	Alerts         []analytics.Alert `json:"alerts"`
	Backend        string            `json:"backend"`
	BackendWarning string            `json:"backend_warning,omitempty"`
}

// handleListAlerts queries the analytics alerts (Phase C). Filters (all optional
// query params): status, kind, device, severity, since (RFC3339), limit (default
// 100, capped at 1000). Newest-first. Monitor-scoped — the same scope as the
// session history and the live stream. The response envelope carries the
// backend-suitability warning (non-empty on SQLite).
func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := analytics.Filter{
		Status:   q.Get("status"),
		Kind:     q.Get("kind"),
		DeviceID: q.Get("device"),
		Severity: q.Get("severity"),
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid since (want RFC3339)")
			return
		}
		f.Since = t
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		f.Limit = n
	}

	alerts, err := analytics.Query(r.Context(), s.db, f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query alerts")
		return
	}
	if alerts == nil {
		alerts = []analytics.Alert{}
	}
	writeJSON(w, http.StatusOK, alertsEnvelope{
		Alerts:         alerts,
		Backend:        s.backend,
		BackendWarning: analytics.BackendWarning(s.backend),
	})
}

// handleAnalyticsStatus reports the engine's backend and any suitability
// warning, separately from the alerts list. Monitor-scoped.
func (s *Server) handleAnalyticsStatus(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{
		"backend":         s.backend,
		"backend_warning": analytics.BackendWarning(s.backend),
	}
	// Surface silent ingest loss: a full history queue sheds events rather than
	// blocking the live stream, so without this the loss is invisible.
	if s.drops != nil {
		out["events_dropped"] = s.drops.Dropped()
	}
	writeJSON(w, http.StatusOK, out)
}

// handleAckAlert sets an alert to acknowledged. Admin-scoped; writes an audit row.
func (s *Server) handleAckAlert(w http.ResponseWriter, r *http.Request) {
	s.setAlertStatus(w, r, analytics.StatusAcknowledged, "alert.ack")
}

// handleResolveAlert sets an alert to resolved. Admin-scoped; writes an audit row.
func (s *Server) handleResolveAlert(w http.ResponseWriter, r *http.Request) {
	s.setAlertStatus(w, r, analytics.StatusResolved, "alert.resolve")
}

// setAlertStatus transitions an alert's status and audits the mutation. A
// missing alert is a 404; the audit row records success or failure either way.
func (s *Server) setAlertStatus(w http.ResponseWriter, r *http.Request, status, action string) {
	id := r.PathValue("id")
	err := analytics.SetStatus(r.Context(), s.db, id, status, time.Now().UTC())
	if errors.Is(err, sql.ErrNoRows) {
		s.audited(r, action, "alert", id, nil, err)
		writeError(w, http.StatusNotFound, "alert not found")
		return
	}
	if err != nil {
		s.audited(r, action, "alert", id, nil, err)
		writeError(w, http.StatusInternalServerError, "failed to update alert")
		return
	}
	s.audited(r, action, "alert", id, map[string]any{"status": status}, nil)

	alert, err := analytics.Get(r.Context(), s.db, id)
	if err != nil {
		// The update succeeded; just echo the id/status if the re-read fails.
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": status})
		return
	}
	writeJSON(w, http.StatusOK, alert)
}
