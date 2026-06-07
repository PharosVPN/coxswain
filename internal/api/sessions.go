// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/PharosVPN/coxswain/internal/monitor"
)

// handleListSessions queries the persisted connection-event history (Phase B).
// Filters (all optional query params): device, user, node, source_ip, since
// (RFC3339), until (RFC3339), limit (default 100, capped at 1000). Newest-first.
// It is monitor-scoped — the same scope as the live /ws/events stream.
func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := monitor.Filter{
		DeviceID: q.Get("device"),
		UserID:   q.Get("user"),
		NodeID:   q.Get("node"),
		SourceIP: q.Get("source_ip"),
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid since (want RFC3339)")
			return
		}
		f.Since = t
	}
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid until (want RFC3339)")
			return
		}
		f.Until = t
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		f.Limit = n
	}

	records, err := monitor.Query(r.Context(), s.db, f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query sessions")
		return
	}
	if records == nil {
		records = []monitor.Record{}
	}
	writeJSON(w, http.StatusOK, records)
}
