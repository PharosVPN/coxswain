// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"net/http"

	"github.com/PharosVPN/coxswain/internal/fleet"
)

// linkView is the API representation of a cascade edge (entry → exit), so the
// map can draw the inner-link arc between the two nodes' pins.
type linkView struct {
	ID          string `json:"id"`
	EntryNodeID string `json:"entry_node_id"`
	ExitNodeID  string `json:"exit_node_id"`
	Status      string `json:"status"`
	Color       string `json:"color"`
}

func (s *Server) handleListNodeLinks(w http.ResponseWriter, r *http.Request) {
	links, err := fleet.ListNodeLinks(r.Context(), s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list node links")
		return
	}
	views := make([]linkView, 0, len(links))
	for _, l := range links {
		views = append(views, linkView{
			ID:          l.ID,
			EntryNodeID: l.EntryNodeID,
			ExitNodeID:  l.ExitNodeID,
			Status:      l.Status,
			Color:       l.Color,
		})
	}
	writeJSON(w, http.StatusOK, views)
}
