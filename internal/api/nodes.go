// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/netpolicy"
)

// nodeView is the API representation of a fleet node.
type nodeView struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Region       string    `json:"region"`
	Status       string    `json:"status"`
	PublicIP     string    `json:"public_ip"`
	SSHHost      string    `json:"ssh_host"`
	ControlAddr  string    `json:"control_addr"`
	AgentVersion string    `json:"agent_version"`
	Forwarding   bool      `json:"forwarding"`
	Masquerade   bool      `json:"masquerade"`
	Isolation    bool      `json:"isolation"`
	Version      int       `json:"version"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func toNodeView(n fleet.Node) nodeView {
	return nodeView{
		ID:           n.ID,
		Name:         n.Name,
		Region:       n.Region,
		Status:       n.Status,
		PublicIP:     n.PublicIP,
		SSHHost:      n.SSHHost,
		ControlAddr:  n.ControlAddr,
		AgentVersion: n.AgentVersion,
		Forwarding:   n.Forwarding,
		Masquerade:   n.Masquerade,
		Isolation:    n.Isolation,
		Version:      n.Version,
		CreatedAt:    n.CreatedAt,
		UpdatedAt:    n.UpdatedAt,
	}
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := fleet.ListNodes(r.Context(), s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list nodes")
		return
	}
	views := make([]nodeView, 0, len(nodes))
	for _, n := range nodes {
		views = append(views, toNodeView(n))
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	n, err := fleet.GetNode(r.Context(), s.db, r.PathValue("id"))
	if errors.Is(err, fleet.ErrNotFound) {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load node")
		return
	}
	writeJSON(w, http.StatusOK, toNodeView(n))
}

// handleUpdateNode updates a node's name and network policy under optimistic
// concurrency: the request must carry the version the admin loaded. A stale
// version yields 409.
func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Version    int    `json:"version"`
		Name       string `json:"name"`
		Forwarding bool   `json:"forwarding"`
		Masquerade bool   `json:"masquerade"`
		Isolation  bool   `json:"isolation"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	policy := netpolicy.Policy{
		Forwarding: req.Forwarding,
		Masquerade: req.Masquerade,
		Isolation:  req.Isolation,
	}
	if err := policy.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	node, err := fleet.GetNode(r.Context(), s.db, r.PathValue("id"))
	if errors.Is(err, fleet.ErrNotFound) {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load node")
		return
	}

	node.Name = req.Name
	node.Forwarding = req.Forwarding
	node.Masquerade = req.Masquerade
	node.Isolation = req.Isolation
	node.Version = req.Version // the version the admin loaded
	updated, err := fleet.UpdateNode(r.Context(), s.db, node)
	if errors.Is(err, fleet.ErrStaleVersion) {
		writeError(w, http.StatusConflict, "node was changed by someone else — reload and retry")
		return
	}
	if errors.Is(err, fleet.ErrNotFound) {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update node")
		return
	}
	writeJSON(w, http.StatusOK, toNodeView(updated))
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	err := fleet.DeleteNode(r.Context(), s.db, r.PathValue("id"))
	if errors.Is(err, fleet.ErrNotFound) {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete node")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
