// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/geoip"
	"github.com/PharosVPN/coxswain/internal/netpolicy"
)

// nodeView is the API representation of a fleet node.
type nodeView struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Region       string          `json:"region"`
	Status       string          `json:"status"`
	PublicIP     string          `json:"public_ip"`
	SSHHost      string          `json:"ssh_host"`
	ControlAddr  string          `json:"control_addr"`
	AgentVersion string          `json:"agent_version"`
	EndpointIPs  []string        `json:"endpoint_ips"`
	Forwarding   bool            `json:"forwarding"`
	Masquerade   bool            `json:"masquerade"`
	Isolation    bool            `json:"isolation"`
	ServerID     string          `json:"server_id"`
	Location     *geoip.Location `json:"location,omitempty"`
	Version      int             `json:"version"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

func (s *Server) nodeView(n fleet.Node) nodeView {
	return nodeView{
		ID:           n.ID,
		Name:         n.Name,
		Region:       n.Region,
		Status:       n.Status,
		PublicIP:     n.PublicIP,
		SSHHost:      n.SSHHost,
		ControlAddr:  n.ControlAddr,
		AgentVersion: n.AgentVersion,
		EndpointIPs:  n.EndpointIPs,
		Forwarding:   n.Forwarding,
		Masquerade:   n.Masquerade,
		Isolation:    n.Isolation,
		ServerID:     n.ServerID,
		Location:     s.locate(n.PublicIP),
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
		views = append(views, s.nodeView(n))
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
	writeJSON(w, http.StatusOK, s.nodeView(n))
}

// handlePushNode reconciles a node — delivers coxswain's current peer set over
// the control plane (the Phase 2 PushNode primitive) — and returns the push
// result as JSON. This is the route the web UI uses to heal a node, which it
// could not do before Phase 2.
func (s *Server) handlePushNode(w http.ResponseWriter, r *http.Request) {
	if s.pusher == nil {
		writeError(w, http.StatusServiceUnavailable, "node push is not available on this server")
		return
	}
	id := r.PathValue("id")
	if _, err := fleet.GetNode(r.Context(), s.db, id); errors.Is(err, fleet.ErrNotFound) {
		writeError(w, http.StatusNotFound, "node not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load node")
		return
	}
	res, err := s.pusher(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusBadGateway, "push failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleUpdateNode updates a node's name and network policy under optimistic
// concurrency: the request must carry the version the admin loaded. A stale
// version yields 409.
func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Version     int      `json:"version"`
		Name        string   `json:"name"`
		Forwarding  bool     `json:"forwarding"`
		Masquerade  bool     `json:"masquerade"`
		Isolation   bool     `json:"isolation"`
		EndpointIPs []string `json:"endpoint_ips"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	endpoints, err := fleet.CleanEndpointIPs(req.EndpointIPs)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid endpoint IP: "+err.Error())
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
	node.EndpointIPs = endpoints
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
		s.audited(r, "node.update", "node", r.PathValue("id"), map[string]any{"name": req.Name}, err)
		writeError(w, http.StatusInternalServerError, "failed to update node")
		return
	}
	s.audited(r, "node.update", "node", updated.ID, map[string]any{"name": updated.Name}, nil)
	writeJSON(w, http.StatusOK, s.nodeView(updated))
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	// Block while clients route through this node — their profiles would break.
	// The admin re-routes (clear exit) / re-provisions them first.
	if n, err := fleet.CountClientsThroughNode(ctx, s.db, id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check node usage")
		return
	} else if n > 0 {
		writeError(w, http.StatusConflict, fmt.Sprintf("%d client(s) route through this node — re-route or re-provision them first", n))
		return
	}
	err := fleet.DeleteNode(ctx, s.db, id)
	if errors.Is(err, fleet.ErrNotFound) {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if err != nil {
		s.audited(r, "node.rm", "node", id, nil, err)
		writeError(w, http.StatusInternalServerError, "failed to delete node")
		return
	}
	s.audited(r, "node.rm", "node", id, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}
