// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/PharosVPN/coxswain/internal/fleet"
)

// PathCoordinator provisions and tears down data-plane paths and binds devices
// onto them over the node control plane. *cascade.Coordinator satisfies it; the
// CLI/serve layer injects it (the api package deliberately doesn't import the
// control dialer). A nil coordinator disables the provisioning/bind routes.
type PathCoordinator interface {
	ProvisionPath(ctx context.Context, pathID string) (fleet.Path, error)
	DeprovisionPath(ctx context.Context, pathID string) error
	BindDeviceToPath(ctx context.Context, deviceID, pathID string) error
	ClearDevicePath(ctx context.Context, deviceID string) error
}

// pathView is the API representation of a data-plane path: its ordered hops (a
// list of node ids, entry first) plus its name, colour, and status.
type pathView struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Color   string   `json:"color"`
	Status  string   `json:"status"`
	Hops    []string `json:"hops"`
	Version int      `json:"version"`
}

func (s *Server) pathView(ctx context.Context, p fleet.Path) (pathView, error) {
	hops, err := fleet.ListPathHops(ctx, s.db, p.ID)
	if err != nil {
		return pathView{}, err
	}
	ids := make([]string, len(hops))
	for i, h := range hops {
		ids[i] = h.NodeID
	}
	return pathView{
		ID:      p.ID,
		Name:    p.Name,
		Color:   p.Color,
		Status:  p.Status,
		Hops:    ids,
		Version: p.Version,
	}, nil
}

func (s *Server) handleListPaths(w http.ResponseWriter, r *http.Request) {
	paths, err := fleet.ListPaths(r.Context(), s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list paths")
		return
	}
	views := make([]pathView, 0, len(paths))
	for _, p := range paths {
		v, err := s.pathView(r.Context(), p)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load path hops")
			return
		}
		views = append(views, v)
	}
	writeJSON(w, http.StatusOK, views)
}

// handleCreatePath defines a path and provisions its inner-link chain in one
// step. If provisioning fails (a node unreachable, MTU floor, …) the half-built
// path is torn back down so the call is atomic.
func (s *Server) handleCreatePath(w http.ResponseWriter, r *http.Request) {
	if s.paths == nil {
		writeError(w, http.StatusServiceUnavailable, "path provisioning unavailable")
		return
	}
	var req struct {
		Name    string   `json:"name"`
		Color   string   `json:"color"`
		NodeIDs []string `json:"node_ids"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	p, err := fleet.CreatePath(r.Context(), s.db, req.Name, req.Color, req.NodeIDs)
	if errors.Is(err, fleet.ErrInvalidPath) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "create path failed: "+err.Error())
		return
	}

	provisioned, err := s.paths.ProvisionPath(r.Context(), p.ID)
	if err != nil {
		// Roll back: clean up any partial inner-link config, then drop the row.
		_ = s.paths.DeprovisionPath(r.Context(), p.ID)
		_ = fleet.DeletePath(r.Context(), s.db, p.ID)
		s.audited(r, "path.create", "path", p.ID, map[string]any{"name": req.Name, "hops": req.NodeIDs}, err)
		writeError(w, http.StatusBadGateway, "provision path failed: "+err.Error())
		return
	}
	s.audited(r, "path.create", "path", provisioned.ID, map[string]any{"name": provisioned.Name, "hops": req.NodeIDs}, nil)
	view, err := s.pathView(r.Context(), provisioned)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load path")
		return
	}
	writeJSON(w, http.StatusCreated, view)
}

// handleProvisionPath re-applies a path's inner-link chain (idempotent heal).
func (s *Server) handleProvisionPath(w http.ResponseWriter, r *http.Request) {
	if s.paths == nil {
		writeError(w, http.StatusServiceUnavailable, "path provisioning unavailable")
		return
	}
	p, err := s.paths.ProvisionPath(r.Context(), r.PathValue("id"))
	if errors.Is(err, fleet.ErrNotFound) {
		writeError(w, http.StatusNotFound, "path not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, "provision path failed: "+err.Error())
		return
	}
	view, err := s.pathView(r.Context(), p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load path")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// handleDeletePath tears a path down. It is blocked while any client is bound to
// it (the data-plane-safe block: the admin re-binds those clients to another
// path first, so no profile silently changes its route).
func (s *Server) handleDeletePath(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	// The 404 / data-plane-safe 409 are pure DB checks and answer regardless of
	// whether provisioning is available; only the teardown itself needs it.
	if _, err := fleet.GetPath(ctx, s.db, id); errors.Is(err, fleet.ErrNotFound) {
		writeError(w, http.StatusNotFound, "path not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load path")
		return
	}
	bound, err := fleet.ListDeviceIDsByPath(ctx, s.db, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check path usage")
		return
	}
	if len(bound) > 0 {
		writeError(w, http.StatusConflict, fmt.Sprintf("%d client(s) are bound to this path — re-bind them first", len(bound)))
		return
	}
	if s.paths == nil {
		writeError(w, http.StatusServiceUnavailable, "path provisioning unavailable")
		return
	}
	if err := s.paths.DeprovisionPath(ctx, id); err != nil {
		s.audited(r, "path.rm", "path", id, nil, err)
		writeError(w, http.StatusBadGateway, "remove path failed: "+err.Error())
		return
	}
	s.audited(r, "path.rm", "path", id, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleBindDevice binds a device's traffic onto a path (the live switch).
func (s *Server) handleBindDevice(w http.ResponseWriter, r *http.Request) {
	if s.paths == nil {
		writeError(w, http.StatusServiceUnavailable, "path provisioning unavailable")
		return
	}
	var req struct {
		PathID string `json:"path_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.PathID == "" {
		writeError(w, http.StatusBadRequest, "path_id is required")
		return
	}
	deviceID := r.PathValue("id")
	if err := s.paths.BindDeviceToPath(r.Context(), deviceID, req.PathID); err != nil {
		s.audited(r, "path.bind", "device", deviceID, map[string]any{"path_id": req.PathID}, err)
		writeError(w, http.StatusBadGateway, "bind device failed: "+err.Error())
		return
	}
	s.audited(r, "path.bind", "device", deviceID, map[string]any{"path_id": req.PathID}, nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleClearDevice removes a device's path binding (back to normal egress).
func (s *Server) handleClearDevice(w http.ResponseWriter, r *http.Request) {
	if s.paths == nil {
		writeError(w, http.StatusServiceUnavailable, "path provisioning unavailable")
		return
	}
	deviceID := r.PathValue("id")
	if err := s.paths.ClearDevicePath(r.Context(), deviceID); err != nil {
		s.audited(r, "path.unbind", "device", deviceID, nil, err)
		writeError(w, http.StatusBadGateway, "clear device binding failed: "+err.Error())
		return
	}
	s.audited(r, "path.unbind", "device", deviceID, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}
