// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"errors"
	"net/http"

	"github.com/PharosVPN/coxswain/internal/fleet"
)

// controlPathView is the API representation of a control-plane path: the
// fleet-wide route coxswain dials out through to reach every node. Exactly one
// is active at a time.
type controlPathView struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Hops    []string `json:"hops"`
	Active  bool     `json:"active"`
	Version int      `json:"version"`
}

func controlPathViewOf(c fleet.ControlPath) controlPathView {
	hops := c.Hops
	if hops == nil {
		hops = []string{}
	}
	return controlPathView{ID: c.ID, Name: c.Name, Hops: hops, Active: c.Active, Version: c.Version}
}

func (s *Server) handleListControlPaths(w http.ResponseWriter, r *http.Request) {
	paths, err := fleet.ListControlPaths(r.Context(), s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list control paths")
		return
	}
	views := make([]controlPathView, 0, len(paths))
	for _, p := range paths {
		views = append(views, controlPathViewOf(p))
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) handleCreateControlPath(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string   `json:"name"`
		Hops []string `json:"hops"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	// Every hop must resolve to a known relay — a control path can't route through
	// a relay that doesn't exist.
	for _, id := range req.Hops {
		if _, err := fleet.GetRelay(r.Context(), s.db, id); errors.Is(err, fleet.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "unknown relay in hops: "+id)
			return
		} else if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to validate hops")
			return
		}
	}
	cp, err := fleet.CreateControlPath(r.Context(), s.db, fleet.ControlPath{Name: req.Name, Hops: req.Hops})
	if err != nil {
		s.audited(r, "control_path.add", "control_path", "", map[string]any{"name": req.Name}, err)
		writeError(w, http.StatusInternalServerError, "failed to create control path")
		return
	}
	s.audited(r, "control_path.add", "control_path", cp.ID, map[string]any{"name": cp.Name, "hops": cp.Hops}, nil)
	writeJSON(w, http.StatusCreated, controlPathViewOf(cp))
}

// handleActivateControlPath makes a control path the single fleet-wide active
// route — the live swap that reroutes the whole control plane.
func (s *Server) handleActivateControlPath(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := fleet.SetActiveControlPath(r.Context(), s.db, id)
	if errors.Is(err, fleet.ErrNotFound) {
		writeError(w, http.StatusNotFound, "control path not found")
		return
	}
	if err != nil {
		s.audited(r, "control_path.activate", "control_path", id, nil, err)
		writeError(w, http.StatusInternalServerError, "failed to activate control path")
		return
	}
	cp, err := fleet.GetControlPath(r.Context(), s.db, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reload control path")
		return
	}
	s.audited(r, "control_path.activate", "control_path", id, map[string]any{"name": cp.Name}, nil)
	writeJSON(w, http.StatusOK, controlPathViewOf(cp))
}

func (s *Server) handleDeleteControlPath(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := fleet.DeleteControlPath(r.Context(), s.db, id)
	if errors.Is(err, fleet.ErrNotFound) {
		writeError(w, http.StatusNotFound, "control path not found")
		return
	}
	if err != nil {
		s.audited(r, "control_path.rm", "control_path", id, nil, err)
		writeError(w, http.StatusInternalServerError, "failed to delete control path")
		return
	}
	s.audited(r, "control_path.rm", "control_path", id, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}
