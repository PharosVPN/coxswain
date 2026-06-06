// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/profile"
	"github.com/PharosVPN/coxswain/internal/provision"
)

// profileSpecView is the API representation of a profile (the admin-created
// connection config): a named egress (a node or a path), an optional entry-IP
// subset, and one data-plane protocol, for one (user, device).
type profileSpecView struct {
	ID       string   `json:"id"`
	UserID   string   `json:"user_id"`
	DeviceID string   `json:"device_id"`
	Name     string   `json:"name"`
	PathID   string   `json:"path_id,omitempty"`
	NodeID   string   `json:"node_id,omitempty"`
	EntryIPs []string `json:"entry_ips,omitempty"`
	Protocol string   `json:"protocol"`
	Version  int      `json:"version"`
}

func toProfileSpecView(s fleet.ProfileSpec) profileSpecView {
	return profileSpecView{
		ID:       s.ID,
		UserID:   s.UserID,
		DeviceID: s.DeviceID,
		Name:     s.Name,
		PathID:   s.PathID,
		NodeID:   s.NodeID,
		EntryIPs: s.EntryIPs,
		Protocol: s.Protocol,
		Version:  s.Version,
	}
}

// handleListProfileSpecs lists profiles, optionally filtered by ?device= or
// ?user=.
func (s *Server) handleListProfileSpecs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var (
		specs []fleet.ProfileSpec
		err   error
	)
	switch {
	case r.URL.Query().Get("device") != "":
		specs, err = fleet.ListProfileSpecsByDevice(ctx, s.db, r.URL.Query().Get("device"))
	case r.URL.Query().Get("user") != "":
		specs, err = fleet.ListProfileSpecsByUser(ctx, s.db, r.URL.Query().Get("user"))
	default:
		specs, err = fleet.ListProfileSpecs(ctx, s.db)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list profiles")
		return
	}
	views := make([]profileSpecView, 0, len(specs))
	for _, sp := range specs {
		views = append(views, toProfileSpecView(sp))
	}
	writeJSON(w, http.StatusOK, views)
}

// handleCreateProfileSpec creates a profile and re-provisions the device so its
// sealed bundle carries it. A device with no encryption key yet is not an error
// — the profile is saved and seals on the next sync/provision.
func (s *Server) handleCreateProfileSpec(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		UserID   string   `json:"user_id"`
		DeviceID string   `json:"device_id"`
		Name     string   `json:"name"`
		NodeID   string   `json:"node_id"`
		PathID   string   `json:"path_id"`
		EntryIPs []string `json:"entry_ips"`
		Protocol string   `json:"protocol"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Validate the egress exists (Validate already enforces exactly one).
	if req.NodeID != "" {
		if _, err := fleet.GetNode(ctx, s.db, req.NodeID); err != nil {
			writeError(w, http.StatusBadRequest, "no such node")
			return
		}
	}
	if req.PathID != "" {
		if _, err := fleet.GetPath(ctx, s.db, req.PathID); err != nil {
			writeError(w, http.StatusBadRequest, "no such path")
			return
		}
	}

	spec, err := fleet.CreateProfileSpec(ctx, s.db, fleet.ProfileSpec{
		UserID:   req.UserID,
		DeviceID: req.DeviceID,
		Name:     req.Name,
		NodeID:   req.NodeID,
		PathID:   req.PathID,
		EntryIPs: req.EntryIPs,
		Protocol: req.Protocol,
	})
	if errors.Is(err, fleet.ErrInvalidProfileSpec) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create profile failed")
		return
	}

	if err := s.reprovision(ctx, spec.DeviceID); err != nil {
		writeError(w, http.StatusBadGateway, "profile saved but re-provision failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, toProfileSpecView(spec))
}

// handleDeleteProfileSpec deletes a profile and re-provisions its device so the
// bundle drops the profile and its peer.
func (s *Server) handleDeleteProfileSpec(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	spec, err := fleet.GetProfileSpec(ctx, s.db, r.PathValue("id"))
	if errors.Is(err, fleet.ErrNotFound) {
		writeError(w, http.StatusNotFound, "profile not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load profile")
		return
	}
	if err := fleet.DeleteProfileSpec(ctx, s.db, spec.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "delete profile failed")
		return
	}
	if err := s.reprovision(ctx, spec.DeviceID); err != nil {
		writeError(w, http.StatusBadGateway, "profile deleted but re-provision failed: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// reprovision re-seals a device's bundle after a profile change. A device whose
// user has not enrolled an encryption key yet can't be sealed to — that's not an
// error here; the change applies on the next sync/provision.
func (s *Server) reprovision(ctx context.Context, deviceID string) error {
	_, err := provision.ProvisionDevice(ctx, s.db, deviceID, s.provOpts)
	if errors.Is(err, profile.ErrNoEncryptionKey) {
		return nil
	}
	return err
}
