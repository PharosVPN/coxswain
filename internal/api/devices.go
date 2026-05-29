// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/profile"
	"github.com/PharosVPN/coxswain/internal/provision"
)

// deviceView is the API representation of a device.
type deviceView struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Name      string    `json:"name"`
	Platform  string    `json:"platform"`
	Status    string    `json:"status"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

func toDeviceView(d account.Device) deviceView {
	return deviceView{
		ID: d.ID, UserID: d.UserID, Name: d.Name, Platform: d.Platform,
		Status: d.Status, Version: d.Version, CreatedAt: d.CreatedAt,
	}
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := account.ListDevicesByUser(r.Context(), s.db, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list devices")
		return
	}
	views := make([]deviceView, 0, len(devices))
	for _, d := range devices {
		views = append(views, toDeviceView(d))
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) handleCreateDevice(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if _, err := account.GetUser(r.Context(), s.db, userID); errors.Is(err, account.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create device")
		return
	}

	var req struct {
		Name     string `json:"name"`
		Platform string `json:"platform"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "device name is required")
		return
	}
	device, err := account.CreateDevice(r.Context(), s.db, account.Device{
		UserID: userID, Name: req.Name, Platform: req.Platform,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create device")
		return
	}
	writeJSON(w, http.StatusCreated, toDeviceView(device))
}

func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := fleet.DeletePeersByDevice(r.Context(), s.db, id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to remove device peers")
		return
	}
	err := account.DeleteDevice(r.Context(), s.db, id)
	if errors.Is(err, account.ErrNotFound) {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete device")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleProvisionDevice places a device on every ready node and issues it a
// freshly sealed profile.
func (s *Server) handleProvisionDevice(w http.ResponseWriter, r *http.Request) {
	res, err := provision.ProvisionDevice(r.Context(), s.db, r.PathValue("id"), s.provOpts)
	switch {
	case errors.Is(err, account.ErrNotFound):
		writeError(w, http.StatusNotFound, "device not found")
		return
	case errors.Is(err, profile.ErrNoEncryptionKey):
		writeError(w, http.StatusConflict, "the user has not enrolled an encryption key")
		return
	case errors.Is(err, fleet.ErrSubnetExhausted):
		writeError(w, http.StatusConflict, "the VPN subnet is exhausted")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "provisioning failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device_id":        res.Device.ID,
		"tunnel_ip":        res.TunnelIP,
		"peer_count":       res.PeerCount,
		"profile_revision": res.ProfileVersion,
	})
}
