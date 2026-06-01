// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"net/http"

	"github.com/PharosVPN/coxswain/internal/netpolicy"
)

// handleNetworkPolicyPreview returns the canonical PreUp/PostUp/PostDown rule
// set for a candidate policy, so the admin UI's advanced panel can show what
// buoy will apply as the operator toggles — before saving.
func (s *Server) handleNetworkPolicyPreview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Forwarding bool `json:"forwarding"`
		Masquerade bool `json:"masquerade"`
		Isolation  bool `json:"isolation"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
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
	writeJSON(w, http.StatusOK, policy.Rules())
}
