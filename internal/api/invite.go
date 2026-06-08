// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/enroll"
	"github.com/PharosVPN/coxswain/internal/pki"
)

// handleInviteUser issues a one-time device-enrollment invite for a user: a
// join-link (pharosvpn://enroll?…) plus a QR PNG the user scans with caravel to
// enrol a device through ClaimEnrollment. Admin-scoped and audited (enroll.invite).
func (s *Server) handleInviteUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if _, err := account.GetUser(r.Context(), s.db, userID); errors.Is(err, account.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue invite")
		return
	}

	if s.relayEndpoint == "" {
		writeError(w, http.StatusConflict, "no relay endpoint configured — set relay.public_endpoint")
		return
	}

	bundle, _, err := pki.EnsureCA(r.Context(), s.db)
	if err != nil {
		s.audited(r, "enroll.invite", "user", userID, nil, err)
		writeError(w, http.StatusInternalServerError, "failed to load CA")
		return
	}

	ticket, token, err := enroll.IssueTicket(r.Context(), s.db, userID)
	if err != nil {
		s.audited(r, "enroll.invite", "user", userID, nil, err)
		writeError(w, http.StatusInternalServerError, "failed to issue invite")
		return
	}
	s.audited(r, "enroll.invite", "ticket", ticket.ID, map[string]any{"user_id": userID}, nil)

	link := enroll.TicketURL(s.relayEndpoint, token, bundle.Root.Fingerprint())
	png, err := enroll.QRCode(link)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to render QR")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"url":           link,
		"qr_png_base64": base64.StdEncoding.EncodeToString(png),
		"expires_at":    ticket.ExpiresAt.UTC().Format(time.RFC3339),
		"ticket_id":     ticket.ID,
	})
}
