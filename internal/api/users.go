// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"errors"
	"net/http"

	"github.com/PharosVPN/coxswain/internal/account"
	"github.com/PharosVPN/coxswain/internal/auth"
)

// handleListUsers lists end-user accounts (role "user"). Admins are listed
// separately by /api/admins.
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := account.ListUsersByRole(r.Context(), s.db, account.RoleUser)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	views := make([]userView, 0, len(users))
	for _, u := range users {
		views = append(views, toUserView(u))
	}
	writeJSON(w, http.StatusOK, views)
}

// handleCreateUser creates an end-user account. The user enrols their own E2E
// encryption key later, from their passphrase (DESIGN §8).
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}
	if len(req.Password) < minPasswordLen {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}
	user, err := account.CreateUser(r.Context(), s.db, account.User{
		Email:        req.Email,
		Role:         account.RoleUser,
		PasswordHash: hash,
	})
	if errors.Is(err, account.ErrEmailTaken) {
		writeError(w, http.StatusConflict, "email already in use")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}
	writeJSON(w, http.StatusCreated, toUserView(user))
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	err := account.DeleteUser(r.Context(), s.db, r.PathValue("id"))
	if errors.Is(err, account.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete user")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
