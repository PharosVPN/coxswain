// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/PharosVPN/coxswain/internal/audit"
	"github.com/PharosVPN/coxswain/internal/authn"
)

// tokenView is the API representation of an API token — never the secret.
type tokenView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Scope      string     `json:"scope"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  string     `json:"created_by,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

func toTokenView(t authn.Token) tokenView {
	return tokenView{
		ID:         t.ID,
		Name:       t.Name,
		Scope:      string(t.Scope),
		Prefix:     t.Prefix,
		CreatedAt:  t.CreatedAt,
		CreatedBy:  t.CreatedBy,
		ExpiresAt:  t.ExpiresAt,
		LastUsedAt: t.LastUsedAt,
		RevokedAt:  t.RevokedAt,
	}
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := authn.List(r.Context(), s.db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list tokens")
		return
	}
	views := make([]tokenView, 0, len(tokens))
	for _, t := range tokens {
		views = append(views, toTokenView(t))
	}
	writeJSON(w, http.StatusOK, views)
}

// handleCreateToken mints a scoped API token and returns its plaintext secret
// exactly once. Body: {name, scope, expires}, where expires is a Go duration
// string (e.g. "720h"); empty/zero means no expiry.
func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor := audit.ActorFrom(ctx)
	var req struct {
		Name    string `json:"name"`
		Scope   string `json:"scope"`
		Expires string `json:"expires"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	scope, err := authn.ParseScope(req.Scope)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var ttl time.Duration
	if req.Expires != "" {
		ttl, err = time.ParseDuration(req.Expires)
		if err != nil || ttl < 0 {
			writeError(w, http.StatusBadRequest, "invalid expires duration")
			return
		}
	}

	secret, rec, err := authn.Create(ctx, s.db, req.Name, scope, ttl, actor.Name)
	if err != nil {
		_ = audit.Log(ctx, s.db, audit.Entry{
			Actor: actor.Name, ActorKind: actor.Kind, Action: "token.create",
			TargetType: "token", SourceIP: audit.SourceIP(r),
			Detail: map[string]any{"name": req.Name, "scope": req.Scope}, Err: err,
		})
		writeError(w, http.StatusInternalServerError, "failed to create token")
		return
	}
	_ = audit.Log(ctx, s.db, audit.Entry{
		Actor: actor.Name, ActorKind: actor.Kind, Action: "token.create",
		TargetType: "token", TargetID: rec.ID, SourceIP: audit.SourceIP(r),
		Detail: map[string]any{"name": rec.Name, "scope": string(rec.Scope)},
	})

	view := toTokenView(rec)
	writeJSON(w, http.StatusCreated, struct {
		tokenView
		Secret string `json:"secret"`
	}{tokenView: view, Secret: secret})
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor := audit.ActorFrom(ctx)
	id := r.PathValue("id")
	err := authn.Revoke(ctx, s.db, id)
	if errors.Is(err, authn.ErrNotFound) {
		writeError(w, http.StatusNotFound, "token not found")
		return
	}
	if err != nil {
		_ = audit.Log(ctx, s.db, audit.Entry{
			Actor: actor.Name, ActorKind: actor.Kind, Action: "token.revoke",
			TargetType: "token", TargetID: id, SourceIP: audit.SourceIP(r), Err: err,
		})
		writeError(w, http.StatusInternalServerError, "failed to revoke token")
		return
	}
	_ = audit.Log(ctx, s.db, audit.Entry{
		Actor: actor.Name, ActorKind: actor.Kind, Action: "token.revoke",
		TargetType: "token", TargetID: id, SourceIP: audit.SourceIP(r),
	})
	w.WriteHeader(http.StatusNoContent)
}
