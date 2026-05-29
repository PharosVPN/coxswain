// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package api is coxswain's localhost admin HTTP server: the JSON API behind the
// admin UI, the live-event WebSocket, and (from M5 phase B) the embedded
// SvelteKit SPA. coxswain opens no public ports — this binds to localhost.
package api

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/PharosVPN/coxswain/internal/live"
	"github.com/PharosVPN/coxswain/internal/provision"
)

const (
	// sessionCookie carries the opaque login session token.
	sessionCookie   = "cox_session"
	shutdownTimeout = 5 * time.Second
)

// Server is the admin HTTP server.
type Server struct {
	db       *sql.DB
	hub      *live.Hub
	provOpts provision.Options
	http     *http.Server
}

// NewServer builds the admin server bound to addr (a localhost address).
// provOpts carries the fleet settings device provisioning needs.
func NewServer(addr string, db *sql.DB, hub *live.Hub, provOpts provision.Options) *Server {
	s := &Server{db: db, hub: hub, provOpts: provOpts}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Auth — login is the only unauthenticated API route.
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", s.requireAuth(s.handleLogout))
	mux.HandleFunc("GET /api/auth/me", s.requireAuth(s.handleMe))

	// Fleet.
	mux.HandleFunc("GET /api/nodes", s.requireAuth(s.handleListNodes))
	mux.HandleFunc("GET /api/nodes/{id}", s.requireAuth(s.handleGetNode))
	mux.HandleFunc("PATCH /api/nodes/{id}", s.requireAuth(s.handleUpdateNode))
	mux.HandleFunc("DELETE /api/nodes/{id}", s.requireAuth(s.handleDeleteNode))
	mux.HandleFunc("POST /api/network-policy/preview", s.requireAuth(s.handleNetworkPolicyPreview))

	// Admins.
	mux.HandleFunc("GET /api/admins", s.requireAuth(s.handleListAdmins))
	mux.HandleFunc("POST /api/admins", s.requireAuth(s.handleCreateAdmin))
	mux.HandleFunc("DELETE /api/admins/{id}", s.requireAuth(s.handleDeleteAdmin))

	// End-user accounts.
	mux.HandleFunc("GET /api/users", s.requireAuth(s.handleListUsers))
	mux.HandleFunc("POST /api/users", s.requireAuth(s.handleCreateUser))
	mux.HandleFunc("DELETE /api/users/{id}", s.requireAuth(s.handleDeleteUser))

	// Devices and provisioning.
	mux.HandleFunc("GET /api/users/{id}/devices", s.requireAuth(s.handleListDevices))
	mux.HandleFunc("POST /api/users/{id}/devices", s.requireAuth(s.handleCreateDevice))
	mux.HandleFunc("DELETE /api/devices/{id}", s.requireAuth(s.handleDeleteDevice))
	mux.HandleFunc("POST /api/devices/{id}/provision", s.requireAuth(s.handleProvisionDevice))

	// Live events — auth-gated (closes the M4 gap).
	mux.HandleFunc("GET /ws/events", s.requireAuth(s.handleEvents))

	// Everything else — the embedded admin SPA (least-specific pattern).
	mux.Handle("GET /", spaHandler())

	s.http = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s
}

// Addr returns the configured listen address.
func (s *Server) Addr() string { return s.http.Addr }

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	errc := make(chan error, 1)
	go func() {
		err := s.http.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return s.http.Shutdown(shutCtx)
	}
}
