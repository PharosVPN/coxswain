// SPDX-License-Identifier: Apache-2.0
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

	"github.com/PharosVPN/coxswain/internal/geoip"
	"github.com/PharosVPN/coxswain/internal/live"
	"github.com/PharosVPN/coxswain/internal/provision"
)

const (
	// sessionCookie carries the opaque login session token.
	sessionCookie   = "cox_session"
	shutdownTimeout = 5 * time.Second
)

// NodePusher delivers coxswain's current peer set to one node over the control
// plane (the Phase 2 PushNode primitive), returning a JSON-encodable result. The
// cli package supplies the concrete implementation (it owns the config + routed
// dialers); a nil pusher disables the reconcile route. It is also called
// best-effort after a device (re)provision to deliver changes immediately.
type NodePusher func(ctx context.Context, nodeID string) (any, error)

// Server is the admin HTTP server.
type Server struct {
	db             *sql.DB
	hub            *live.Hub
	provOpts       provision.Options
	deployer       Deployer
	paths          PathCoordinator
	geo            *geoip.Resolver
	controllerHost string
	pusher         NodePusher
	http           *http.Server
}

// SetNodePusher wires the node-push primitive used by the reconcile route and
// push-on-provision. Call it before Run. A nil pusher leaves those best-effort
// (provision still succeeds; the sweep heals) and the push route returns 503.
func (s *Server) SetNodePusher(p NodePusher) { s.pusher = p }

// NewServer builds the admin server bound to addr (a localhost address).
// provOpts carries the fleet settings device provisioning needs; deployer
// performs server onboarding and component deploys (nil disables those routes);
// paths provisions/binds data-plane paths over the node control plane (nil
// disables those routes); geo resolves host IPs to locations for the map (nil
// disables resolution); controllerHost is the controller's own public IP (for
// plotting it on the map; empty when undetected).
func NewServer(addr string, db *sql.DB, hub *live.Hub, provOpts provision.Options, deployer Deployer, paths PathCoordinator, geo *geoip.Resolver, controllerHost string) *Server {
	s := &Server{db: db, hub: hub, provOpts: provOpts, deployer: deployer, paths: paths, geo: geo, controllerHost: controllerHost}
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
	// Reconcile a node — deliver coxswain's current peer set (the Phase 2 push
	// primitive), so the web UI can heal a node, which it could not do before.
	mux.HandleFunc("POST /api/nodes/{id}/push", s.requireAuth(s.handlePushNode))
	mux.HandleFunc("POST /api/network-policy/preview", s.requireAuth(s.handleNetworkPolicyPreview))

	// Relays — relays in the egress / onion chain (for the fleet map's roles).
	mux.HandleFunc("GET /api/relays", s.requireAuth(s.handleListRelays))
	// Cascade edges — entry→exit inner links (for the map's route arcs).
	mux.HandleFunc("GET /api/node-links", s.requireAuth(s.handleListNodeLinks))

	// Data-plane paths — named multi-hop chains entry → [mid] → exit.
	mux.HandleFunc("GET /api/paths", s.requireAuth(s.handleListPaths))
	mux.HandleFunc("POST /api/paths", s.requireAuth(s.handleCreatePath))
	mux.HandleFunc("DELETE /api/paths/{id}", s.requireAuth(s.handleDeletePath))
	mux.HandleFunc("POST /api/paths/{id}/provision", s.requireAuth(s.handleProvisionPath))

	// The controller itself — its public IP + resolved location, for the map.
	mux.HandleFunc("GET /api/self", s.requireAuth(s.handleSelf))

	// Servers — machines cox owns; onboard by key or password, then deploy roles.
	mux.HandleFunc("GET /api/ssh-key", s.requireAuth(s.handleSSHKey))
	mux.HandleFunc("GET /api/servers", s.requireAuth(s.handleListServers))
	mux.HandleFunc("POST /api/servers", s.requireAuth(s.handleCreateServer))
	mux.HandleFunc("DELETE /api/servers/{id}", s.requireAuth(s.handleDeleteServer))
	mux.HandleFunc("POST /api/servers/{id}/deploy", s.requireAuth(s.handleDeployServer))
	mux.HandleFunc("PATCH /api/servers/{id}/route", s.requireAuth(s.handleSetServerRoute))

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
	// Bind a device's traffic onto a data-plane path (the live switch), or clear it.
	mux.HandleFunc("POST /api/devices/{id}/bind", s.requireAuth(s.handleBindDevice))
	mux.HandleFunc("DELETE /api/devices/{id}/bind", s.requireAuth(s.handleClearDevice))

	// Profiles — a device's named connection configs (egress + entry IPs + protocol).
	mux.HandleFunc("GET /api/profiles", s.requireAuth(s.handleListProfileSpecs))
	mux.HandleFunc("POST /api/profiles", s.requireAuth(s.handleCreateProfileSpec))
	mux.HandleFunc("DELETE /api/profiles/{id}", s.requireAuth(s.handleDeleteProfileSpec))

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
