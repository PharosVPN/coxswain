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

	"github.com/PharosVPN/coxswain/internal/agentver"
	"github.com/PharosVPN/coxswain/internal/authn"
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
	db              *sql.DB
	hub             *live.Hub
	provOpts        provision.Options
	deployer        Deployer
	paths           PathCoordinator
	geo             *geoip.Resolver
	controllerHost  string
	pusher          NodePusher
	backend         string          // state-store kind ("sqlite"|"postgres"); drives the analytics warning
	drops           DropCounter     // ingest-loss counter surfaced by /api/analytics/status (nil = unknown)
	siemDrops       SIEMDropCounter // SIEM slow-consumer drop counter (nil = listener disabled)
	behindTLSProxy  bool            // trust X-Forwarded-Proto for the cookie Secure attribute
	relayEndpoint   string          // public relay endpoint baked into enrollment invites (empty = invites disabled)
	nodeBinaryPath  string          // configured node.binary_path — the candidate the "available" node version is read from (empty = unknown)
	relayBinaryPath string          // configured relay.binary_path — the candidate the "available" relay version is read from (empty = unknown)
	http            *http.Server
}

// SetAgentBinaries records the configured candidate binary paths
// (node.binary_path / relay.binary_path) so the components API can report each
// agent's available version and whether an update is offered. Call before Run;
// an empty path leaves that component's available version unknown (no Update
// prompt). The files are read on demand, so swapping a binary on disk is picked
// up without restarting coxswain.
func (s *Server) SetAgentBinaries(nodePath, relayPath string) {
	s.nodeBinaryPath, s.relayBinaryPath = nodePath, relayPath
}

// availableNodeVersion / availableRelayVersion read the configured candidate
// binary's build version (or "" when none is configured / unreadable).
func (s *Server) availableNodeVersion() string  { return agentver.FromFile(s.nodeBinaryPath) }
func (s *Server) availableRelayVersion() string { return agentver.FromFile(s.relayBinaryPath) }

// SetRelayEndpoint records the public relay endpoint enrollment invites embed in
// their join-link/QR (the address the claimed device syncs through). Call before
// Run; empty leaves the invite route returning 409 (no relay configured).
func (s *Server) SetRelayEndpoint(ep string) { s.relayEndpoint = ep }

// DropCounter reports how many connection events were shed because the history
// ingest queue fell behind. *monitor.Store satisfies it. The analytics status
// endpoint surfaces this so silent ingest loss is observable from the UI.
type DropCounter interface {
	Dropped() uint64
}

// SetDropCounter wires the history store's ingest-loss counter into the
// analytics status endpoint. Call before Run; nil leaves the count absent.
func (s *Server) SetDropCounter(d DropCounter) { s.drops = d }

// SIEMDropCounter reports how many events the SIEM gRPC listener shed because a
// slow consumer fell behind. *siem.Listener satisfies it. The analytics status
// endpoint surfaces this so a SIEM integration's silent loss is observable.
type SIEMDropCounter interface {
	Dropped() int64
}

// SetSIEMDropCounter wires the SIEM listener's slow-consumer drop counter into
// the analytics status endpoint. Call before Run; nil (the listener is disabled)
// leaves siem_events_dropped reported as 0.
func (s *Server) SetSIEMDropCounter(d SIEMDropCounter) { s.siemDrops = d }

// SetBehindTLSProxy declares that a trusted TLS-terminating reverse proxy fronts
// the UI, so the session cookie's Secure attribute may be derived from the
// X-Forwarded-Proto header. Call before Run; unset (the default) trusts only the
// request's own TLS state, so a spoofed header can never flip cookie security.
func (s *Server) SetBehindTLSProxy(v bool) { s.behindTLSProxy = v }

// SetBackend records the state-store backend kind so the analytics alerts
// endpoints can surface the backend-suitability warning. Call before Run;
// unset defaults to SQLite (the historical backend).
func (s *Server) SetBackend(kind string) { s.backend = kind }

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
	s := &Server{db: db, hub: hub, provOpts: provOpts, deployer: deployer, paths: paths, geo: geo, controllerHost: controllerHost, backend: "sqlite"}
	mux := http.NewServeMux()

	// Scope helpers: GET reads require readonly; the live/monitoring stream
	// requires monitor+; mutations require admin. A session admin satisfies any
	// scope (the existing behaviour), so the web UI is unaffected.
	readonly := func(h http.HandlerFunc) http.HandlerFunc { return s.requireScope(authn.ScopeReadonly, h) }
	monitor := func(h http.HandlerFunc) http.HandlerFunc { return s.requireScope(authn.ScopeMonitor, h) }
	admin := func(h http.HandlerFunc) http.HandlerFunc { return s.requireScope(authn.ScopeAdmin, h) }

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Auth — login is the only unauthenticated API route.
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", readonly(s.handleLogout))
	mux.HandleFunc("GET /api/auth/me", readonly(s.handleMe))

	// Fleet.
	mux.HandleFunc("GET /api/nodes", readonly(s.handleListNodes))
	mux.HandleFunc("GET /api/nodes/{id}", readonly(s.handleGetNode))
	mux.HandleFunc("PATCH /api/nodes/{id}", admin(s.handleUpdateNode))
	mux.HandleFunc("DELETE /api/nodes/{id}", admin(s.handleDeleteNode))
	// Reconcile a node — deliver coxswain's current peer set (the Phase 2 push
	// primitive), so the web UI can heal a node, which it could not do before.
	mux.HandleFunc("POST /api/nodes/{id}/push", admin(s.handlePushNode))
	// In-place agent upgrade — re-install the configured node binary (the Update
	// action; offered when a newer build is available).
	mux.HandleFunc("POST /api/nodes/{id}/update-agent", admin(s.handleUpdateNodeAgent))
	mux.HandleFunc("POST /api/network-policy/preview", readonly(s.handleNetworkPolicyPreview))

	// Relays — relays in the egress / onion chain (for the fleet map's roles).
	mux.HandleFunc("GET /api/relays", readonly(s.handleListRelays))
	mux.HandleFunc("DELETE /api/relays/{id}", admin(s.handleDeleteRelay))
	mux.HandleFunc("POST /api/relays/{id}/update-agent", admin(s.handleUpdateRelayAgent))
	// Cascade edges — entry→exit inner links (for the map's route arcs).
	mux.HandleFunc("GET /api/node-links", readonly(s.handleListNodeLinks))

	// Data-plane paths — named multi-hop chains entry → [mid] → exit.
	mux.HandleFunc("GET /api/paths", readonly(s.handleListPaths))
	mux.HandleFunc("POST /api/paths", admin(s.handleCreatePath))
	mux.HandleFunc("DELETE /api/paths/{id}", admin(s.handleDeletePath))
	mux.HandleFunc("POST /api/paths/{id}/provision", admin(s.handleProvisionPath))

	// The controller itself — its public IP + resolved location, for the map.
	mux.HandleFunc("GET /api/self", readonly(s.handleSelf))
	// Active IP-geolocation source + the attribution its license requires (the UI
	// credits it on the map; empty = region-map fallback).
	mux.HandleFunc("GET /api/geoip", readonly(s.handleGeoIP))

	// Servers — machines cox owns; onboard by key or password, then deploy roles.
	mux.HandleFunc("GET /api/ssh-key", readonly(s.handleSSHKey))
	mux.HandleFunc("GET /api/servers", readonly(s.handleListServers))
	mux.HandleFunc("POST /api/servers", admin(s.handleCreateServer))
	mux.HandleFunc("DELETE /api/servers/{id}", admin(s.handleDeleteServer))
	mux.HandleFunc("POST /api/servers/{id}/deploy", admin(s.handleDeployServer))
	mux.HandleFunc("PATCH /api/servers/{id}/route", admin(s.handleSetServerRoute))

	// Admins.
	mux.HandleFunc("GET /api/admins", readonly(s.handleListAdmins))
	mux.HandleFunc("POST /api/admins", admin(s.handleCreateAdmin))
	mux.HandleFunc("DELETE /api/admins/{id}", admin(s.handleDeleteAdmin))

	// End-user accounts.
	mux.HandleFunc("GET /api/users", readonly(s.handleListUsers))
	mux.HandleFunc("POST /api/users", admin(s.handleCreateUser))
	mux.HandleFunc("DELETE /api/users/{id}", admin(s.handleDeleteUser))
	// Issue a one-time device-enrollment invite (join-link + QR) for a user.
	mux.HandleFunc("POST /api/users/{id}/invite", admin(s.handleInviteUser))

	// Devices and provisioning.
	mux.HandleFunc("GET /api/users/{id}/devices", readonly(s.handleListDevices))
	mux.HandleFunc("POST /api/users/{id}/devices", admin(s.handleCreateDevice))
	mux.HandleFunc("DELETE /api/devices/{id}", admin(s.handleDeleteDevice))
	mux.HandleFunc("POST /api/devices/{id}/provision", admin(s.handleProvisionDevice))
	// Bind a device's traffic onto a data-plane path (the live switch), or clear it.
	mux.HandleFunc("POST /api/devices/{id}/bind", admin(s.handleBindDevice))
	mux.HandleFunc("DELETE /api/devices/{id}/bind", admin(s.handleClearDevice))

	// Profiles — a device's named connection configs (egress + entry IPs + protocol).
	mux.HandleFunc("GET /api/profiles", readonly(s.handleListProfileSpecs))
	mux.HandleFunc("POST /api/profiles", admin(s.handleCreateProfileSpec))
	mux.HandleFunc("DELETE /api/profiles/{id}", admin(s.handleDeleteProfileSpec))

	// API tokens — scoped bearer credentials (admin-only management).
	mux.HandleFunc("GET /api/tokens", admin(s.handleListTokens))
	mux.HandleFunc("POST /api/tokens", admin(s.handleCreateToken))
	mux.HandleFunc("DELETE /api/tokens/{id}", admin(s.handleRevokeToken))

	// Audit log — the management trail (admin-only).
	mux.HandleFunc("GET /api/audit", admin(s.handleListAudit))

	// Live events — monitoring scope (closes the M4 gap).
	mux.HandleFunc("GET /ws/events", monitor(s.handleEvents))

	// Session history — the persisted, source-IP-aware connection log
	// (Phase B monitoring). Monitor scope, the same as the live stream.
	mux.HandleFunc("GET /api/sessions", monitor(s.handleListSessions))

	// Analytics alerts (Phase C) — anomaly-detection findings over the session
	// history. Reads are monitor-scoped (beside sessions); ack/resolve are admin
	// mutations (audited). The status endpoint surfaces the backend warning.
	mux.HandleFunc("GET /api/alerts", monitor(s.handleListAlerts))
	mux.HandleFunc("GET /api/analytics/status", monitor(s.handleAnalyticsStatus))
	mux.HandleFunc("POST /api/alerts/{id}/ack", admin(s.handleAckAlert))
	mux.HandleFunc("POST /api/alerts/{id}/resolve", admin(s.handleResolveAlert))

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
