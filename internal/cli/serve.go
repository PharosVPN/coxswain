// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/PharosVPN/coxswain/internal/analytics"
	"github.com/PharosVPN/coxswain/internal/api"
	"github.com/PharosVPN/coxswain/internal/auth"
	"github.com/PharosVPN/coxswain/internal/config"
	"github.com/PharosVPN/coxswain/internal/fleet"
	"github.com/PharosVPN/coxswain/internal/geoip"
	"github.com/PharosVPN/coxswain/internal/live"
	"github.com/PharosVPN/coxswain/internal/monitor"
	"github.com/PharosVPN/coxswain/internal/pki"
	"github.com/PharosVPN/coxswain/internal/profile"
	"github.com/PharosVPN/coxswain/internal/provision"
	"github.com/PharosVPN/coxswain/internal/reconcile"
	"github.com/PharosVPN/coxswain/internal/relayhost"
	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the admin server and live plane",
		Long: "Run coxswain's admin server: the localhost JSON API and admin UI,\n" +
			"plus the live plane (DESIGN §7) — a WatchEvents stream held open\n" +
			"to every enrolled node, fanned out to admin browsers over a\n" +
			"WebSocket. Runs until interrupted.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cfg, conn, err := openState(cfgPath)
			if err != nil {
				return err
			}
			defer conn.Close()

			// The config password is the source of truth for the fixed admin.
			if err := auth.SyncConfigAdmin(ctx, conn, cfg.Admin.Password); err != nil {
				return err
			}

			// Represent the controller's own host as the is_self server, so it's
			// visible and can host components. Best-effort — never block serving.
			if _, err := ensureSelfServer(ctx, conn, cfg); err != nil {
				fmt.Printf("  warning: could not register self server: %v\n", err)
			}

			// The relay tier fronts the account/sync gRPC service
			// (DESIGN §2): an in-process relay and/or reverse tunnels out to
			// remote relays. Relay failures are non-fatal — the admin plane
			// still serves; only client sync is unavailable.
			remotes, err := remoteRelayEndpoints(ctx, cfg, conn)
			if err != nil {
				return err
			}
			if cfg.Accounts.Sync && (cfg.Relay.Embedded || len(remotes) > 0) {
				if stop := startRelayRelay(ctx, cfg, conn, remotes); stop != nil {
					defer stop()
				}
			}

			nodes, err := fleet.ListNodes(ctx, conn)
			if err != nil {
				return err
			}

			hub := live.NewHub()
			// The connection-history store turns the ephemeral WatchEvents
			// firehose into persisted, source-IP-aware session history (Phase B).
			// Its writer runs off the stream goroutines so a DB stall never stalls
			// the live plane; it is the sink every node watcher feeds.
			history := monitor.NewStore(conn, nil)
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				history.Run(ctx)
			}()
			watched := 0
			for _, n := range nodes {
				if n.ControlAddr == "" {
					continue
				}
				// Each node is watched through its own server route (or direct),
				// so the live control plane honours the same routing as onboarding.
				dialer, dErr := newControlDialer(ctx, conn, nodeRoute(ctx, conn, n))
				if dErr != nil {
					fmt.Printf("  watch:   %s unreachable to set up (%v)\n", n.Name, dErr)
					continue
				}
				watched++
				wg.Add(1)
				go func(node fleet.Node) {
					defer wg.Done()
					live.WatchNode(ctx, dialer, node, hub, history)
				}(n)
			}

			// Resolve server locations from their IPs (auto-region). The mmdb is
			// large + licensed, so it's loaded from a path, not embedded; absent
			// is fine — the UI falls back to its region-code map.
			geo := geoip.Open(cfg.GeoIPDatabase,
				filepath.Join(cfg.StateDir, "GeoLite2-City.mmdb"), "GeoLite2-City.mmdb")
			defer geo.Close()
			if geo.Available() {
				fmt.Println("  geoip:   GeoLite2-City loaded — server regions auto-resolved")
			}

			// The controller's public IP places it on the map (best-effort; an
			// enterprise setup may have none — then it's set manually, later).
			controllerHost := detectPublicIP(ctx)
			if controllerHost != "" {
				fmt.Printf("  self:    controller public IP %s\n", controllerHost)
			}

			provOpts := provision.Options{
				VPNSubnet: cfg.Fleet.VPNSubnet,
				PortMin:   cfg.Fleet.EndpointPortMin,
				PortMax:   cfg.Fleet.EndpointPortMax,
				Rotation: profile.RotationPolicy{
					Enabled:         cfg.Fleet.Rotation.Enabled,
					IntervalSeconds: cfg.Fleet.Rotation.IntervalSeconds,
					JitterSeconds:   cfg.Fleet.Rotation.JitterSeconds,
				},
				XRay: provision.XRayOptions{
					Enabled:    cfg.Protocols.XRay,
					ServerName: cfg.Reality.DecoySite,
				},
				Control: controlEndpoint(geo, hostOnly(cfg.Relay.PublicEndpoint), controllerHost, cfg.ControlLocation),
			}
			// The cascade coordinator drives data-plane path provisioning/binding
			// over the node control plane; a nil interface (a missing CA) disables
			// those routes. Keep it a genuine nil interface, not a typed nil.
			var pathCoord api.PathCoordinator
			if coord, cErr := newCascadeCoordinator(ctx, conn); cErr != nil {
				fmt.Printf("  paths:   provisioning unavailable (%v)\n", cErr)
			} else {
				pathCoord = coord
			}
			srv := api.NewServer(cfg.UI.Listen, conn, hub, provOpts, cliDeployer{cfg: cfg, conn: conn, geo: geo}, pathCoord, geo, controllerHost)
			// The state-store backend drives the analytics backend-suitability
			// warning (surfaced on the alerts endpoints).
			backend := cfg.BackendKind()
			srv.SetBackend(backend)
			// Only when a trusted TLS-terminating proxy is declared do we honour
			// X-Forwarded-Proto for the session cookie's Secure attribute.
			srv.SetBehindTLSProxy(cfg.UI.BehindTLSProxy)
			// The node-push primitive backs the reconcile route + push-on-provision.
			// cli owns the config + routed dialers, so it supplies the closure.
			cfgCopy := cfg
			srv.SetNodePusher(func(pctx context.Context, nodeID string) (any, error) {
				node, gErr := fleet.GetNode(pctx, conn, nodeID)
				if gErr != nil {
					return nil, gErr
				}
				return reconcile.PushNode(pctx, &cfgCopy, conn, node)
			})

			// The reconcile sweep (Phase 2, Option B): an always-on goroutine that
			// polls every node's live status and heals drift/stale data planes, so a
			// missed push self-heals. Runs under the serve ctx; stops on cancel.
			interval := time.Duration(cfg.Fleet.ReconcileSeconds()) * time.Second
			wg.Add(1)
			go func() {
				defer wg.Done()
				reconcile.Run(ctx, &cfgCopy, conn, interval, func(format string, args ...any) {
					fmt.Printf("  "+format+"\n", args...)
				})
			}()

			// Audit retention: purge rows older than retention.audit_days on
			// startup and once a day after. Skipped entirely when audit_days is 0.
			wg.Add(1)
			go func() {
				defer wg.Done()
				runAuditPurge(ctx, conn, cfg.Retention.AuditDays)
			}()

			// Connection-history retention: purge connection_events older than
			// retention.metrics_days on startup and once a day after (it is the
			// same time-series class as the metrics samples). Skipped at 0.
			wg.Add(1)
			go func() {
				defer wg.Done()
				runHistoryPurge(ctx, conn, cfg.Retention.MetricsDays)
			}()

			// Alerts retention: purge analytics alerts older than
			// retention.metrics_days (same time-series class as the history they
			// derive from). Skipped at 0.
			wg.Add(1)
			go func() {
				defer wg.Done()
				runAlertsPurge(ctx, conn, cfg.Retention.MetricsDays)
			}()

			// The analytics engine (Phase C): an always-on goroutine that sweeps
			// recent connection_events on a ticker, upserts anomaly alerts, and
			// fans each NEW alert onto the live hub for real-time dashboards. It
			// runs once on startup and emits the one-time backend-suitability
			// warning. Disabled via analytics.disabled.
			if !cfg.Analytics.Disabled {
				engine := analytics.NewEngine(conn, analytics.Options{
					GeoIP:    analytics.FromGeoIP(geo),
					Interval: time.Duration(cfg.Analytics.IntervalSecondsOr()) * time.Second,
					Window:   time.Duration(cfg.Analytics.WindowHoursOr()) * time.Hour,
					Backend:  backend,
					Publish: func(a analytics.Alert) {
						hub.PublishAlert(a, a.DeviceID, a.At)
					},
				})
				wg.Add(1)
				go func() {
					defer wg.Done()
					engine.Run(ctx)
				}()
				fmt.Printf("  analytics: sweep every %ds, %dh window (backend %s)\n",
					cfg.Analytics.IntervalSecondsOr(), cfg.Analytics.WindowHoursOr(), backend)
			}

			fmt.Printf("coxswain admin server — http://%s, watching %d node(s)\n", cfg.UI.Listen, watched)
			fmt.Printf("  api:     http://%s/api\n", cfg.UI.Listen)
			fmt.Printf("  events:  ws://%s/ws/events\n", cfg.UI.Listen)
			fmt.Printf("  reconcile sweep every %s\n", interval)

			err = srv.Run(ctx)
			wg.Wait()
			return err
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", config.DefaultPath, "path to the config file")
	return cmd
}

// remoteRelayEndpoints is the set of remote relay tunnel addresses coxswain dials:
// the relays enrolled with `cox relays add` (active, kind "remote") unioned
// with any relay.remote_endpoints in the config. Enrolled relays are dialed
// whenever they are active; config endpoints honour the relay.remote toggle.
func remoteRelayEndpoints(ctx context.Context, cfg config.Config, conn *sql.DB) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(ep string) {
		if ep != "" && !seen[ep] {
			seen[ep] = true
			out = append(out, ep)
		}
	}

	relays, err := fleet.ListRelays(ctx, conn)
	if err != nil {
		return nil, err
	}
	for _, r := range relays {
		if r.Kind == fleet.RelayKindRemote && r.Status == fleet.StatusActive {
			add(r.Endpoint)
		}
	}
	if cfg.Relay.Remote {
		for _, ep := range cfg.Relay.RemoteEndpoints {
			add(ep)
		}
	}
	return out, nil
}

// startRelayRelay issues coxswain's relay-tier service certs and brings up the
// relay tier behind the account/sync gRPC service: the in-process relay (when
// relay.embedded) and a reverse tunnel to each remote relay. It returns a
// stop func, or nil if nothing started. Any failure prints a warning and is
// non-fatal, so a missing data-plane port never blocks the admin server.
func startRelayRelay(ctx context.Context, cfg config.Config, conn *sql.DB, remotes []string) (stop func()) {
	bundle, _, err := pki.EnsureCA(ctx, conn)
	if err != nil {
		fmt.Printf("  warning: relay disabled — load CA: %v\n", err)
		return nil
	}
	grpcCert, err := pki.EnsureServiceCert(ctx, conn, bundle.Fleet, pki.ServiceGRPC)
	if err != nil {
		fmt.Printf("  warning: relay disabled — gRPC cert: %v\n", err)
		return nil
	}
	// The embedded relay's leaf must carry the controller's public host/IP so a
	// remote caravel device that dials the public endpoint can verify it. Prefer
	// the configured public endpoint; fall back to the autodetected public IP.
	relaySAN := hostOnly(cfg.Relay.PublicEndpoint)
	if relaySAN == "" {
		relaySAN = detectPublicIP(ctx)
	}
	relayCert, err := pki.EnsureServiceCert(ctx, conn, bundle.Fleet, pki.ServiceRelay, relaySAN)
	if err != nil {
		fmt.Printf("  warning: relay disabled — relay cert: %v\n", err)
		return nil
	}
	srv, err := relayhost.AccountServer(conn, grpcCert, bundle.Fleet.CertPEM)
	if err != nil {
		fmt.Printf("  warning: relay disabled — gRPC server: %v\n", err)
		return nil
	}

	// The embedded relay binds a public listener; remote relays are dialed
	// out to. The same gRPC server backs both.
	var emb *relayhost.Embedded
	if cfg.Relay.Embedded {
		emb, err = relayhost.StartEmbedded(srv, relayhost.EmbeddedConfig{
			ClientListen: cfg.Relay.ClientListen,
			RelayCert:    relayCert,
			DeviceCAPEM:  bundle.Device.CertPEM,
			FleetCAPEM:   bundle.Fleet.CertPEM,
		})
		if err != nil {
			fmt.Printf("  warning: embedded relay disabled — %v\n", err)
			emb = nil
		} else {
			fmt.Printf("  relay:   mtls://%s (embedded, caravel clients)\n", emb.Addr())
		}
	}

	var wg sync.WaitGroup
	dialed := 0
	for _, ep := range remotes {
		if ep == "" {
			continue
		}
		dialed++
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			if err := relayhost.RunRemote(ctx, srv, addr, relayCert, bundle.Fleet.CertPEM); err != nil && ctx.Err() == nil {
				fmt.Printf("  warning: remote relay %s stopped: %v\n", addr, err)
			}
		}(ep)
		fmt.Printf("  relay:   reverse tunnel to remote relay %s\n", ep)
	}

	if emb == nil && dialed == 0 {
		srv.Stop()
		return nil
	}
	return func() {
		if emb != nil {
			emb.Stop()
		} else {
			srv.Stop()
		}
		wg.Wait()
	}
}
