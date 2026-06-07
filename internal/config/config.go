// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package config defines coxswain's configuration model, the personal/enterprise
// presets, and the koanf-based loader.
package config

// Posture is the deployment posture chosen at `cox init`.
type Posture string

const (
	// PosturePersonal — one operator, a handful of nodes.
	PosturePersonal Posture = "personal"
	// PostureEnterprise — a team managing many users across many regions.
	PostureEnterprise Posture = "enterprise"
)

// Config is the full coxswain configuration. It is persisted as YAML and reloaded
// on every start. Field tags are shared between koanf (load) and yaml (write).
type Config struct {
	// Posture records which preset this deployment was initialised from.
	Posture Posture `koanf:"posture" yaml:"posture"`
	// Backend is the state-store backend: "sqlite" (the default, single static
	// binary) or "postgres" (recommended for production/enterprise scale —
	// heavy analytical queries + write concurrency). Only SQLite is wired today;
	// the value drives the analytics engine's backend-suitability warning.
	Backend string `koanf:"backend" yaml:"backend"`
	// StateDir holds the SQLite database, snapshots, and other on-disk state.
	StateDir string `koanf:"state_dir" yaml:"state_dir"`
	// GeoIPDatabase is the path to a MaxMind GeoLite2-City.mmdb used to resolve
	// a server's location from its IP (so the admin never types a region).
	// Empty falls back to GeoLite2-City.mmdb in the state dir, then the cwd.
	GeoIPDatabase string `koanf:"geoip_db" yaml:"geoip_db"`
	// ControlLocation is the controller's map location for the client's
	// control-plane pin, used when geoip can't resolve the relay endpoint (no
	// mmdb). Optional — without it (and without geoip) the client omits the pin.
	ControlLocation ControlLocationConfig `koanf:"control_location" yaml:"control_location"`

	Log       LogConfig       `koanf:"log" yaml:"log"`
	UI        UIConfig        `koanf:"ui" yaml:"ui"`
	Analytics AnalyticsConfig `koanf:"analytics" yaml:"analytics"`
	Protocols ProtocolsConfig `koanf:"protocols" yaml:"protocols"`
	Relay     RelayConfig     `koanf:"relay" yaml:"relay"`
	Accounts  AccountsConfig  `koanf:"accounts" yaml:"accounts"`
	Retention RetentionConfig `koanf:"retention" yaml:"retention"`
	Reality   RealityConfig   `koanf:"reality" yaml:"reality"`
	Fleet     FleetConfig     `koanf:"fleet" yaml:"fleet"`
	Node      NodeConfig      `koanf:"node" yaml:"node"`
	Admin     AdminConfig     `koanf:"admin" yaml:"admin"`
	// SIEM is the optional inbound gRPC monitoring stream for enterprise/SIEM
	// ingestion. Off by default (empty Listen) — coxswain keeps zero inbound ports
	// unless this is configured.
	SIEM SIEMConfig `koanf:"siem" yaml:"siem"`
}

// SIEMConfig controls the optional inbound gRPC MonitorStream server (the
// SIEM/enterprise ingestion plane). It is DISABLED by default: with Listen empty
// coxswain opens no inbound port, preserving the zero-inbound-by-default posture
// (DESIGN §2, §6). When enabled, an enterprise consumer dials in over gRPC,
// authenticates with a monitor-scope API token, and receives the live stream of
// session connect/disconnect events plus analytics alerts.
//
// Production guidance: set TLSCert/TLSKey so the stream is encrypted in transit
// (a monitor token over a plaintext socket is exposed to a network observer),
// and mint a dedicated monitor-scope token for the consumer. Without TLS, only
// expose Listen over loopback / an SSH-forwarded port.
type SIEMConfig struct {
	// Listen is the address the SIEM gRPC server binds (e.g. ":9443"). Empty
	// (the default) disables the listener entirely — no inbound port is opened.
	Listen string `koanf:"listen" yaml:"listen"`
	// TLSCert / TLSKey are PEM file paths for transport TLS. Both must be set to
	// enable TLS; otherwise the listener is plaintext (loopback / SSH-tunnel only).
	TLSCert string `koanf:"tls_cert" yaml:"tls_cert"`
	TLSKey  string `koanf:"tls_key" yaml:"tls_key"`
}

// ControlLocationConfig is the controller's manual map location (when geoip is
// unavailable). Zero lat/lon means "unset".
type ControlLocationConfig struct {
	City string  `koanf:"city" yaml:"city"`
	Lat  float64 `koanf:"lat" yaml:"lat"`
	Lon  float64 `koanf:"lon" yaml:"lon"`
}

// Backend identifiers.
const (
	BackendSQLite   = "sqlite"
	BackendPostgres = "postgres"
)

// BackendKind returns the configured state-store backend, defaulting to SQLite
// when unset (the historical, always-SQLite behaviour). The value is
// lower-cased so "Postgres"/"POSTGRES" all match.
func (c Config) BackendKind() string {
	switch b := normaliseBackend(c.Backend); b {
	case BackendPostgres:
		return BackendPostgres
	default:
		return BackendSQLite
	}
}

func normaliseBackend(b string) string {
	switch b {
	case "postgres", "Postgres", "POSTGRES", "postgresql", "pg":
		return BackendPostgres
	default:
		return BackendSQLite
	}
}

// AnalyticsConfig controls the anomaly-detection engine (Phase C). Disabled is
// a kill-switch; IntervalSeconds and WindowHours tune the sweep cadence and how
// far back each sweep looks. Zero values fall back to the defaults below.
type AnalyticsConfig struct {
	// Disabled turns the analytics sweep off entirely (no ticker, no startup run).
	Disabled bool `koanf:"disabled" yaml:"disabled"`
	// IntervalSeconds is how often the sweep runs. Zero → DefaultAnalyticsSeconds.
	IntervalSeconds int `koanf:"interval_seconds" yaml:"interval_seconds"`
	// WindowHours is how far back each sweep scans connection_events. Zero →
	// DefaultAnalyticsWindowHours.
	WindowHours int `koanf:"window_hours" yaml:"window_hours"`
}

// Analytics-engine defaults.
const (
	// DefaultAnalyticsSeconds is the sweep interval when unset.
	DefaultAnalyticsSeconds = 60
	// DefaultAnalyticsWindowHours is the look-back window when unset.
	DefaultAnalyticsWindowHours = 24
)

// IntervalSecondsOr returns the effective sweep interval, applying the default
// when unset or non-positive.
func (a AnalyticsConfig) IntervalSecondsOr() int {
	if a.IntervalSeconds > 0 {
		return a.IntervalSeconds
	}
	return DefaultAnalyticsSeconds
}

// WindowHoursOr returns the effective look-back window, applying the default
// when unset or non-positive.
func (a AnalyticsConfig) WindowHoursOr() int {
	if a.WindowHours > 0 {
		return a.WindowHours
	}
	return DefaultAnalyticsWindowHours
}

// AdminConfig holds the fixed controller-admin account (DESIGN §8). The
// password here is the source of truth — coxswain re-syncs it into the database
// on every start, so editing it and restarting changes the admin login.
type AdminConfig struct {
	// Password is the fixed admin's login password. `cox init` generates a
	// strong random value; the operator may replace it and restart.
	Password string `koanf:"password" yaml:"password"`
}

// NodeConfig holds defaults for SSH-based node onboarding (DESIGN §5). coxswain
// reaches a node over SSH only to install and update the node agent.
type NodeConfig struct {
	// NodeBinaryURL is the default download URL for the node agent, used by
	// `cox nodes add` when no local binary is supplied.
	NodeBinaryURL string `koanf:"node_binary_url" yaml:"node_binary_url"`
	// BinaryPath is a local path to the (linux) node binary the controller
	// uploads when deploying a node from the admin UI / API (which can't take a
	// --binary flag). Falls back to NodeBinaryURL.
	BinaryPath string `koanf:"binary_path" yaml:"binary_path"`
	// SSHUser is the default SSH user for reaching new nodes.
	SSHUser string `koanf:"ssh_user" yaml:"ssh_user"`
	// SSHPort is the default SSH port for reaching new nodes.
	SSHPort int `koanf:"ssh_port" yaml:"ssh_port"`
}

// LogConfig controls diagnostic logging.
type LogConfig struct {
	// Level is one of debug, info, warn, error.
	Level string `koanf:"level" yaml:"level"`
}

// UIConfig controls the embedded admin Web UI. It binds to a loopback address —
// coxswain opens no inbound ports. The controller may run on a remote droplet
// (reached over an SSH-forwarded loopback port or a TLS-terminating proxy), so
// the dashboard must only be reached over TLS or an SSH-forwarded loopback port.
type UIConfig struct {
	// Listen is the loopback address the admin UI binds to.
	Listen string `koanf:"listen" yaml:"listen"`
	// BehindTLSProxy declares that a trusted TLS-terminating reverse proxy sits in
	// front of the UI. Only when true does coxswain trust the X-Forwarded-Proto
	// header to decide whether a request arrived over a secure transport (and thus
	// whether to set the session cookie's Secure attribute). Default false —
	// matching why audit.go deliberately does NOT trust X-Forwarded-For — so a
	// spoofed header can never flip cookie security on a direct/loopback deploy.
	BehindTLSProxy bool `koanf:"behind_tls_proxy" yaml:"behind_tls_proxy"`
}

// ProtocolsConfig toggles which data-plane protocols the fleet offers.
type ProtocolsConfig struct {
	AmneziaWG bool `koanf:"amneziawg" yaml:"amneziawg"`
	XRay      bool `koanf:"xray" yaml:"xray"`
}

// RelayConfig controls the relay tier (DESIGN §2).
type RelayConfig struct {
	// Embedded runs a relay in-process inside coxswain.
	Embedded bool `koanf:"embedded" yaml:"embedded"`
	// Remote enables dialing out to remote relays over a reverse tunnel.
	Remote bool `koanf:"remote" yaml:"remote"`
	// RemoteEndpoints are the tunnel-listener addresses of remote relay
	// relays coxswain dials out to (DESIGN §2). coxswain keeps zero inbound ports —
	// it reconnects to each forever. Used only when Remote is true. Relays
	// enrolled with `cox relays add` are dialed in addition to these.
	RemoteEndpoints []string `koanf:"remote_endpoints" yaml:"remote_endpoints"`
	// BinaryURL is the default download URL for the relay binary, used by
	// `cox relays add` when no local binary is supplied.
	BinaryURL string `koanf:"binary_url" yaml:"binary_url"`
	// BinaryPath is a local path to the (linux) relay binary the controller
	// uploads when deploying a relay from the admin UI / API. Falls back to BinaryURL.
	BinaryPath string `koanf:"binary_path" yaml:"binary_path"`
	// PublicEndpoint is the address clients reach a relay at — baked into
	// enrollment tickets so a scanned device knows where to connect.
	PublicEndpoint string `koanf:"public_endpoint" yaml:"public_endpoint"`
	// ClientListen is the address the embedded relay binds for caravel mTLS
	// clients (DESIGN §2) — the data-plane client port.
	ClientListen string `koanf:"client_listen" yaml:"client_listen"`
}

// AccountsConfig controls the account & profile-sync service (DESIGN §8).
type AccountsConfig struct {
	// Sync enables account login and E2E-encrypted profile sync.
	Sync bool `koanf:"sync" yaml:"sync"`
}

// RetentionConfig controls how long audit and metrics data is kept.
type RetentionConfig struct {
	AuditDays   int `koanf:"audit_days" yaml:"audit_days"`
	MetricsDays int `koanf:"metrics_days" yaml:"metrics_days"`
}

// RealityConfig controls the XRay REALITY decoy site (DESIGN §12).
type RealityConfig struct {
	DecoySite string `koanf:"decoy_site" yaml:"decoy_site"`
}

// FleetConfig holds fleet-shape defaults.
type FleetConfig struct {
	// Regions the operator intends to deploy into. Empty means "decide at
	// provisioning time" (personal: one, nearest).
	Regions []string `koanf:"regions" yaml:"regions"`
	// IdleNodes encourages pre-positioned, stopped nodes (enterprise).
	IdleNodes bool `koanf:"idle_nodes" yaml:"idle_nodes"`
	// VPNSubnet is the CIDR coxswain allocates per-device tunnel addresses from.
	VPNSubnet string `koanf:"vpn_subnet" yaml:"vpn_subnet"`
	// EndpointPortMin/Max is the UDP port range each node accepts AmneziaWG
	// on (DESIGN §3, decision 17) — the breadth of the endpoint pool.
	EndpointPortMin int `koanf:"endpoint_port_min" yaml:"endpoint_port_min"`
	EndpointPortMax int `koanf:"endpoint_port_max" yaml:"endpoint_port_max"`
	// Rotation is the client endpoint-rotation policy (anti-correlation).
	Rotation RotationConfig `koanf:"rotation" yaml:"rotation"`
	// ReconcileInterval is how often (in seconds) `cox serve`'s reconcile sweep
	// polls every node's live status and heals drift (Phase 2, Option B). Zero or
	// negative falls back to DefaultReconcileSeconds. The sweep is the backstop
	// that makes silent config drift self-heal even when a push is missed.
	ReconcileInterval int `koanf:"reconcile_interval" yaml:"reconcile_interval"`
}

// DefaultReconcileSeconds is the reconcile-sweep interval used when
// fleet.reconcile_interval is unset.
const DefaultReconcileSeconds = 45

// ReconcileSeconds returns the effective reconcile-sweep interval, applying the
// default when the configured value is unset or non-positive.
func (f FleetConfig) ReconcileSeconds() int {
	if f.ReconcileInterval > 0 {
		return f.ReconcileInterval
	}
	return DefaultReconcileSeconds
}

// RotationConfig is the client endpoint-rotation policy (DESIGN §3,
// decision 17). When enabled, a client re-picks its (ip, port) endpoint every
// IntervalSeconds, jittered by up to JitterSeconds.
type RotationConfig struct {
	Enabled         bool `koanf:"enabled" yaml:"enabled"`
	IntervalSeconds int  `koanf:"interval_seconds" yaml:"interval_seconds"`
	JitterSeconds   int  `koanf:"jitter_seconds" yaml:"jitter_seconds"`
}
