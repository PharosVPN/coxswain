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
	// StateDir holds the SQLite database, snapshots, and other on-disk state.
	StateDir string `koanf:"state_dir" yaml:"state_dir"`

	Log       LogConfig       `koanf:"log" yaml:"log"`
	UI        UIConfig        `koanf:"ui" yaml:"ui"`
	Protocols ProtocolsConfig `koanf:"protocols" yaml:"protocols"`
	Relay     RelayConfig     `koanf:"relay" yaml:"relay"`
	Accounts  AccountsConfig  `koanf:"accounts" yaml:"accounts"`
	Retention RetentionConfig `koanf:"retention" yaml:"retention"`
	Reality   RealityConfig   `koanf:"reality" yaml:"reality"`
	Fleet     FleetConfig     `koanf:"fleet" yaml:"fleet"`
	Node      NodeConfig      `koanf:"node" yaml:"node"`
	Admin     AdminConfig     `koanf:"admin" yaml:"admin"`
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

// UIConfig controls the embedded admin Web UI. It binds to localhost only —
// coxswain opens no inbound ports.
type UIConfig struct {
	// Listen is the localhost address the admin UI binds to.
	Listen string `koanf:"listen" yaml:"listen"`
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
}

// RotationConfig is the client endpoint-rotation policy (DESIGN §3,
// decision 17). When enabled, a client re-picks its (ip, port) endpoint every
// IntervalSeconds, jittered by up to JitterSeconds.
type RotationConfig struct {
	Enabled         bool `koanf:"enabled" yaml:"enabled"`
	IntervalSeconds int  `koanf:"interval_seconds" yaml:"interval_seconds"`
	JitterSeconds   int  `koanf:"jitter_seconds" yaml:"jitter_seconds"`
}
