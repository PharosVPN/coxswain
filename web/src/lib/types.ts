// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

export interface User {
	id: string;
	name: string;
	email: string;
	phone: string;
	role: string;
	status: string;
	version: number;
}

// Self is the controller's own marker for the map (GET /api/self): its public
// IP and the location resolved from it.
export interface Self {
	public_ip: string;
	location?: GeoLocation;
	name: string;
	status: string;
}

// GeoLocation is a host's location resolved from its IP (MaxMind GeoLite2),
// so the admin never types a region.
export interface GeoLocation {
	city: string;
	country: string;
	country_code: string;
	latitude: number;
	longitude: number;
}

export interface Node {
	id: string;
	name: string;
	region: string;
	status: string;
	public_ip: string;
	ssh_host: string;
	control_addr: string;
	agent_version: string;
	// version_display is the human-friendly deployed version; available_version is
	// the configured candidate binary's version; update_available is true only when
	// the candidate is strictly newer than the deployed build.
	version_display: string;
	available_version: string;
	update_available: boolean;
	endpoint_ips: string[];
	forwarding: boolean;
	masquerade: boolean;
	isolation: boolean;
	version: number;
	created_at: string;
	updated_at: string;
	server_id?: string;
	location?: GeoLocation;
}

export interface Relay {
	id: string;
	name: string;
	kind: string;
	region: string;
	status: string;
	host: string;
	agent_version: string;
	version_display: string;
	available_version: string;
	update_available: boolean;
	egress: boolean;
	egress_hop: number;
	onion: boolean;
	server_id?: string;
	location?: GeoLocation;
}

// Server is a machine cox owns — onboarded by password, then keyed. Roles
// (node/relay) deploy onto it; the controller's own host is is_self.
export interface Server {
	id: string;
	name: string;
	region: string;
	ssh_host: string;
	is_self: boolean;
	status: string;
	// route is the ordered relay-id hops coxswain reaches this server through;
	// empty = direct (the default).
	route: string[];
	version: number;
	location?: GeoLocation;
}

// NodeLink is one cascade edge — an inner AmneziaWG link from an entry node to
// an exit node (drawn as a route arc on the map).
export interface NodeLink {
	id: string;
	entry_node_id: string;
	exit_node_id: string;
	status: string;
	color: string;
}

// Path is a named, ordered data plane: entry → [mid] → exit. `hops` is the
// ordered list of node ids (entry first, exit last); the map draws an arc per
// consecutive pair, all in the path's colour.
export interface Path {
	id: string;
	name: string;
	color: string;
	status: string;
	hops: string[];
	version: number;
}

// Site is one host on the fleet map — the aggregate of every role at an IP.
export interface Site {
	key: string;
	region: string;
	roles: import('./roles').Role[];
	status: string;
	node?: Node;
	relays: Relay[];
	server?: Server;
	location?: GeoLocation;
	label: string;
}

export interface LiveEvent {
	node_id: string;
	at: string;
	type: string;
	protocol?: string;
	peer_id?: string;
	message?: string;
	device_id?: string;
	user?: string;
	source_ip?: string;
	source_endpoint?: string;
	// alert carries an analytics Alert when type === 'alert' (Phase C).
	alert?: Alert;
}

export interface Device {
	id: string;
	user_id: string;
	name: string;
	platform: string;
	status: string;
	version: number;
	created_at: string;
}

export interface ProvisionResult {
	device_id: string;
	tunnel_ip: string;
	peer_count: number;
	profile_revision: number;
}

// ProfileSpec is an admin-created profile: a named connection config for a
// (user, device) — an egress (a node or a path), an optional entry-IP subset,
// and one data-plane protocol. A device may hold several.
export interface ProfileSpec {
	id: string;
	user_id: string;
	device_id: string;
	name: string;
	path_id?: string;
	node_id?: string;
	entry_ips?: string[];
	protocol: string;
	version: number;
}

// Token is the API representation of an API token — never the secret. Minted
// secrets come back once inside TokenCreated.
export interface Token {
	id: string;
	name: string;
	scope: string;
	prefix: string;
	created_at: string;
	created_by?: string;
	expires_at?: string;
	last_used_at?: string;
	revoked_at?: string;
}

// TokenCreated is the create response — the token view plus the plaintext
// secret, returned exactly once.
export interface TokenCreated extends Token {
	secret: string;
}

// AuditRecord is one row of the management trail.
export interface AuditRecord {
	id: string;
	at: string;
	actor: string;
	actor_kind: string;
	action: string;
	target_type: string;
	target_id: string;
	source_ip: string;
	detail?: Record<string, unknown>;
	result: string;
	error?: string;
}

// SessionRecord is one persisted connection event (connect/disconnect).
export interface SessionRecord {
	id: string;
	at: string;
	node_id?: string;
	peer_id?: string;
	device_id?: string;
	user_id?: string;
	protocol?: string;
	event_type: string;
	source_ip?: string;
	source_endpoint?: string;
	rx_bytes: number;
	tx_bytes: number;
}

// Alert is one analytics finding over the session history.
export interface Alert {
	id: string;
	at: string;
	kind: string;
	severity: string;
	device_id?: string;
	user_id?: string;
	node_id?: string;
	source_ips: string[];
	detail?: Record<string, unknown>;
	status: string;
	dedup_key?: string;
	created_at: string;
	updated_at: string;
}

// AlertsEnvelope wraps the alerts list with the analytics backend warning.
export interface AlertsEnvelope {
	alerts: Alert[];
	backend: string;
	backend_warning?: string;
}

// AnalyticsStatus reports the analytics backend and any suitability warning.
export interface AnalyticsStatus {
	backend: string;
	backend_warning?: string;
}

export interface ApiError {
	status: number;
	message: string;
}
