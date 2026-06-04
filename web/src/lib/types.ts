// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

export interface User {
	id: string;
	email: string;
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

export interface ApiError {
	status: number;
	message: string;
}
