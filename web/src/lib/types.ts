// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

export interface User {
	id: string;
	email: string;
	role: string;
	status: string;
	version: number;
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
