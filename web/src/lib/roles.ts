// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// The role + status language of the fleet map. Icon = what a host IS (its
// composable roles); color = how it's DOING (one status glow). A single cheap
// box can be all three at once — the individual's whole private internet.

export type Role = 'helm' | 'buoy' | 'beacon';

export interface RoleMeta {
	id: Role;
	label: string;
	sub: string;
}

// Maritime, like the rest of PharosVPN: the lighthouse steers, the buoy marks a
// surfacing point, the beacon relays a signal.
export const ROLES: RoleMeta[] = [
	{ id: 'helm', label: 'Controller', sub: 'coxswain — the lighthouse that steers the fleet' },
	{ id: 'buoy', label: 'Node', sub: 'buoy — where you surface on the internet' },
	{ id: 'beacon', label: 'Relay', sub: 'beacon — a hop that hides the controller' }
];

export interface StatusMeta {
	label: string;
	color: string;
}

// The status buckets a glow can show, for the legend.
export const STATUSES: StatusMeta[] = [
	{ label: 'Active', color: 'var(--c-success)' },
	{ label: 'Coming up', color: 'var(--c-warning)' },
	{ label: 'Needs attention', color: 'var(--c-danger)' },
	{ label: 'Stopped', color: 'var(--c-gray-400)' }
];

export function statusColor(status: string): string {
	switch (status) {
		case 'active':
			return 'var(--c-success)';
		case 'error':
		case 'unreachable':
			return 'var(--c-danger)';
		case 'provisioning':
		case 'enrolling':
		case 'pending':
			return 'var(--c-warning)';
		case 'stopped':
			return 'var(--c-gray-400)';
		default:
			return 'var(--c-info)';
	}
}

// rank orders statuses attention-first, so a host wearing several roles glows by
// its most-urgent one (a problem anywhere makes the whole pin demand a look).
const RANK: Record<string, number> = {
	error: 5,
	unreachable: 5,
	provisioning: 4,
	enrolling: 4,
	pending: 4,
	active: 3,
	stopped: 1
};

export function dominantStatus(statuses: string[]): string {
	let best = '';
	let bestRank = -1;
	for (const s of statuses) {
		const r = RANK[s] ?? 2;
		if (r > bestRank) {
			bestRank = r;
			best = s;
		}
	}
	return best || 'active';
}
