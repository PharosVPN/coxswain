<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<!--
  FleetMap — the Living Map. The fleet drawn on a dim world: each host a pin on
  its real city, wearing a badge for every role it plays (controller / node /
  relay) and glowing by its status. One cheap box that runs everything shows one
  pin with all three badges; an enterprise fleet shows a sky of single-role pins.
  Hosts that share a city fan out so none hides behind another.
-->
<script lang="ts">
	import { geoNaturalEarth1, geoPath, geoGraticule10 } from 'd3-geo';
	import { feature } from 'topojson-client';
	import landTopo from 'world-atlas/land-110m.json';
	import type { Node, Relay, Site } from '$lib/types';
	import { locate } from '$lib/geo';
	import { ROLES, STATUSES, statusColor, dominantStatus, type Role } from '$lib/roles';
	import RoleGlyph from './RoleGlyph.svelte';

	let { nodes = [], relays = [], selectedKey = '', onselect }: {
		nodes?: Node[];
		relays?: Relay[];
		selectedKey?: string;
		onselect?: (s: Site) => void;
	} = $props();

	const W = 960;
	const H = 500;

	const land = feature(landTopo as any, (landTopo as any).objects.land);
	const projection = geoNaturalEarth1().fitExtent(
		[
			[14, 14],
			[W - 14, H - 14]
		],
		land as any
	);
	const pathOf = geoPath(projection);
	const landPath = pathOf(land as any) ?? '';
	const graticulePath = pathOf(geoGraticule10()) ?? '';

	const ROLE_ORDER: Role[] = ['helm', 'buoy', 'beacon'];

	// Aggregate every entity into a per-host site, so a box that is a node AND a
	// relay (AND, one day, the controller) becomes a single multi-badge pin.
	const sites = $derived.by<Site[]>(() => {
		const byHost = new Map<string, Site>();
		const ensure = (key: string, region: string): Site => {
			let s = byHost.get(key);
			if (!s) {
				s = { key, region, roles: [], status: '', node: undefined, relays: [], label: '' };
				byHost.set(key, s);
			}
			if (!s.region) s.region = region;
			return s;
		};
		for (const n of nodes) {
			const s = ensure(n.public_ip || n.id, n.region);
			if (!s.roles.includes('buoy')) s.roles.push('buoy');
			s.node = n;
			s.label = n.name;
		}
		for (const r of relays) {
			const s = ensure(r.host || r.id, r.region);
			if (!s.roles.includes('beacon')) s.roles.push('beacon');
			s.relays.push(r);
			if (!s.label) s.label = r.name;
		}
		return [...byHost.values()].map((s) => {
			const statuses = [
				...(s.node ? [s.node.status] : []),
				...s.relays.map((r) => r.status)
			];
			s.status = dominantStatus(statuses);
			s.roles.sort((a, b) => ROLE_ORDER.indexOf(a) - ROLE_ORDER.indexOf(b));
			return s;
		});
	});

	// Project + fan out co-located hosts so a city with two boxes shows two pins.
	const pins = $derived.by(() => {
		const seen = new Map<string, number>();
		return sites
			.map((s) => {
				const loc = locate(s.region);
				const xy = projection([loc.lon, loc.lat]);
				return { site: s, loc, xy };
			})
			.filter((p) => p.xy)
			.map((p) => {
				const gkey = `${Math.round(p.xy![0])},${Math.round(p.xy![1])}`;
				const i = seen.get(gkey) ?? 0;
				seen.set(gkey, i + 1);
				const a = i * 2.39996;
				const r = i === 0 ? 0 : 14 + i * 4;
				return {
					site: p.site,
					loc: p.loc,
					x: p.xy![0] + Math.cos(a) * r,
					y: p.xy![1] + Math.sin(a) * r,
					color: statusColor(p.site.status),
					live: p.site.status === 'active'
				};
			});
	});

	const CHIP = 11; // chip radius
	const GAP = 3;
	function chipX(count: number, i: number): number {
		const span = count * (CHIP * 2) + (count - 1) * GAP;
		return -span / 2 + CHIP + i * (CHIP * 2 + GAP);
	}
	function pinWidth(count: number): number {
		return count * (CHIP * 2) + (count - 1) * GAP;
	}

	function statusLabel(s: string): string {
		switch (s) {
			case 'active':
				return 'Active';
			case 'error':
			case 'unreachable':
				return 'Needs attention';
			case 'provisioning':
			case 'enrolling':
			case 'pending':
				return 'Coming up';
			case 'stopped':
				return 'Stopped';
			default:
				return s;
		}
	}

	// One readable line per role on a host — what it is + what it's doing here.
	function roleLines(site: Site): { role: Role; label: string; detail: string }[] {
		return site.roles.map((role) => {
			if (role === 'buoy') {
				const n = site.node;
				let detail = 'dead end';
				if (n?.forwarding) {
					detail = n.masquerade ? 'NAT egress' : 'routes onward';
					if (n.isolation) detail += ' · isolated';
				}
				return { role, label: 'Node', detail };
			}
			if (role === 'beacon') {
				const r = site.relays[0];
				const parts: string[] = [];
				if (r?.egress) parts.push(`egress · hop ${r.egress_hop}`);
				if (r?.onion) parts.push('onion');
				return { role, label: 'Relay', detail: parts.join(' · ') || 'relay' };
			}
			return { role, label: 'Controller', detail: 'steers the fleet' };
		});
	}

	const CARD_W = 198;
	function cardH(roles: number): number {
		return 34 + roles * 22 + 20;
	}
</script>

<div class="map">
	<svg viewBox="0 0 {W} {H}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Fleet map">
		<defs>
			<radialGradient id="map-vignette" cx="50%" cy="42%" r="75%">
				<stop offset="0%" stop-color="var(--c-gray-925)" />
				<stop offset="100%" stop-color="var(--c-gray-950)" />
			</radialGradient>
		</defs>
		<rect x="0" y="0" width={W} height={H} fill="url(#map-vignette)" />
		<path d={graticulePath} class="graticule" />
		<path d={landPath} class="land" />

		{#each pins as p (p.site.key)}
			{@const lines = roleLines(p.site)}
			{@const ch = cardH(lines.length)}
			{@const cy = p.y < ch + 34 ? 22 : -(ch + 16)}
			<g
				class="pin"
				class:selected={p.site.key === selectedKey}
				transform="translate({p.x},{p.y})"
				role="button"
				tabindex="0"
				aria-label="{p.loc.city || p.site.region}: {p.site.label} — {p.site.roles.join(', ')} ({p.site.status})"
				onclick={() => onselect?.(p.site)}
				onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && onselect?.(p.site)}
			>
				<!-- one status glow + pulse behind the whole badge row -->
				<ellipse class="halo" rx={pinWidth(p.site.roles.length) / 2 + 8} ry="15" style="fill: {p.color}" />
				{#if p.live}
					<circle class="ping" r="13" style="stroke: {p.color}" />
				{/if}

				{#each p.site.roles as role, i (role)}
					<g transform="translate({chipX(p.site.roles.length, i)},0)">
						<circle class="chip" r={CHIP} style="--glow: {p.color}" />
						<g transform="translate(-8,-8)" style="color: {p.color}">
							<RoleGlyph {role} size={16} />
						</g>
					</g>
				{/each}

				<!-- rich hover card: city, status, a row per role, the host -->
				<g class="card" transform="translate({-CARD_W / 2},{cy})">
					<rect class="card-bg" x="0" y="0" width={CARD_W} height={ch} rx="11" />
					<text class="card-city" x="14" y="22">{p.loc.flag} {p.loc.city || p.site.region}</text>
					<g transform="translate({CARD_W - 14},14)">
						<circle cx="-5" cy="4" r="3.5" style="fill: {p.color}" />
						<text class="card-status" x="-13" y="7.5" text-anchor="end" style="fill: {p.color}"
							>{statusLabel(p.site.status)}</text
						>
					</g>
					<line class="card-rule" x1="14" y1="32" x2={CARD_W - 14} y2="32" />
					{#each lines as ln, i (ln.role)}
						{@const ry = 34 + i * 22}
						<g transform="translate(14,{ry})" style="color: {p.color}">
							<g transform="translate(0,3)"><RoleGlyph role={ln.role} size={15} /></g>
						</g>
						<text class="card-role" x="36" y={34 + i * 22 + 14}>{ln.label}</text>
						<text class="card-detail" x={CARD_W - 14} y={34 + i * 22 + 14} text-anchor="end"
							>{ln.detail}</text
						>
					{/each}
					<text class="card-host" x="14" y={ch - 8}>{p.site.key}</text>
				</g>
			</g>
		{/each}
	</svg>

	<!-- legend: roles (what a host is) + status (how it's doing) -->
	<div class="legend">
		<div class="legend-col">
			<div class="legend-head">Roles</div>
			{#each ROLES as r (r.id)}
				<div class="legend-row">
					<span class="legend-glyph"><RoleGlyph role={r.id} size={15} /></span>
					<span class="legend-text"><b>{r.label}</b><span class="legend-sub">{r.sub}</span></span>
				</div>
			{/each}
		</div>
		<div class="legend-col">
			<div class="legend-head">Status</div>
			{#each STATUSES as s (s.label)}
				<div class="legend-row">
					<span class="legend-swatch" style="background: {s.color}"></span>
					<span class="legend-text"><b>{s.label}</b></span>
				</div>
			{/each}
		</div>
	</div>

	{#if pins.length === 0}
		<div class="empty">
			<div class="empty-title">The world is quiet</div>
			<div class="empty-sub">Onboard a node or relay and it lights up on its city.</div>
		</div>
	{/if}
</div>

<style>
	.map {
		position: relative;
		width: 100%;
		border-radius: 16px;
		overflow: hidden;
		border: 1px solid var(--c-gray-700);
		background: var(--c-gray-950);
	}
	svg {
		display: block;
		width: 100%;
		height: auto;
	}
	.land {
		fill: var(--c-gray-800);
		stroke: var(--c-gray-700);
		stroke-width: 0.4;
	}
	.graticule {
		fill: none;
		stroke: var(--c-gray-800);
		stroke-width: 0.3;
		opacity: 0.55;
	}
	.pin {
		cursor: pointer;
		outline: none;
	}
	.halo {
		opacity: 0.13;
		transition: opacity 0.2s ease;
	}
	.pin:hover .halo,
	.pin.selected .halo {
		opacity: 0.26;
	}
	.chip {
		fill: var(--c-gray-925);
		stroke: var(--glow);
		stroke-width: 1.6;
		transition: fill 0.2s ease;
	}
	.pin:hover .chip,
	.pin.selected .chip {
		fill: var(--c-gray-850);
	}
	.ping {
		fill: none;
		stroke-width: 1.5;
		transform-origin: center;
		animation: ping 2.8s ease-out infinite;
	}
	@keyframes ping {
		0% {
			r: 12;
			opacity: 0.6;
		}
		70%,
		100% {
			r: 30;
			opacity: 0;
		}
	}
	.card {
		opacity: 0;
		transition: opacity 0.18s ease;
		pointer-events: none;
	}
	.pin:hover .card,
	.pin:focus-visible .card,
	.pin.selected .card {
		opacity: 1;
	}
	.card-bg {
		fill: var(--c-gray-900);
		stroke: var(--c-gray-700);
		stroke-width: 1;
		filter: drop-shadow(0 6px 16px rgba(0, 0, 0, 0.45));
	}
	.card-city {
		fill: var(--c-gray-50);
		font-size: 13px;
		font-weight: 700;
	}
	.card-status {
		font-size: 10px;
		font-weight: 600;
	}
	.card-rule {
		stroke: var(--c-gray-700);
		stroke-width: 1;
	}
	.card-role {
		fill: var(--c-gray-100);
		font-size: 12px;
		font-weight: 600;
	}
	.card-detail {
		fill: var(--c-gray-300);
		font-size: 11px;
	}
	.card-host {
		fill: var(--c-gray-400);
		font-size: 10px;
		font-family: ui-monospace, monospace;
	}
	.legend {
		position: absolute;
		left: 14px;
		bottom: 14px;
		display: flex;
		gap: 22px;
		padding: 12px 14px;
		border-radius: 12px;
		background: color-mix(in srgb, var(--c-gray-900) 86%, transparent);
		border: 1px solid var(--c-gray-700);
		backdrop-filter: blur(6px);
	}
	.legend-head {
		font-size: 10px;
		font-weight: 700;
		letter-spacing: 0.08em;
		text-transform: uppercase;
		color: var(--c-brand-100);
		margin-bottom: 8px;
	}
	.legend-row {
		display: flex;
		align-items: center;
		gap: 8px;
		min-height: 20px;
		margin-bottom: 4px;
	}
	.legend-glyph {
		display: inline-flex;
		color: var(--c-gray-100);
	}
	.legend-swatch {
		width: 11px;
		height: 11px;
		border-radius: 50%;
	}
	.legend-text {
		display: flex;
		flex-direction: column;
		line-height: 1.2;
	}
	.legend-text :global(b) {
		font-size: 12px;
		font-weight: 600;
		color: var(--c-gray-50);
	}
	.legend-sub {
		font-size: 10px;
		color: var(--c-gray-300);
	}
	.empty {
		position: absolute;
		inset: 0;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		text-align: center;
		pointer-events: none;
	}
	.empty-title {
		font-size: 15px;
		font-weight: 600;
		color: var(--c-gray-100);
	}
	.empty-sub {
		margin-top: 4px;
		font-size: 13px;
		color: var(--c-gray-300);
	}
	@media (prefers-reduced-motion: reduce) {
		.ping {
			animation: none;
			display: none;
		}
	}
</style>
