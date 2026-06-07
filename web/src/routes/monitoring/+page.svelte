<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { api, errorMessage } from '$lib/api';
	import type { SessionRecord, LiveEvent } from '$lib/types';

	// ───────── Session history ─────────
	let sessions = $state<SessionRecord[]>([]);
	let loading = $state(true);
	let loadError = $state('');

	let fDevice = $state('');
	let fUser = $state('');
	let fNode = $state('');
	let fSourceIP = $state('');
	let fSince = $state('');
	let fLimit = $state(100);

	function fmt(iso: string): string {
		const d = new Date(iso);
		return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
	}
	function clockTime(iso: string): string {
		const d = new Date(iso);
		return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString();
	}

	// connect → green, disconnect → gray, anything else (e.g. alert) → warning.
	function eventBadge(type: string): string {
		if (type === 'connect') return 'badge-success';
		if (type === 'disconnect') return 'badge-gray';
		if (type === 'alert') return 'badge-warning';
		return 'badge-info';
	}

	async function load() {
		loading = true;
		loadError = '';
		try {
			const p = new URLSearchParams();
			if (fDevice) p.set('device', fDevice);
			if (fUser) p.set('user', fUser);
			if (fNode) p.set('node', fNode);
			if (fSourceIP) p.set('source_ip', fSourceIP);
			if (fSince) {
				const d = new Date(fSince);
				if (!Number.isNaN(d.getTime())) p.set('since', d.toISOString());
			}
			p.set('limit', String(fLimit));
			sessions = await api.get<SessionRecord[]>(`/api/sessions?${p.toString()}`);
		} catch (e) {
			loadError = errorMessage(e);
		}
		loading = false;
	}

	function reset() {
		fDevice = '';
		fUser = '';
		fNode = '';
		fSourceIP = '';
		fSince = '';
		fLimit = 100;
		load();
	}

	// ───────── Live events WebSocket ─────────
	// Same wiring as the Fleet page: ws/wss by page scheme, reconnect on drop,
	// torn down on destroy. The session cookie authenticates the upgrade.
	let events = $state<LiveEvent[]>([]);
	let wsConnected = $state(false);
	let ws: WebSocket | null = null;
	let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
	let destroyed = false;

	function connectEvents() {
		if (destroyed) return;
		const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
		ws = new WebSocket(`${scheme}://${location.host}/ws/events`);
		ws.onopen = () => (wsConnected = true);
		ws.onmessage = (m) => {
			try {
				events = [JSON.parse(m.data) as LiveEvent, ...events].slice(0, 100);
			} catch {
				/* ignore malformed frame */
			}
		};
		ws.onclose = () => {
			wsConnected = false;
			if (!destroyed) reconnectTimer = setTimeout(connectEvents, 3000);
		};
		ws.onerror = () => ws?.close();
	}

	// A short human line for a live event — alerts read as a finding, peer events
	// as identity → node.
	function liveLine(ev: LiveEvent): string {
		if (ev.type === 'alert') {
			const a = ev.alert;
			return a ? `${a.severity}: ${a.kind}` : ev.message || 'alert';
		}
		const who = ev.user || ev.device_id || ev.peer_id || '';
		const parts = [who, ev.node_id ? `→ ${ev.node_id}` : ''].filter(Boolean);
		if (ev.source_ip) parts.push(`(${ev.source_ip})`);
		return parts.join(' ') || ev.message || '';
	}

	onMount(() => {
		load();
		connectEvents();
	});
	onDestroy(() => {
		destroyed = true;
		if (reconnectTimer) clearTimeout(reconnectTimer);
		ws?.close();
	});
</script>

<svelte:head><title>Monitoring — coxswain</title></svelte:head>

<div>
	<h1 class="section-title">Monitoring</h1>
	<p class="section-subtitle">
		Live connection events and the persisted, source-IP-aware session history.
	</p>
</div>

<!-- Live feed -->
<div class="mt-6">
	<div class="flex items-center gap-2">
		<h2 class="section-title" style="font-size:16px">Live</h2>
		<span class="badge {wsConnected ? 'badge-success' : 'badge-gray'}">
			<span class="dot" class:pulse={wsConnected}></span>
			{wsConnected ? 'connected' : 'offline'}
		</span>
	</div>
	<div class="mt-3 card p-4">
		{#if events.length === 0}
			<p class="text-sm text-ink-3">
				No live events yet. Connects, disconnects, and analytics alerts appear here in real time.
			</p>
		{:else}
			<ul class="flex flex-col gap-2">
				{#each events as ev, i (i)}
					<li class="flex items-center gap-3 text-sm">
						<span class="tnum text-xs text-ink-3">{clockTime(ev.at)}</span>
						<span class="badge {eventBadge(ev.type)}">{ev.type}</span>
						{#if ev.protocol}<span class="text-xs text-ink-3">{ev.protocol}</span>{/if}
						<span class="text-ink-2">{liveLine(ev)}</span>
					</li>
				{/each}
			</ul>
		{/if}
	</div>
</div>

<!-- Session history -->
<div class="mt-8">
	<h2 class="section-title" style="font-size:16px">Session history</h2>

	<div class="mt-3 card p-4">
		<div class="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-6">
			<div>
				<label class="label" for="f-device">Device</label>
				<input id="f-device" class="input" bind:value={fDevice} placeholder="device id" onkeydown={(e) => e.key === 'Enter' && load()} />
			</div>
			<div>
				<label class="label" for="f-user">User</label>
				<input id="f-user" class="input" bind:value={fUser} placeholder="user id" onkeydown={(e) => e.key === 'Enter' && load()} />
			</div>
			<div>
				<label class="label" for="f-node">Node</label>
				<input id="f-node" class="input" bind:value={fNode} placeholder="node id" onkeydown={(e) => e.key === 'Enter' && load()} />
			</div>
			<div>
				<label class="label" for="f-ip">Source IP</label>
				<input id="f-ip" class="input" bind:value={fSourceIP} placeholder="203.0.113.5" onkeydown={(e) => e.key === 'Enter' && load()} />
			</div>
			<div>
				<label class="label" for="f-since">Since</label>
				<input id="f-since" class="input" type="datetime-local" bind:value={fSince} />
			</div>
			<div>
				<label class="label" for="f-limit">Limit</label>
				<select id="f-limit" class="input" bind:value={fLimit}>
					<option value={50}>50</option>
					<option value={100}>100</option>
					<option value={250}>250</option>
					<option value={500}>500</option>
					<option value={1000}>1000</option>
				</select>
			</div>
		</div>
		<div class="mt-3 flex gap-2">
			<button class="btn btn-primary btn-sm" onclick={load} disabled={loading}>{loading ? 'Loading…' : 'Apply filters'}</button>
			<button class="btn btn-text btn-sm" onclick={reset}>Reset</button>
		</div>
	</div>

	{#if loading}
		<div class="mt-4 card p-6 text-sm text-ink-3">Loading sessions…</div>
	{:else if loadError}
		<div class="mt-4 card p-6 text-sm" style="color: var(--c-danger)">{loadError}</div>
	{:else if sessions.length === 0}
		<div class="mt-4 card p-10 text-center text-sm text-ink-3">No sessions match these filters.</div>
	{:else}
		<div class="mt-4 card overflow-x-auto">
			<table class="dtable">
				<thead>
					<tr>
						<th>Time</th><th>Event</th><th>Device</th><th>User</th>
						<th>Node</th><th>Source IP</th><th>Protocol</th>
					</tr>
				</thead>
				<tbody>
					{#each sessions as s (s.id)}
						<tr>
							<td class="tnum whitespace-nowrap text-ink-2">{fmt(s.at)}</td>
							<td><span class="badge {eventBadge(s.event_type)}">{s.event_type}</span></td>
							<td class="text-ink-2">{s.device_id || '—'}</td>
							<td class="text-ink-2">{s.user_id || '—'}</td>
							<td class="text-ink-2">{s.node_id || '—'}</td>
							<td class="tnum text-ink-2">{s.source_ip || '—'}</td>
							<td class="text-ink-2">{s.protocol || '—'}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
