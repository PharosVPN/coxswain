<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { api, errorMessage, isApiError } from '$lib/api';
	import Modal from '$lib/components/Modal.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import FleetMap from '$lib/components/FleetMap.svelte';
	import type { Node, Relay, Server, Site, NodeLink, LiveEvent } from '$lib/types';

	interface Rules {
		pre_up: string[];
		post_up: string[];
		post_down: string[];
	}

	let nodes = $state<Node[]>([]);
	let relays = $state<Relay[]>([]);
	let links = $state<NodeLink[]>([]);
	let servers = $state<Server[]>([]);
	let loading = $state(true);
	let loadError = $state('');

	// Add-server modal (onboard by IP + user + one-time password).
	let addingServer = $state(false);
	let sHost = $state('');
	let sUser = $state('root');
	let sPassword = $state('');
	let sName = $state('');
	let sRegion = $state('');
	let addBusy = $state(false);
	let addError = $state('');

	// Deploy-component modal.
	let deployFor = $state<Server | null>(null);
	let deployRole = $state<'node' | 'relay'>('node');
	let deployRegion = $state('');
	let deployEgress = $state(true);
	let deployOnion = $state(true);
	let deployBusy = $state(false);
	let deployError = $state('');

	let removingServer = $state<Server | null>(null);
	let removeServerBusy = $state(false);
	let removeServerError = $state('');

	let events = $state<LiveEvent[]>([]);
	let wsConnected = $state(false);

	// Node settings modal — name + network policy.
	let editing = $state<Node | null>(null);
	let editName = $state('');
	let fwd = $state(true);
	let masq = $state(true);
	let iso = $state(false);
	let editError = $state('');
	let editBusy = $state(false);
	let advancedOpen = $state(false);
	let rules = $state<Rules | null>(null);

	let deleting = $state<Node | null>(null);
	let deleteError = $state('');
	let deleteBusy = $state(false);

	const total = $derived(nodes.length);
	const activeCount = $derived(nodes.filter((n) => n.status === 'active').length);
	const attentionCount = $derived(
		nodes.filter((n) => n.status === 'error' || n.status === 'unreachable').length
	);

	function statusBadge(s: string): string {
		if (s === 'active') return 'badge-success';
		if (s === 'error' || s === 'unreachable') return 'badge-danger';
		if (s === 'provisioning' || s === 'enrolling') return 'badge-warning';
		if (s === 'stopped') return 'badge-gray';
		return 'badge-info';
	}

	function clockTime(iso: string): string {
		const d = new Date(iso);
		return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString();
	}

	function policyLabel(n: Node): string {
		if (!n.forwarding) return 'no forwarding';
		const parts = ['forwarding'];
		if (n.masquerade) parts.push('NAT');
		if (n.isolation) parts.push('isolated');
		return parts.join(' · ');
	}

	async function loadNodes() {
		loading = true;
		loadError = '';
		try {
			nodes = await api.get<Node[]>('/api/nodes');
			// Relays + links enrich the map with relay roles and route arcs;
			// tolerate their absence on older controllers.
			try {
				[relays, links, servers] = await Promise.all([
					api.get<Relay[]>('/api/relays'),
					api.get<NodeLink[]>('/api/node-links'),
					api.get<Server[]>('/api/servers')
				]);
			} catch {
				relays = [];
				links = [];
				servers = [];
			}
		} catch (e) {
			loadError = errorMessage(e);
		}
		loading = false;
	}

	function selectSite(s: Site) {
		if (s.node) openEdit(s.node);
	}

	// ───────── Live events WebSocket ─────────
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
				events = [JSON.parse(m.data) as LiveEvent, ...events].slice(0, 50);
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

	onMount(() => {
		loadNodes();
		connectEvents();
	});
	onDestroy(() => {
		destroyed = true;
		if (reconnectTimer) clearTimeout(reconnectTimer);
		ws?.close();
	});

	// ───────── Node settings ─────────
	function openEdit(n: Node) {
		editing = n;
		editName = n.name;
		fwd = n.forwarding;
		masq = n.masquerade;
		iso = n.isolation;
		editError = '';
		advancedOpen = false;
		rules = null;
	}

	// Masquerade and isolation require forwarding — clamp when it is off.
	$effect(() => {
		if (!fwd && (masq || iso)) {
			masq = false;
			iso = false;
		}
	});

	// Refresh the rule preview whenever the policy changes while editing.
	$effect(() => {
		if (!editing) return;
		const body = { forwarding: fwd, masquerade: masq, isolation: iso };
		api.post<Rules>('/api/network-policy/preview', body)
			.then((r) => (rules = r))
			.catch(() => (rules = null));
	});

	async function submitEdit() {
		if (!editing) return;
		editBusy = true;
		editError = '';
		try {
			const updated = await api.patch<Node>(`/api/nodes/${editing.id}`, {
				version: editing.version,
				name: editName,
				forwarding: fwd,
				masquerade: masq,
				isolation: iso
			});
			nodes = nodes.map((n) => (n.id === updated.id ? updated : n));
			editing = null;
		} catch (e) {
			editError = errorMessage(e);
			if (isApiError(e) && e.status === 409) loadNodes();
		}
		editBusy = false;
	}

	// ───────── Servers ─────────
	function openAddServer() {
		addingServer = true;
		sHost = '';
		sUser = 'root';
		sPassword = '';
		sName = '';
		sRegion = '';
		addError = '';
	}

	async function submitAddServer() {
		addBusy = true;
		addError = '';
		try {
			await api.post<Server>('/api/servers', {
				ssh_host: sHost,
				ssh_user: sUser,
				password: sPassword,
				name: sName,
				region: sRegion
			});
			sPassword = '';
			addingServer = false;
			await loadNodes();
		} catch (e) {
			addError = errorMessage(e);
		}
		addBusy = false;
	}

	function openDeploy(s: Server) {
		deployFor = s;
		deployRole = 'node';
		deployRegion = s.region;
		deployEgress = true;
		deployOnion = true;
		deployError = '';
	}

	async function submitDeploy() {
		if (!deployFor) return;
		deployBusy = true;
		deployError = '';
		try {
			const body: Record<string, unknown> = { role: deployRole, region: deployRegion };
			if (deployRole === 'relay') {
				body.egress = deployEgress;
				body.onion = deployOnion;
			}
			await api.post(`/api/servers/${deployFor.id}/deploy`, body);
			deployFor = null;
			await loadNodes();
		} catch (e) {
			deployError = errorMessage(e);
		}
		deployBusy = false;
	}

	async function confirmRemoveServer() {
		if (!removingServer) return;
		removeServerBusy = true;
		removeServerError = '';
		try {
			await api.del(`/api/servers/${removingServer.id}`);
			servers = servers.filter((s) => s.id !== removingServer!.id);
			removingServer = null;
		} catch (e) {
			removeServerError = errorMessage(e);
		}
		removeServerBusy = false;
	}

	// ───────── Delete ─────────
	async function confirmDelete() {
		if (!deleting) return;
		deleteBusy = true;
		deleteError = '';
		try {
			await api.del(`/api/nodes/${deleting.id}`);
			nodes = nodes.filter((n) => n.id !== deleting!.id);
			deleting = null;
		} catch (e) {
			deleteError = errorMessage(e);
		}
		deleteBusy = false;
	}
</script>

<svelte:head><title>Fleet — coxswain</title></svelte:head>

<h1 class="section-title">Fleet</h1>
<p class="section-subtitle">Where your fleet lives. Click a city to open its node.</p>

{#if !loading && !loadError}
	<div class="mt-6">
		<FleetMap {nodes} {relays} {links} {servers} selectedKey={editing?.public_ip ?? ''} onselect={selectSite} />
	</div>
{/if}

<div class="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
	{#each [{ label: 'Total nodes', value: total }, { label: 'Active', value: activeCount }, { label: 'Needs attention', value: attentionCount }] as stat (stat.label)}
		<div class="card p-5">
			<div class="tnum text-[28px] font-bold text-ink">{stat.value}</div>
			<div class="mt-1 text-sm text-ink-2">{stat.label}</div>
		</div>
	{/each}
</div>

<div class="mt-8 card overflow-hidden">
	{#if loading}
		<div class="p-6 text-sm text-ink-3">Loading nodes…</div>
	{:else if loadError}
		<div class="p-6 text-sm" style="color: var(--c-danger)">{loadError}</div>
	{:else if nodes.length === 0}
		<div class="p-8 text-center">
			<div class="text-base font-semibold text-ink">No nodes yet</div>
			<p class="mt-1 text-sm text-ink-2">
				Onboard one with <code>cox nodes add &lt;ssh-host&gt; --region &lt;region&gt;</code>.
			</p>
		</div>
	{:else}
		<table class="dtable">
			<thead>
				<tr>
					<th>Name</th><th>Region</th><th>Status</th><th>Network</th>
					<th>Agent</th><th class="text-right">Actions</th>
				</tr>
			</thead>
			<tbody>
				{#each nodes as n (n.id)}
					<tr>
						<td class="font-medium">{n.name}</td>
						<td class="text-ink-2">{n.region}</td>
						<td>
							<span class="badge {statusBadge(n.status)}">
								<span class="dot"></span>{n.status}
							</span>
						</td>
						<td class="text-ink-2">{policyLabel(n)}</td>
						<td class="text-ink-2">{n.agent_version || '—'}</td>
						<td class="text-right whitespace-nowrap">
							<button class="btn btn-text btn-sm" onclick={() => openEdit(n)}>Settings</button>
							<button
								class="btn btn-text btn-sm"
								style="color: var(--c-danger)"
								onclick={() => {
									deleting = n;
									deleteError = '';
								}}>Remove</button
							>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
</div>

<div class="mt-8">
	<div class="flex items-center justify-between">
		<h2 class="section-title">Servers</h2>
		<button class="btn btn-primary btn-sm" onclick={openAddServer}>Add server</button>
	</div>
	<p class="section-subtitle">Machines cox owns. Onboard one with an IP + a one-time password, then deploy node/relay roles onto it.</p>
	<div class="mt-4 card overflow-hidden">
		{#if servers.length === 0}
			<div class="p-6 text-sm text-ink-3">No servers yet. Click âAdd serverâ to onboard a machine by password.</div>
		{:else}
			<table class="dtable">
				<thead>
					<tr><th>Name</th><th>Host</th><th>Region</th><th>Status</th><th>Self</th><th class="text-right">Actions</th></tr>
				</thead>
				<tbody>
					{#each servers as s (s.id)}
						<tr>
							<td class="font-medium">{s.name || 'â'}</td>
							<td class="text-ink-2">{s.ssh_host}</td>
							<td class="text-ink-2">{s.region || 'â'}</td>
							<td><span class="badge {statusBadge(s.status)}"><span class="dot"></span>{s.status}</span></td>
							<td class="text-ink-2">{s.is_self ? 'yes' : ''}</td>
							<td class="text-right whitespace-nowrap">
								<button class="btn btn-text btn-sm" onclick={() => openDeploy(s)}>Deploy</button>
								{#if !s.is_self}
									<button class="btn btn-text btn-sm" style="color: var(--c-danger)" onclick={() => { removingServer = s; removeServerError = ''; }}>Remove</button>
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</div>
</div>

<div class="mt-8">
	<div class="flex items-center gap-2">
		<h2 class="section-title">Live events</h2>
		<span class="badge {wsConnected ? 'badge-success' : 'badge-gray'}">
			<span class="dot" class:pulse={wsConnected}></span>
			{wsConnected ? 'connected' : 'offline'}
		</span>
	</div>
	<div class="mt-4 card p-4">
		{#if events.length === 0}
			<p class="text-sm text-ink-3">
				No events yet. Node handshakes and peer changes appear here in real time.
			</p>
		{:else}
			<ul class="flex flex-col gap-2">
				{#each events as ev, i (i)}
					<li class="flex items-center gap-3 text-sm">
						<span class="tnum text-xs text-ink-3">{clockTime(ev.at)}</span>
						<span class="badge badge-info">{ev.type}</span>
						<span class="text-ink-2">{ev.node_id}</span>
						{#if ev.message}<span class="text-ink-3">{ev.message}</span>{/if}
					</li>
				{/each}
			</ul>
		{/if}
	</div>
</div>

<!-- Node settings: name + network policy -->
{#if editing}
	<Modal title="Node settings" onclose={() => (editing = null)}>
		<label class="label" for="node-name">Node name</label>
		<input id="node-name" class="input" bind:value={editName} />

		<p class="overline mt-6">Network policy</p>
		<div class="mt-2 flex flex-col">
			<button
				type="button"
				role="switch"
				aria-checked={fwd}
				class="toggle-row"
				onclick={() => (fwd = !fwd)}
			>
				<span class="toggle-text">
					<span class="text-sm font-medium text-ink">Forwarding</span>
					<span class="text-xs text-ink-3">Route client traffic onward. Off makes the node a dead end.</span>
				</span>
				<Switch checked={fwd} />
			</button>

			<button
				type="button"
				role="switch"
				aria-checked={masq}
				class="toggle-row"
				disabled={!fwd}
				onclick={() => (masq = !masq)}
			>
				<span class="toggle-text">
					<span class="text-sm font-medium text-ink">Masquerade (NAT)</span>
					<span class="text-xs text-ink-3">On: clients share the node's IP. Off: destinations see the client's tunnel IP.</span>
				</span>
				<Switch checked={masq} disabled={!fwd} />
			</button>

			<button
				type="button"
				role="switch"
				aria-checked={iso}
				class="toggle-row"
				disabled={!fwd}
				onclick={() => (iso = !iso)}
			>
				<span class="toggle-text">
					<span class="text-sm font-medium text-ink">Client isolation</span>
					<span class="text-xs text-ink-3">On: clients cannot reach each other. Off: clients route peer-to-peer.</span>
				</span>
				<Switch checked={iso} disabled={!fwd} />
			</button>
		</div>

		<details class="mt-4" bind:open={advancedOpen}>
			<summary class="cursor-pointer text-xs font-medium text-brand">
				Advanced — generated firewall rules
			</summary>
			<div class="mt-2 rounded-md border border-line bg-bg p-3">
				{#if rules}
					{#each [{ h: 'PreUp', lines: rules.pre_up }, { h: 'PostUp', lines: rules.post_up }, { h: 'PostDown', lines: rules.post_down }] as group (group.h)}
						{#if group.lines.length}
							<div class="mb-2 last:mb-0">
								<div class="text-[11px] font-semibold text-ink-3">{group.h}</div>
								{#each group.lines as line (line)}
									<div class="font-mono text-xs text-ink-2">{line}</div>
								{/each}
							</div>
						{/if}
					{/each}
					{#if !rules.pre_up.length && !rules.post_up.length}
						<div class="text-xs text-ink-3">No rules — forwarding is off.</div>
					{/if}
					<div class="mt-2 text-[11px] text-ink-4">
						%i = the WireGuard interface · %e = the node's egress interface (autodetected by the node)
					</div>
				{:else}
					<div class="text-xs text-ink-3">Generating…</div>
				{/if}
			</div>
		</details>

		{#if editError}<p class="field-error" role="alert">{editError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (editing = null)}>Cancel</button>
			<button class="btn btn-primary" onclick={submitEdit} disabled={editBusy}>
				{editBusy ? 'Saving…' : 'Save'}
			</button>
		</div>
	</Modal>
{/if}

<!-- Delete confirmation -->
{#if deleting}
	<Modal title="Remove node" onclose={() => (deleting = null)}>
		<p class="text-sm text-ink-2">
			Remove <span class="font-medium text-ink">{deleting.name}</span> from the fleet
			inventory? This does not touch the VM.
		</p>
		{#if deleteError}<p class="field-error" role="alert">{deleteError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (deleting = null)}>Cancel</button>
			<button class="btn btn-danger" onclick={confirmDelete} disabled={deleteBusy}>
				{deleteBusy ? 'Removing…' : 'Remove'}
			</button>
		</div>
	</Modal>
{/if}

<!-- Add server: onboard by IP + one-time password -->
{#if addingServer}
	<Modal title="Add server" onclose={() => (addingServer = false)}>
		<p class="text-sm text-ink-2">
			cox SSHes in once with this password, installs its key, then uses key auth.
			The password is used once and never stored.
		</p>
		<label class="label mt-4" for="s-host">IP / hostname</label>
		<input id="s-host" class="input" bind:value={sHost} placeholder="203.0.113.10" />
		<div class="mt-3 grid grid-cols-2 gap-3">
			<div>
				<label class="label" for="s-user">SSH user</label>
				<input id="s-user" class="input" bind:value={sUser} />
			</div>
			<div>
				<label class="label" for="s-region">Region</label>
				<input id="s-region" class="input" bind:value={sRegion} placeholder="nyc1" />
			</div>
		</div>
		<label class="label mt-3" for="s-pass">One-time password</label>
		<input id="s-pass" class="input" type="password" autocomplete="off" bind:value={sPassword} />
		<label class="label mt-3" for="s-name">Name (optional)</label>
		<input id="s-name" class="input" bind:value={sName} />
		{#if addError}<p class="field-error" role="alert">{addError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (addingServer = false)}>Cancel</button>
			<button class="btn btn-primary" onclick={submitAddServer} disabled={addBusy || !sHost || !sPassword}>
				{addBusy ? 'Onboardingâ¦' : 'Onboard'}
			</button>
		</div>
	</Modal>
{/if}

<!-- Deploy a role onto a server -->
{#if deployFor}
	<Modal title="Deploy onto {deployFor.name || deployFor.ssh_host}" onclose={() => (deployFor = null)}>
		<label class="label" for="d-role">Role</label>
		<select id="d-role" class="input" bind:value={deployRole}>
			<option value="node">Node â egress server</option>
			<option value="relay">Relay â control-plane hop</option>
		</select>
		<label class="label mt-3" for="d-region">Region</label>
		<input id="d-region" class="input" bind:value={deployRegion} placeholder="nyc1" />
		{#if deployRole === 'relay'}
			<p class="overline mt-4">Relay roles</p>
			{#if deployFor.is_self}
				<p class="text-xs text-ink-3">On the controller host a relay is egress/onion only (no client ingress).</p>
			{/if}
			<button type="button" role="switch" aria-checked={deployEgress} class="toggle-row" onclick={() => (deployEgress = !deployEgress)}>
				<span class="toggle-text">
					<span class="text-sm font-medium text-ink">Egress hop</span>
					<span class="text-xs text-ink-3">Route the controller's traffic through this relay (decision 19).</span>
				</span>
				<Switch checked={deployEgress} />
			</button>
			<button type="button" role="switch" aria-checked={deployOnion} class="toggle-row" onclick={() => (deployOnion = !deployOnion)}>
				<span class="toggle-text">
					<span class="text-sm font-medium text-ink">Onion hop</span>
					<span class="text-xs text-ink-3">Peel one onion layer (requires egress).</span>
				</span>
				<Switch checked={deployOnion} />
			</button>
		{/if}
		{#if deployError}<p class="field-error" role="alert">{deployError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (deployFor = null)}>Cancel</button>
			<button class="btn btn-primary" onclick={submitDeploy} disabled={deployBusy}>
				{deployBusy ? 'Deployingâ¦' : 'Deploy'}
			</button>
		</div>
	</Modal>
{/if}

<!-- Remove server confirmation -->
{#if removingServer}
	<Modal title="Remove server" onclose={() => (removingServer = null)}>
		<p class="text-sm text-ink-2">
			Remove <span class="font-medium text-ink">{removingServer.name || removingServer.ssh_host}</span>
			from the inventory? It must have no deployed roles.
		</p>
		{#if removeServerError}<p class="field-error" role="alert">{removeServerError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (removingServer = null)}>Cancel</button>
			<button class="btn btn-danger" onclick={confirmRemoveServer} disabled={removeServerBusy}>
				{removeServerBusy ? 'Removingâ¦' : 'Remove'}
			</button>
		</div>
	</Modal>
{/if}

<style>
	.toggle-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 16px;
		min-height: 48px;
		padding: 8px 0;
		background: transparent;
		border: none;
		text-align: left;
		cursor: pointer;
	}
	.toggle-row:disabled {
		cursor: not-allowed;
	}
	.toggle-text {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
</style>
