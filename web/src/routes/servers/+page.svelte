<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<script lang="ts">
	import { onMount } from 'svelte';
	import { api, errorMessage } from '$lib/api';
	import Modal from '$lib/components/Modal.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import RoleGlyph from '$lib/components/RoleGlyph.svelte';
	import type { Node, Relay, Server } from '$lib/types';

	let servers = $state<Server[]>([]);
	let nodes = $state<Node[]>([]);
	let relays = $state<Relay[]>([]);
	let loading = $state(true);
	let loadError = $state('');

	// coxswain's public SSH key — add it as a login key when creating a machine,
	// then onboard with the "key" method (no password).
	let coxKey = $state('');
	let copied = $state(false);

	async function copyKey() {
		try {
			await navigator.clipboard.writeText(coxKey);
			copied = true;
			setTimeout(() => (copied = false), 1500);
		} catch {
			/* clipboard unavailable */
		}
	}

	function locLabel(s: Server): string {
		if (s.location) return [s.location.city, s.location.country].filter(Boolean).join(', ');
		return s.region || '';
	}

	// How many components are deployed on a server (for the remove warning).
	function compCount(id: string): number {
		const c = cards.find((x) => x.server.id === id);
		return c ? c.nodes.length + c.relays.length : 0;
	}

	// A server with the components deployed onto it, resolved by server_id.
	interface ServerCard {
		server: Server;
		nodes: Node[];
		relays: Relay[];
	}
	const cards = $derived<ServerCard[]>(
		servers.map((s) => ({
			server: s,
			nodes: nodes.filter((n) => n.server_id === s.id),
			relays: relays.filter((r) => r.server_id === s.id)
		}))
	);

	// Control-plane provision route: how coxswain reaches a server (direct by
	// default, or through ordered relay hops). MAX_ROUTE_HOPS mirrors the
	// MaxRouteHops code constant.
	const MAX_ROUTE_HOPS = 2;
	const relayById = $derived(new Map(relays.map((r) => [r.id, r])));
	// Relays usable as control-plane hops — active and carrying an egress/onion role.
	const routableRelays = $derived(relays.filter((r) => r.status === 'active' && (r.egress || r.onion)));

	function relayLabel(id: string): string {
		const r = relayById.get(id);
		if (!r) return id;
		return `${r.name || r.host} (${r.onion ? 'onion' : 'egress'})`;
	}
	function routeText(route: string[]): string {
		if (!route || route.length === 0) return 'direct';
		return 'via ' + route.map(relayLabel).join(' → ');
	}

	function statusBadge(s: string): string {
		if (s === 'active') return 'badge-success';
		if (s === 'error' || s === 'unreachable') return 'badge-danger';
		if (s === 'provisioning' || s === 'enrolling') return 'badge-warning';
		if (s === 'stopped') return 'badge-gray';
		return 'badge-info';
	}

	function nodeDetail(n: Node): string {
		if (!n.forwarding) return 'no forwarding';
		const parts = [n.masquerade ? 'NAT egress' : 'routes onward'];
		if (n.isolation) parts.push('isolated');
		return parts.join(' · ');
	}

	function relayDetail(r: Relay): string {
		const parts: string[] = [];
		if (r.egress) parts.push(`egress · hop ${r.egress_hop}`);
		if (r.onion) parts.push('onion');
		return parts.join(' · ') || 'ingress';
	}

	async function load() {
		loading = true;
		loadError = '';
		try {
			[servers, nodes, relays] = await Promise.all([
				api.get<Server[]>('/api/servers'),
				api.get<Node[]>('/api/nodes'),
				api.get<Relay[]>('/api/relays')
			]);
			coxKey = (await api.get<{ public_key: string }>('/api/ssh-key')).public_key;
		} catch (e) {
			loadError = errorMessage(e);
		}
		loading = false;
	}
	onMount(load);

	// ───────── Add server ─────────
	let adding = $state(false);
	let method = $state<'password' | 'key'>('password');
	let sHost = $state('');
	let sUser = $state('root');
	let sPassword = $state('');
	let sName = $state('');
	let sRoute = $state<string[]>([]);
	let sRoutePick = $state('');
	let addBusy = $state(false);
	let addError = $state('');

	function openAdd() {
		adding = true;
		method = 'password';
		sHost = '';
		sUser = 'root';
		sPassword = '';
		sName = '';
		sRoute = [];
		sRoutePick = '';
		addError = '';
	}

	function addRouteHop() {
		if (sRoutePick && sRoute.length < MAX_ROUTE_HOPS && !sRoute.includes(sRoutePick)) {
			sRoute = [...sRoute, sRoutePick];
			sRoutePick = '';
		}
	}

	async function submitAdd() {
		addBusy = true;
		addError = '';
		try {
			await api.post<Server>('/api/servers', {
				ssh_host: sHost,
				ssh_user: sUser,
				name: sName,
				password: method === 'password' ? sPassword : '',
				route: sRoute
			});
			sPassword = '';
			adding = false;
			await load();
		} catch (e) {
			addError = errorMessage(e);
		}
		addBusy = false;
	}

	// ───────── Edit route (re-route an existing server) ─────────
	let editingRoute = $state<Server | null>(null);
	let erRoute = $state<string[]>([]);
	let erPick = $state('');
	let erBusy = $state(false);
	let erError = $state('');

	function openEditRoute(s: Server) {
		editingRoute = s;
		erRoute = [...(s.route ?? [])];
		erPick = '';
		erError = '';
	}
	function addErHop() {
		if (erPick && erRoute.length < MAX_ROUTE_HOPS && !erRoute.includes(erPick)) {
			erRoute = [...erRoute, erPick];
			erPick = '';
		}
	}
	async function submitEditRoute() {
		if (!editingRoute) return;
		erBusy = true;
		erError = '';
		try {
			await api.patch(`/api/servers/${editingRoute.id}/route`, { route: erRoute });
			editingRoute = null;
			await load();
		} catch (e) {
			erError = errorMessage(e);
		}
		erBusy = false;
	}

	// ───────── Deploy a component onto a server ─────────
	let deployFor = $state<Server | null>(null);
	let deployRole = $state<'node' | 'relay'>('node');
	let deployRegion = $state('');
	let deployEgress = $state(true);
	let deployOnion = $state(true);
	let deployBusy = $state(false);
	let deployError = $state('');

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
			await load();
		} catch (e) {
			deployError = errorMessage(e);
		}
		deployBusy = false;
	}

	// ───────── Remove server ─────────
	let removing = $state<Server | null>(null);
	let removeBusy = $state(false);
	let removeError = $state('');

	async function confirmRemove() {
		if (!removing) return;
		removeBusy = true;
		removeError = '';
		try {
			await api.del(`/api/servers/${removing.id}`);
			removing = null;
			await load();
		} catch (e) {
			removeError = errorMessage(e);
		}
		removeBusy = false;
	}

	// ───────── Component version actions (Update / Remove) ─────────
	// busyId marks the in-flight component row; actionError surfaces a failed
	// update at the top of the list.
	let busyId = $state('');
	let actionError = $state('');

	// doUpdate re-installs the configured binary in place (the version-aware
	// Update, offered only when a newer build is available).
	async function doUpdate(kind: 'node' | 'relay', id: string, name: string) {
		busyId = id;
		actionError = '';
		try {
			await api.post(`/api/${kind}s/${id}/update-agent`, {});
			await load();
		} catch (e) {
			actionError = `Update ${name}: ${errorMessage(e)}`;
		}
		busyId = '';
	}

	let removingComp = $state<{ kind: 'node' | 'relay'; id: string; name: string } | null>(null);
	let compRemoveBusy = $state(false);
	let compRemoveError = $state('');

	async function confirmRemoveComp() {
		if (!removingComp) return;
		compRemoveBusy = true;
		compRemoveError = '';
		try {
			await api.del(`/api/${removingComp.kind}s/${removingComp.id}`);
			removingComp = null;
			await load();
		} catch (e) {
			compRemoveError = errorMessage(e);
		}
		compRemoveBusy = false;
	}
</script>

<svelte:head><title>Servers — coxswain</title></svelte:head>

<div class="flex items-center justify-between">
	<div>
		<h1 class="section-title">Servers</h1>
		<p class="section-subtitle">The machines you own. Onboard one with a one-time password, then deploy node and relay roles onto it.</p>
	</div>
	<button class="btn btn-primary" onclick={openAdd}>Add server</button>
</div>

{#if actionError}
	<div class="mt-4 card flex items-center justify-between gap-3 p-3 text-sm" style="color: var(--c-danger)">
		<span>{actionError}</span>
		<button class="btn btn-text btn-sm" onclick={() => (actionError = '')}>Dismiss</button>
	</div>
{/if}

{#if loading}
	<div class="mt-6 card p-6 text-sm text-ink-3">Loading servers…</div>
{:else if loadError}
	<div class="mt-6 card p-6 text-sm" style="color: var(--c-danger)">{loadError}</div>
{:else if cards.length === 0}
	<div class="mt-6 card p-10 text-center">
		<div class="text-base font-semibold text-ink">No servers yet</div>
		<p class="mx-auto mt-1 max-w-md text-sm text-ink-2">
			A server is a machine cox manages. Add one by IP and a one-time password —
			cox installs its key and switches to key auth, then you deploy roles onto it.
		</p>
		<button class="btn btn-primary mt-4" onclick={openAdd}>Add your first server</button>
	</div>
{:else}
	<div class="mt-6 flex flex-col gap-4">
		{#each cards as c (c.server.id)}
			{@const comps = c.nodes.length + c.relays.length}
			<div class="card p-5">
				<div class="flex items-start justify-between gap-4">
					<div class="min-w-0">
						<div class="flex items-center gap-2">
							<span class="text-base font-semibold text-ink">{c.server.name || c.server.ssh_host}</span>
							{#if c.server.is_self}<span class="badge badge-info">controller host</span>{/if}
							<span class="badge {statusBadge(c.server.status)}"><span class="dot"></span>{c.server.status}</span>
						</div>
						<div class="mt-1 text-sm text-ink-3">
							<span class="tnum">{c.server.ssh_host}</span>{#if locLabel(c.server)} · {locLabel(c.server)}{/if}
						</div>
						{#if !c.server.is_self}
							<div class="mt-1 text-xs text-ink-3">Route: {routeText(c.server.route)}</div>
						{/if}
					</div>
					<div class="flex flex-none gap-2">
						<button class="btn btn-secondary btn-sm" onclick={() => openDeploy(c.server)}>Deploy component</button>
						{#if !c.server.is_self}
							<button class="btn btn-text btn-sm" onclick={() => openEditRoute(c.server)}>Route</button>
							<button class="btn btn-text btn-sm" style="color: var(--c-danger)" onclick={() => { removing = c.server; removeError = ''; }}>Remove</button>
						{/if}
					</div>
				</div>

				<!-- Components running under this server -->
				<div class="mt-4 border-t border-line pt-3">
					{#if comps === 0}
						<div class="text-sm text-ink-3">No components running yet — deploy a node or relay.</div>
					{:else}
						<div class="flex flex-col gap-2">
							{#each c.nodes as n (n.id)}
								<div class="comp-row">
									<span class="comp-icon" style="color: var(--c-success)"><RoleGlyph role="node" size={16} /></span>
									<span class="comp-name">{n.name}</span>
									<span class="badge {statusBadge(n.status)}"><span class="dot"></span>{n.status}</span>
									{#if n.version_display}<span class="comp-ver" title="Deployed build">{n.version_display}</span>{/if}
									{#if n.update_available}<span class="badge badge-warning" title="A newer build is available">update</span>{/if}
									<span class="comp-detail">{nodeDetail(n)}</span>
									<span class="comp-actions">
										{#if n.update_available}
											<button class="btn btn-secondary btn-sm" disabled={busyId === n.id} onclick={() => doUpdate('node', n.id, n.name)}>
												{busyId === n.id ? 'Updating…' : `Update → ${n.available_version}`}
											</button>
										{/if}
										<button class="btn btn-text btn-sm" style="color: var(--c-danger)" disabled={busyId === n.id} onclick={() => (removingComp = { kind: 'node', id: n.id, name: n.name })}>Remove</button>
									</span>
								</div>
							{/each}
							{#each c.relays as r (r.id)}
								<div class="comp-row">
									<span class="comp-icon" style="color: var(--c-brand-200)"><RoleGlyph role="relay" size={16} /></span>
									<span class="comp-name">{r.name}</span>
									<span class="badge {statusBadge(r.status)}"><span class="dot"></span>{r.status}</span>
									{#if r.version_display}<span class="comp-ver" title="Deployed build">{r.version_display}</span>{/if}
									{#if r.update_available}<span class="badge badge-warning" title="A newer build is available">update</span>{/if}
									<span class="comp-detail">{relayDetail(r)}</span>
									<span class="comp-actions">
										{#if r.update_available}
											<button class="btn btn-secondary btn-sm" disabled={busyId === r.id} onclick={() => doUpdate('relay', r.id, r.name)}>
												{busyId === r.id ? 'Updating…' : `Update → ${r.available_version}`}
											</button>
										{/if}
										<button class="btn btn-text btn-sm" style="color: var(--c-danger)" disabled={busyId === r.id} onclick={() => (removingComp = { kind: 'relay', id: r.id, name: r.name })}>Remove</button>
									</span>
								</div>
							{/each}
						</div>
					{/if}
				</div>
			</div>
		{/each}
	</div>
{/if}

<!-- Add server -->
{#if adding}
	<Modal title="Add server" onclose={() => (adding = false)}>
		<div class="seg" role="tablist">
			<button type="button" role="tab" aria-selected={method === 'password'} class="seg-btn" class:seg-on={method === 'password'} onclick={() => (method = 'password')}>Password</button>
			<button type="button" role="tab" aria-selected={method === 'key'} class="seg-btn" class:seg-on={method === 'key'} onclick={() => (method = 'key')}>SSH key</button>
		</div>
		<p class="mt-3 text-sm text-ink-2">
			{#if method === 'password'}
				cox logs in once with the password, installs its SSH key, then uses key auth. The password is used once and never stored.
			{:else}
				cox connects with its own SSH key — add the key below as a login key when you create the machine.
			{/if}
		</p>

		<!-- coxswain's public key — paste as a login key at creation -->
		<div class="label-row mt-4">
			<span class="label">coxswain's SSH login key</span>
			<button class="btn btn-text btn-sm" onclick={copyKey} disabled={!coxKey}>{copied ? 'Copied' : 'Copy'}</button>
		</div>
		<code class="keybox">{coxKey || '…'}</code>

		<label class="label mt-4" for="s-host">IP / hostname</label>
		<input id="s-host" class="input" bind:value={sHost} placeholder="203.0.113.10" />
		<div class="mt-3 grid grid-cols-2 gap-3">
			<div>
				<label class="label" for="s-user">SSH user</label>
				<input id="s-user" class="input" bind:value={sUser} />
			</div>
			<div>
				<label class="label" for="s-name">Name (optional)</label>
				<input id="s-name" class="input" bind:value={sName} />
			</div>
		</div>
		{#if method === 'password'}
			<label class="label mt-3" for="s-pass">One-time password</label>
			<input id="s-pass" class="input" type="password" autocomplete="off" bind:value={sPassword} />
		{/if}
		<p class="mt-3 text-xs text-ink-3">The region is resolved automatically from the IP — no need to type it.</p>

		<p class="overline mt-5">Route</p>
		<p class="text-xs text-ink-3">
			How coxswain reaches this machine. <b>Direct</b> (default): your controller dials it itself.
			Add relay hops to reach it through them — the machine then never sees the controller.
		</p>
		<div class="mt-2 flex flex-col gap-2">
			{#each sRoute as id, i (id)}
				<div class="hop-row">
					<span class="hop-kind">Hop {i + 1}</span>
					<span class="hop-name grow">{relayLabel(id)}</span>
					<button class="icon-btn" aria-label="Remove hop" onclick={() => (sRoute = sRoute.filter((_, j) => j !== i))}>✕</button>
				</div>
			{/each}
			{#if sRoute.length === 0}<div class="text-sm text-ink-3">Direct — no relay hops.</div>{/if}
		</div>
		{#if sRoute.length < MAX_ROUTE_HOPS && routableRelays.filter((r) => !sRoute.includes(r.id)).length > 0}
			<div class="mt-2 flex gap-2">
				<select class="input grow" bind:value={sRoutePick}>
					<option value="" disabled>Add a relay hop…</option>
					{#each routableRelays.filter((r) => !sRoute.includes(r.id)) as r (r.id)}
						<option value={r.id}>{r.name || r.host} — {r.region || 'unknown'} ({r.onion ? 'onion' : 'egress'})</option>
					{/each}
				</select>
				<button class="btn btn-secondary" onclick={addRouteHop} disabled={!sRoutePick}>Add hop</button>
			</div>
		{:else if routableRelays.length === 0}
			<p class="mt-1 text-xs text-ink-3">No relays to route through yet — onboard a relay first to use one as a hop.</p>
		{/if}

		{#if addError}<p class="field-error" role="alert">{addError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (adding = false)}>Cancel</button>
			<button class="btn btn-primary" onclick={submitAdd} disabled={addBusy || !sHost || (method === 'password' && !sPassword)}>
				{addBusy ? 'Onboarding…' : 'Onboard'}
			</button>
		</div>
	</Modal>
{/if}

<!-- Deploy a role onto a server -->
{#if deployFor}
	<Modal title="Deploy onto {deployFor.name || deployFor.ssh_host}" onclose={() => (deployFor = null)}>
		<label class="label" for="d-role">Role</label>
		<select id="d-role" class="input" bind:value={deployRole}>
			<option value="node">Node — egress server</option>
			<option value="relay">Relay — control-plane hop</option>
		</select>
		<p class="mt-2 text-xs text-ink-3">Deploys onto {deployFor.ssh_host}; location is resolved from its IP.</p>
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
				{deployBusy ? 'Deploying…' : 'Deploy'}
			</button>
		</div>
	</Modal>
{/if}

<!-- Edit route -->
{#if editingRoute}
	<Modal title="Route to {editingRoute.name || editingRoute.ssh_host}" onclose={() => (editingRoute = null)}>
		<p class="text-xs text-ink-3">
			<b>Direct</b>: your controller dials this machine itself (its logs see the controller).
			Add relay hops to reach it through them instead. Applies to future deploys and the node's control plane.
		</p>
		<div class="mt-3 flex flex-col gap-2">
			{#each erRoute as id, i (id)}
				<div class="hop-row">
					<span class="hop-kind">Hop {i + 1}</span>
					<span class="hop-name grow">{relayLabel(id)}</span>
					<button class="icon-btn" aria-label="Remove hop" onclick={() => (erRoute = erRoute.filter((_, j) => j !== i))}>✕</button>
				</div>
			{/each}
			{#if erRoute.length === 0}<div class="text-sm text-ink-3">Direct — no relay hops.</div>{/if}
		</div>
		{#if erRoute.length < MAX_ROUTE_HOPS && routableRelays.filter((r) => !erRoute.includes(r.id)).length > 0}
			<div class="mt-2 flex gap-2">
				<select class="input grow" bind:value={erPick}>
					<option value="" disabled>Add a relay hop…</option>
					{#each routableRelays.filter((r) => !erRoute.includes(r.id)) as r (r.id)}
						<option value={r.id}>{r.name || r.host} — {r.region || 'unknown'} ({r.onion ? 'onion' : 'egress'})</option>
					{/each}
				</select>
				<button class="btn btn-secondary" onclick={addErHop} disabled={!erPick}>Add hop</button>
			</div>
		{:else if routableRelays.length === 0}
			<p class="mt-1 text-xs text-ink-3">No relays to route through yet.</p>
		{/if}
		{#if erError}<p class="field-error" role="alert">{erError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (editingRoute = null)}>Cancel</button>
			<button class="btn btn-primary" onclick={submitEditRoute} disabled={erBusy}>{erBusy ? 'Saving…' : 'Save route'}</button>
		</div>
	</Modal>
{/if}

<!-- Remove server -->
{#if removing}
	<Modal title="Remove server" onclose={() => (removing = null)}>
		<p class="text-sm text-ink-2">
			Remove <span class="font-medium text-ink">{removing.name || removing.ssh_host}</span>
			from the inventory? This forgets it from coxswain — it doesn't touch the machine.
		</p>
		{#if compCount(removing.id) > 0}
			<p class="mt-2 text-sm" style="color: var(--c-warning)">
				This also removes {compCount(removing.id)} component{compCount(removing.id) === 1 ? '' : 's'} deployed on it.
			</p>
		{/if}
		{#if removeError}<p class="field-error" role="alert">{removeError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (removing = null)}>Cancel</button>
			<button class="btn btn-danger" onclick={confirmRemove} disabled={removeBusy}>
				{removeBusy ? 'Removing…' : 'Remove'}
			</button>
		</div>
	</Modal>
{/if}

<!-- Remove a component (node / relay) -->
{#if removingComp}
	<Modal title="Remove {removingComp.kind}" onclose={() => (removingComp = null)}>
		<p class="text-sm text-ink-2">
			Remove <span class="font-medium text-ink">{removingComp.name}</span> from the fleet?
			This forgets it from coxswain — it doesn't uninstall the agent on the machine.
		</p>
		{#if compRemoveError}<p class="field-error" role="alert">{compRemoveError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (removingComp = null)}>Cancel</button>
			<button class="btn btn-danger" onclick={confirmRemoveComp} disabled={compRemoveBusy}>
				{compRemoveBusy ? 'Removing…' : 'Remove'}
			</button>
		</div>
	</Modal>
{/if}

<style>
	.comp-row {
		display: flex;
		align-items: center;
		gap: 10px;
	}
	.comp-icon {
		display: inline-flex;
		flex: none;
	}
	.comp-name {
		font-size: 14px;
		font-weight: 500;
		color: var(--c-gray-50);
		min-width: 0;
	}
	.comp-ver {
		font-family: ui-monospace, monospace;
		font-size: 11px;
		color: var(--c-gray-300);
		white-space: nowrap;
	}
	.comp-detail {
		font-size: 12px;
		color: var(--c-gray-300);
	}
	.comp-actions {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		margin-left: auto;
		flex: none;
	}
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
	.toggle-text {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	.seg {
		display: inline-flex;
		overflow: hidden;
		border: 1px solid var(--c-line);
		border-radius: 8px;
	}
	.seg-btn {
		padding: 6px 16px;
		font-size: 13px;
		font-weight: 500;
		color: var(--c-gray-300);
		background: transparent;
		border: none;
		cursor: pointer;
	}
	.seg-btn + .seg-btn {
		border-left: 1px solid var(--c-line);
	}
	.seg-on {
		background: var(--hover-overlay);
		color: var(--c-brand-100);
	}
	.label-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.keybox {
		display: block;
		margin-top: 6px;
		padding: 10px 12px;
		border: 1px solid var(--c-line);
		border-radius: 8px;
		background: var(--c-bg);
		font-family: ui-monospace, monospace;
		font-size: 12px;
		color: var(--c-gray-200);
		word-break: break-all;
	}
	.hop-row {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 8px 12px;
		border: 1px solid var(--c-line);
		border-radius: 8px;
	}
	.hop-kind {
		font-size: 10px;
		font-weight: 700;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--c-brand-100);
	}
	.hop-name {
		font-size: 13px;
		font-weight: 500;
		color: var(--c-gray-50);
	}
	.grow {
		flex: 1 1 auto;
		min-width: 0;
	}
	.icon-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 28px;
		height: 28px;
		border: 1px solid var(--c-line);
		border-radius: 6px;
		background: transparent;
		color: var(--c-gray-200);
		cursor: pointer;
	}
</style>
