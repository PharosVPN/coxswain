<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<script lang="ts">
	import { onMount } from 'svelte';
	import { api, errorMessage } from '$lib/api';
	import Modal from '$lib/components/Modal.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import type { Node, Path, Relay, ControlPath } from '$lib/types';

	// MaxPathHops in the controller is 2 inner-link segments → at most 3 nodes
	// (entry → mid → exit). Kept in lockstep with cascade.MaxPathHops.
	const MAX_NODES = 3;
	// Control paths chain relay hops; cap the picker at a sane depth.
	const MAX_CONTROL_HOPS = 3;

	let paths = $state<Path[]>([]);
	let nodes = $state<Node[]>([]);
	let relays = $state<Relay[]>([]);
	let controlPaths = $state<ControlPath[]>([]);
	let loading = $state(true);
	let loadError = $state('');

	const byId = $derived(new Map(nodes.map((n) => [n.id, n])));
	const relayById = $derived(new Map(relays.map((r) => [r.id, r])));
	// Relays usable as control hops: active and carrying an egress/onion role.
	const routableRelays = $derived(relays.filter((r) => r.status === 'active' && (r.egress || r.onion)));

	function nodeName(id: string): string {
		return byId.get(id)?.name ?? id;
	}
	function relayName(id: string): string {
		const r = relayById.get(id);
		return r ? r.name || r.host || id : id;
	}

	function hopRole(i: number, len: number): string {
		if (i === 0) return 'Entry';
		if (i === len - 1) return 'Exit';
		return 'Mid';
	}

	function statusBadge(s: string): string {
		if (s === 'active') return 'badge-success';
		if (s === 'error' || s === 'unreachable') return 'badge-danger';
		if (s === 'pending' || s === 'provisioning') return 'badge-warning';
		return 'badge-info';
	}

	async function load() {
		loading = true;
		loadError = '';
		try {
			[paths, nodes, relays, controlPaths] = await Promise.all([
				api.get<Path[]>('/api/paths'),
				api.get<Node[]>('/api/nodes'),
				api.get<Relay[]>('/api/relays'),
				api.get<ControlPath[]>('/api/control-paths')
			]);
		} catch (e) {
			loadError = errorMessage(e);
		}
		loading = false;
	}
	onMount(load);

	// ───────── Add data path (hop-stacker) ─────────
	let adding = $state(false);
	let pName = $state('');
	let pColor = $state('');
	let stack = $state<string[]>([]);
	let pick = $state('');
	let addBusy = $state(false);
	let addError = $state('');

	const available = $derived(nodes.filter((n) => !stack.includes(n.id)));

	function openAdd() {
		adding = true;
		pName = '';
		pColor = '';
		stack = [];
		pick = '';
		addError = '';
	}

	function addHop() {
		if (pick && stack.length < MAX_NODES && !stack.includes(pick)) {
			stack = [...stack, pick];
			pick = '';
		}
	}
	function removeHop(i: number) {
		stack = stack.filter((_, j) => j !== i);
	}
	function move(i: number, d: number) {
		const j = i + d;
		if (j < 0 || j >= stack.length) return;
		const next = [...stack];
		[next[i], next[j]] = [next[j], next[i]];
		stack = next;
	}

	async function submitAdd() {
		addBusy = true;
		addError = '';
		try {
			await api.post<Path>('/api/paths', { name: pName, color: pColor, node_ids: stack });
			adding = false;
			await load();
		} catch (e) {
			addError = errorMessage(e);
		}
		addBusy = false;
	}

	// ───────── Re-provision data path ─────────
	let busyId = $state('');
	async function reprovision(p: Path) {
		busyId = p.id;
		try {
			await api.post(`/api/paths/${p.id}/provision`);
			await load();
		} catch (e) {
			loadError = errorMessage(e);
		}
		busyId = '';
	}

	// ───────── Remove data path ─────────
	let removing = $state<Path | null>(null);
	let removeBusy = $state(false);
	let removeError = $state('');

	async function confirmRemove() {
		if (!removing) return;
		removeBusy = true;
		removeError = '';
		try {
			await api.del(`/api/paths/${removing.id}`);
			removing = null;
			await load();
		} catch (e) {
			removeError = errorMessage(e);
		}
		removeBusy = false;
	}

	// ───────── Control plane paths ─────────
	function controlChain(hops: string[]): string {
		return hops.length ? hops.map(relayName).join(' → ') : 'direct';
	}

	// Add a control path (relay hop-stacker; empty = a named "direct" route).
	let cpAdding = $state(false);
	let cpName = $state('');
	let cpStack = $state<string[]>([]);
	let cpPick = $state('');
	let cpActivate = $state(true);
	let cpBusy = $state(false);
	let cpError = $state('');
	const cpAvailable = $derived(routableRelays.filter((r) => !cpStack.includes(r.id)));

	function openCpAdd() {
		cpAdding = true;
		cpName = '';
		cpStack = [];
		cpPick = '';
		cpActivate = controlPaths.length === 0; // first path: activate by default
		cpError = '';
	}
	function addCpHop() {
		if (cpPick && cpStack.length < MAX_CONTROL_HOPS && !cpStack.includes(cpPick)) {
			cpStack = [...cpStack, cpPick];
			cpPick = '';
		}
	}
	function removeCpHop(i: number) {
		cpStack = cpStack.filter((_, j) => j !== i);
	}
	function moveCp(i: number, d: number) {
		const j = i + d;
		if (j < 0 || j >= cpStack.length) return;
		const next = [...cpStack];
		[next[i], next[j]] = [next[j], next[i]];
		cpStack = next;
	}
	async function submitCpAdd() {
		cpBusy = true;
		cpError = '';
		try {
			const created = await api.post<ControlPath>('/api/control-paths', { name: cpName, hops: cpStack });
			if (cpActivate) await api.post(`/api/control-paths/${created.id}/activate`);
			cpAdding = false;
			await load();
		} catch (e) {
			cpError = errorMessage(e);
		}
		cpBusy = false;
	}

	let cpActBusy = $state('');
	async function activateCp(p: ControlPath) {
		cpActBusy = p.id;
		try {
			await api.post(`/api/control-paths/${p.id}/activate`);
			await load();
		} catch (e) {
			loadError = errorMessage(e);
		}
		cpActBusy = '';
	}

	let cpRemoving = $state<ControlPath | null>(null);
	let cpRemoveBusy = $state(false);
	let cpRemoveError = $state('');
	async function confirmCpRemove() {
		if (!cpRemoving) return;
		cpRemoveBusy = true;
		cpRemoveError = '';
		try {
			await api.del(`/api/control-paths/${cpRemoving.id}`);
			cpRemoving = null;
			await load();
		} catch (e) {
			cpRemoveError = errorMessage(e);
		}
		cpRemoveBusy = false;
	}
</script>

<svelte:head><title>Paths — coxswain</title></svelte:head>

<h1 class="section-title">Paths</h1>
<p class="section-subtitle">
	Two kinds of route: the <b>control plane</b> (how coxswain reaches your nodes) and the
	<b>data planes</b> (how a client's traffic egresses).
</p>

{#if loading}
	<div class="mt-6 card p-6 text-sm text-ink-3">Loading paths…</div>
{:else if loadError}
	<div class="mt-6 card p-6 text-sm" style="color: var(--c-danger)">{loadError}</div>
{:else}
	<!-- ───────── Control plane ───────── -->
	<div class="mt-8 flex items-center justify-between">
		<div>
			<h2 class="subhead">Control plane</h2>
			<p class="subhead-sub">
				The fleet-wide route coxswain dials out through to reach every node. Exactly one is active —
				activating another reroutes the whole control plane live, no re-onboarding.
			</p>
		</div>
		<button class="btn btn-secondary" onclick={openCpAdd}>Add control path</button>
	</div>

	{#if controlPaths.length === 0}
		<div class="mt-4 card p-6 text-sm text-ink-2">
			No control paths — coxswain reaches nodes <b>directly</b>. Add one to route the control plane
			through relays and hide the controller's origin.
		</div>
	{:else}
		<div class="mt-4 flex flex-col gap-3">
			{#each controlPaths as p (p.id)}
				<div class="card p-5">
					<div class="flex items-start justify-between gap-4">
						<div class="min-w-0">
							<div class="flex items-center gap-2">
								<span class="text-base font-semibold text-ink">{p.name}</span>
								{#if p.active}<span class="badge badge-success"><span class="dot"></span>active</span>{/if}
							</div>
							<div class="chain mt-2">
								{#if p.hops.length === 0}
									<span class="hop"><span class="hop-name">direct</span></span>
								{:else}
									{#each p.hops as h, i (h)}
										{#if i > 0}<span class="arrow">→</span>{/if}
										<span class="hop">
											<span class="hop-kind">Hop {i + 1}</span>
											<span class="hop-name">{relayName(h)}</span>
										</span>
									{/each}
								{/if}
							</div>
						</div>
						<div class="flex flex-none gap-2">
							{#if !p.active}
								<button class="btn btn-secondary btn-sm" disabled={cpActBusy === p.id} onclick={() => activateCp(p)}>
									{cpActBusy === p.id ? 'Activating…' : 'Activate'}
								</button>
							{/if}
							<button class="btn btn-text btn-sm" style="color: var(--c-danger)" onclick={() => { cpRemoving = p; cpRemoveError = ''; }}>Remove</button>
						</div>
					</div>
				</div>
			{/each}
		</div>
	{/if}

	<!-- ───────── Data planes ───────── -->
	<div class="mt-10 flex items-center justify-between">
		<div>
			<h2 class="subhead">Data planes</h2>
			<p class="subhead-sub">
				Named client egress chains — order nodes entry → [mid] → exit. Provision a path, then bind a
				client onto it.
			</p>
		</div>
		<button class="btn btn-secondary" onclick={openAdd} disabled={nodes.length < 2}>Add path</button>
	</div>

	{#if nodes.length < 2}
		<div class="mt-4 card p-6 text-sm text-ink-2">
			A data path chains two or more nodes — onboard at least two, then come back to define one.
		</div>
	{:else if paths.length === 0}
		<div class="mt-4 card p-6 text-sm text-ink-2">
			No data paths yet. Stack nodes into a chain — the first is the entry a client connects to, the
			last is the exit that reaches the internet, with an optional mid hop between.
		</div>
	{:else}
		<div class="mt-4 flex flex-col gap-4">
			{#each paths as p (p.id)}
				<div class="card p-5">
					<div class="flex items-start justify-between gap-4">
						<div class="min-w-0">
							<div class="flex items-center gap-2">
								<span class="swatch" style="background: {p.color || '#4fd1c4'}"></span>
								<span class="text-base font-semibold text-ink">{p.name}</span>
								<span class="badge {statusBadge(p.status)}"><span class="dot"></span>{p.status}</span>
							</div>
							<div class="chain mt-2">
								{#each p.hops as h, i (h)}
									{#if i > 0}<span class="arrow">→</span>{/if}
									<span class="hop">
										<span class="hop-kind">{hopRole(i, p.hops.length)}</span>
										<span class="hop-name">{nodeName(h)}</span>
									</span>
								{/each}
							</div>
						</div>
						<div class="flex flex-none gap-2">
							<button class="btn btn-secondary btn-sm" disabled={busyId === p.id} onclick={() => reprovision(p)}>
								{busyId === p.id ? 'Re-applying…' : 'Re-provision'}
							</button>
							<button class="btn btn-text btn-sm" style="color: var(--c-danger)" onclick={() => { removing = p; removeError = ''; }}>Remove</button>
						</div>
					</div>
				</div>
			{/each}
		</div>
	{/if}
{/if}

<!-- Add control path: the relay hop-stacker -->
{#if cpAdding}
	<Modal title="Add control path" onclose={() => (cpAdding = false)}>
		<label class="label" for="cp-name">Name</label>
		<input id="cp-name" class="input" bind:value={cpName} placeholder="via-frankfurt" />

		<p class="overline mt-5">Relay hops</p>
		<p class="text-xs text-ink-3">
			Order from coxswain outward (hop 1 closest to the controller, the last reaches the node). Leave
			empty for a <b>direct</b> route. Only active egress/onion relays can be hops.
		</p>

		<div class="mt-3 flex flex-col gap-2">
			{#each cpStack as id, i (id)}
				<div class="hop-row">
					<span class="hop-kind">Hop {i + 1}</span>
					<span class="hop-name grow">{relayName(id)}</span>
					<button class="icon-btn" aria-label="Move up" disabled={i === 0} onclick={() => moveCp(i, -1)}>↑</button>
					<button class="icon-btn" aria-label="Move down" disabled={i === cpStack.length - 1} onclick={() => moveCp(i, 1)}>↓</button>
					<button class="icon-btn" aria-label="Remove hop" onclick={() => removeCpHop(i)}>✕</button>
				</div>
			{/each}
			{#if cpStack.length === 0}
				<div class="text-sm text-ink-3">Direct — no relay hops.</div>
			{/if}
		</div>

		{#if cpStack.length < MAX_CONTROL_HOPS && cpAvailable.length > 0}
			<div class="mt-3 flex gap-2">
				<select class="input grow" bind:value={cpPick}>
					<option value="" disabled>Add a relay hop…</option>
					{#each cpAvailable as r (r.id)}
						<option value={r.id}>{r.name || r.host} — {r.region || 'unknown'} ({r.onion ? 'onion' : 'egress'})</option>
					{/each}
				</select>
				<button class="btn btn-secondary" onclick={addCpHop} disabled={!cpPick}>Add hop</button>
			</div>
		{:else if routableRelays.length === 0}
			<p class="mt-1 text-xs text-ink-3">No egress/onion relays yet — this path will be direct. Deploy a relay to add hops.</p>
		{/if}

		<button type="button" role="switch" aria-checked={cpActivate} class="toggle-row mt-4" onclick={() => (cpActivate = !cpActivate)}>
			<span class="toggle-text">
				<span class="text-sm font-medium text-ink">Activate now</span>
				<span class="text-xs text-ink-3">Make this the fleet's active control route immediately.</span>
			</span>
			<Switch checked={cpActivate} />
		</button>

		{#if cpError}<p class="field-error" role="alert">{cpError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (cpAdding = false)}>Cancel</button>
			<button class="btn btn-primary" onclick={submitCpAdd} disabled={cpBusy || !cpName}>
				{cpBusy ? 'Saving…' : 'Create'}
			</button>
		</div>
	</Modal>
{/if}

<!-- Remove control path -->
{#if cpRemoving}
	<Modal title="Remove control path" onclose={() => (cpRemoving = null)}>
		<p class="text-sm text-ink-2">
			Delete <span class="font-medium text-ink">{cpRemoving.name}</span>?
			{#if cpRemoving.active}
				It is the <b>active</b> route — removing it leaves coxswain reaching nodes directly until you
				activate another.
			{/if}
		</p>
		{#if cpRemoveError}<p class="field-error" role="alert">{cpRemoveError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (cpRemoving = null)}>Cancel</button>
			<button class="btn btn-danger" onclick={confirmCpRemove} disabled={cpRemoveBusy}>
				{cpRemoveBusy ? 'Removing…' : 'Remove'}
			</button>
		</div>
	</Modal>
{/if}

<!-- Add data path: the hop-stacker -->
{#if adding}
	<Modal title="Add path" onclose={() => (adding = false)}>
		<label class="label" for="p-name">Name</label>
		<input id="p-name" class="input" bind:value={pName} placeholder="edge-to-frankfurt" />

		<p class="overline mt-5">Hops</p>
		<p class="text-xs text-ink-3">
			Order from entry to exit (up to {MAX_NODES} nodes). Best practice: don't reuse an entry as a
			later hop — shown as guidance, not enforced.
		</p>

		<div class="mt-3 flex flex-col gap-2">
			{#each stack as id, i (id)}
				<div class="hop-row">
					<span class="hop-kind">{hopRole(i, stack.length)}</span>
					<span class="hop-name grow">{nodeName(id)}</span>
					<button class="icon-btn" aria-label="Move up" disabled={i === 0} onclick={() => move(i, -1)}>↑</button>
					<button class="icon-btn" aria-label="Move down" disabled={i === stack.length - 1} onclick={() => move(i, 1)}>↓</button>
					<button class="icon-btn" aria-label="Remove hop" onclick={() => removeHop(i)}>✕</button>
				</div>
			{/each}
			{#if stack.length === 0}
				<div class="text-sm text-ink-3">No hops yet — add an entry node below.</div>
			{/if}
		</div>

		{#if stack.length < MAX_NODES && available.length > 0}
			<div class="mt-3 flex gap-2">
				<select class="input grow" bind:value={pick}>
					<option value="" disabled>Add a node…</option>
					{#each available as n (n.id)}
						<option value={n.id}>{n.name} — {n.region || 'unknown'} ({n.status})</option>
					{/each}
				</select>
				<button class="btn btn-secondary" onclick={addHop} disabled={!pick}>Add hop</button>
			</div>
		{/if}

		<label class="label mt-5" for="p-color">Map colour (optional)</label>
		<input id="p-color" class="input" bind:value={pColor} placeholder="#4fd1c4 — auto-assigned if empty" />

		{#if addError}<p class="field-error" role="alert">{addError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (adding = false)}>Cancel</button>
			<button class="btn btn-primary" onclick={submitAdd} disabled={addBusy || !pName || stack.length < 2}>
				{addBusy ? 'Provisioning…' : 'Create & provision'}
			</button>
		</div>
	</Modal>
{/if}

<!-- Remove data path -->
{#if removing}
	<Modal title="Remove path" onclose={() => (removing = null)}>
		<p class="text-sm text-ink-2">
			Tear down <span class="font-medium text-ink">{removing.name}</span> and remove its inner-link
			chain? Blocked if a client is still bound to it.
		</p>
		{#if removeError}<p class="field-error" role="alert">{removeError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (removing = null)}>Cancel</button>
			<button class="btn btn-danger" onclick={confirmRemove} disabled={removeBusy}>
				{removeBusy ? 'Removing…' : 'Remove'}
			</button>
		</div>
	</Modal>
{/if}

<style>
	.subhead {
		font-size: 15px;
		font-weight: 600;
		color: var(--c-ink, var(--c-gray-50));
	}
	.subhead-sub {
		margin-top: 2px;
		max-width: 46rem;
		font-size: 12px;
		color: var(--c-gray-300);
	}
	.swatch {
		width: 12px;
		height: 12px;
		border-radius: 3px;
		flex: none;
	}
	.chain {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 8px;
	}
	.arrow {
		color: var(--c-gray-400);
	}
	.hop {
		display: inline-flex;
		align-items: baseline;
		gap: 6px;
		padding: 3px 10px;
		border: 1px solid var(--c-line);
		border-radius: 999px;
		background: var(--c-bg);
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
	.hop-row {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 8px 12px;
		border: 1px solid var(--c-line);
		border-radius: 8px;
	}
	.grow {
		flex: 1 1 auto;
		min-width: 0;
	}
	.toggle-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 16px;
		width: 100%;
		min-height: 44px;
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
	.icon-btn:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}
</style>
