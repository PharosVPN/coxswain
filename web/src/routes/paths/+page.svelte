<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<script lang="ts">
	import { onMount } from 'svelte';
	import { api, errorMessage } from '$lib/api';
	import Modal from '$lib/components/Modal.svelte';
	import type { Node, Path } from '$lib/types';

	// MaxPathHops in the controller is 2 inner-link segments → at most 3 nodes
	// (entry → mid → exit). Kept in lockstep with cascade.MaxPathHops.
	const MAX_NODES = 3;

	let paths = $state<Path[]>([]);
	let nodes = $state<Node[]>([]);
	let loading = $state(true);
	let loadError = $state('');

	const byId = $derived(new Map(nodes.map((n) => [n.id, n])));

	function nodeName(id: string): string {
		return byId.get(id)?.name ?? id;
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
			[paths, nodes] = await Promise.all([
				api.get<Path[]>('/api/paths'),
				api.get<Node[]>('/api/nodes')
			]);
		} catch (e) {
			loadError = errorMessage(e);
		}
		loading = false;
	}
	onMount(load);

	// ───────── Add path (hop-stacker) ─────────
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

	// ───────── Re-provision ─────────
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

	// ───────── Remove path ─────────
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
</script>

<svelte:head><title>Paths — coxswain</title></svelte:head>

<div class="flex items-center justify-between">
	<div>
		<h1 class="section-title">Paths</h1>
		<p class="section-subtitle">
			Named data planes — order nodes into a chain entry → [mid] → exit. Provision a path here,
			then bind a client onto it.
		</p>
	</div>
	<button class="btn btn-primary" onclick={openAdd} disabled={nodes.length < 2}>Add path</button>
</div>

{#if loading}
	<div class="mt-6 card p-6 text-sm text-ink-3">Loading paths…</div>
{:else if loadError}
	<div class="mt-6 card p-6 text-sm" style="color: var(--c-danger)">{loadError}</div>
{:else if nodes.length < 2}
	<div class="mt-6 card p-10 text-center">
		<div class="text-base font-semibold text-ink">Add nodes first</div>
		<p class="mx-auto mt-1 max-w-md text-sm text-ink-2">
			A path chains two or more nodes. Onboard at least two nodes, then come back to define a path.
		</p>
	</div>
{:else if paths.length === 0}
	<div class="mt-6 card p-10 text-center">
		<div class="text-base font-semibold text-ink">No paths yet</div>
		<p class="mx-auto mt-1 max-w-md text-sm text-ink-2">
			Stack nodes into a chain — the first is the entry a client connects to, the last is the exit
			that reaches the internet, with an optional mid hop between.
		</p>
		<button class="btn btn-primary mt-4" onclick={openAdd}>Add your first path</button>
	</div>
{:else}
	<div class="mt-6 flex flex-col gap-4">
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

<!-- Add path: the hop-stacker -->
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

<!-- Remove path -->
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
