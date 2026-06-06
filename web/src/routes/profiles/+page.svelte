<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<script lang="ts">
	import { onMount } from 'svelte';
	import { api, errorMessage } from '$lib/api';
	import Modal from '$lib/components/Modal.svelte';
	import type { ProfileSpec, User, Device, Node, Path } from '$lib/types';

	let specs = $state<ProfileSpec[]>([]);
	let users = $state<User[]>([]);
	let nodes = $state<Node[]>([]);
	let paths = $state<Path[]>([]);
	let devicesByUser = $state<Record<string, Device[]>>({});
	let loading = $state(true);
	let loadError = $state('');

	const userEmail = $derived(new Map(users.map((u) => [u.id, u.email])));
	const nodeName = $derived(new Map(nodes.map((n) => [n.id, n.name])));
	const pathName = $derived(new Map(paths.map((p) => [p.id, p.name])));
	const deviceName = $derived(
		new Map(
			Object.values(devicesByUser)
				.flat()
				.map((d) => [d.id, d.name])
		)
	);

	function egressLabel(s: ProfileSpec): string {
		if (s.node_id) return nodeName.get(s.node_id) ?? s.node_id;
		if (s.path_id) return `${pathName.get(s.path_id) ?? s.path_id} (cascade)`;
		return '—';
	}

	function protoLabel(p: string): string {
		return p === 'xray-reality' ? 'XRay/REALITY' : 'AmneziaWG';
	}

	async function load() {
		loading = true;
		loadError = '';
		try {
			[specs, users, nodes, paths] = await Promise.all([
				api.get<ProfileSpec[]>('/api/profiles'),
				api.get<User[]>('/api/users'),
				api.get<Node[]>('/api/nodes'),
				api.get<Path[]>('/api/paths')
			]);
			// Each user's devices, so the list can name them and the form can pick one.
			const entries = await Promise.all(
				users.map(
					async (u) => [u.id, await api.get<Device[]>(`/api/users/${u.id}/devices`)] as const
				)
			);
			devicesByUser = Object.fromEntries(entries);
		} catch (e) {
			loadError = errorMessage(e);
		}
		loading = false;
	}
	onMount(load);

	// ───────── Add profile ─────────
	let adding = $state(false);
	let fUser = $state('');
	let fDevice = $state('');
	let fName = $state('');
	let egressType = $state<'node' | 'path'>('node');
	let fNode = $state('');
	let fPath = $state('');
	let fProtocol = $state('amneziawg');
	let fEntryIPs = $state<string[]>([]);
	let addBusy = $state(false);
	let addError = $state('');

	const userDevices = $derived(fUser ? (devicesByUser[fUser] ?? []) : []);
	const entryPool = $derived(nodes.find((n) => n.id === fNode)?.endpoint_ips ?? []);

	// When the user changes, default to their sole device (if any), else force a
	// re-pick. Called on open and on the user select's change.
	function defaultDevice() {
		const devs = fUser ? (devicesByUser[fUser] ?? []) : [];
		fDevice = devs.length === 1 ? devs[0].id : '';
	}

	function openAdd() {
		fUser = users[0]?.id ?? '';
		fName = '';
		egressType = 'node';
		fNode = '';
		fPath = '';
		fProtocol = 'amneziawg';
		fEntryIPs = [];
		addError = '';
		defaultDevice();
		adding = true;
	}

	function toggleEntryIP(ip: string) {
		fEntryIPs = fEntryIPs.includes(ip) ? fEntryIPs.filter((x) => x !== ip) : [...fEntryIPs, ip];
	}

	const canSubmit = $derived(
		!!fUser && !!fDevice && !!fName && (egressType === 'node' ? !!fNode : !!fPath)
	);

	async function submitAdd() {
		addBusy = true;
		addError = '';
		try {
			await api.post<ProfileSpec>('/api/profiles', {
				user_id: fUser,
				device_id: fDevice,
				name: fName,
				node_id: egressType === 'node' ? fNode : '',
				path_id: egressType === 'path' ? fPath : '',
				entry_ips: egressType === 'node' ? fEntryIPs : [],
				protocol: fProtocol
			});
			adding = false;
			await load();
		} catch (e) {
			addError = errorMessage(e);
		}
		addBusy = false;
	}

	// ───────── Remove ─────────
	let removing = $state<ProfileSpec | null>(null);
	let removeBusy = $state(false);
	let removeError = $state('');

	async function confirmRemove() {
		if (!removing) return;
		removeBusy = true;
		removeError = '';
		try {
			await api.del(`/api/profiles/${removing.id}`);
			removing = null;
			await load();
		} catch (e) {
			removeError = errorMessage(e);
		}
		removeBusy = false;
	}
</script>

<svelte:head><title>Profiles — coxswain</title></svelte:head>

<div class="flex items-center justify-between">
	<div>
		<h1 class="section-title">Profiles</h1>
		<p class="section-subtitle">
			A device's named connection configs — pick an egress (a node, or a cascade path), an optional
			entry-IP subset, and a protocol. The device syncs and the app lists them by name.
		</p>
	</div>
	<button class="btn btn-primary" onclick={openAdd} disabled={users.length === 0}>Add profile</button>
</div>

{#if loading}
	<div class="mt-6 card p-6 text-sm text-ink-3">Loading profiles…</div>
{:else if loadError}
	<div class="mt-6 card p-6 text-sm" style="color: var(--c-danger)">{loadError}</div>
{:else if specs.length === 0}
	<div class="mt-6 card p-10 text-center">
		<div class="text-base font-semibold text-ink">No profiles yet</div>
		<p class="mx-auto mt-1 max-w-md text-sm text-ink-2">
			Create a profile for a user's device: choose where it exits (a single node, or a multi-hop
			path) and how it connects (AmneziaWG or XRay/REALITY).
		</p>
		{#if users.length > 0}
			<button class="btn btn-primary mt-4" onclick={openAdd}>Add your first profile</button>
		{:else}
			<p class="mt-3 text-xs text-ink-3">Add a user first.</p>
		{/if}
	</div>
{:else}
	<div class="mt-6 flex flex-col gap-3">
		{#each specs as s (s.id)}
			<div class="card p-5">
				<div class="flex items-start justify-between gap-4">
					<div class="min-w-0">
						<div class="flex items-center gap-2">
							<span class="text-base font-semibold text-ink">{s.name}</span>
							<span class="badge badge-info">{protoLabel(s.protocol)}</span>
						</div>
						<div class="mt-1 text-sm text-ink-2">
							{userEmail.get(s.user_id) ?? s.user_id} · {deviceName.get(s.device_id) ?? s.device_id}
							· egress <span class="text-ink">{egressLabel(s)}</span>
							{#if s.entry_ips && s.entry_ips.length > 0}
								· entry {s.entry_ips.join(', ')}
							{/if}
						</div>
					</div>
					<button
						class="btn btn-text btn-sm flex-none"
						style="color: var(--c-danger)"
						onclick={() => {
							removing = s;
							removeError = '';
						}}>Remove</button
					>
				</div>
			</div>
		{/each}
	</div>
{/if}

<!-- Add profile -->
{#if adding}
	<Modal title="Add profile" onclose={() => (adding = false)}>
		<label class="label" for="pf-user">User</label>
		<select id="pf-user" class="input" bind:value={fUser} onchange={defaultDevice}>
			{#each users as u (u.id)}
				<option value={u.id}>{u.email || u.name || u.id}</option>
			{/each}
		</select>

		<label class="label mt-4" for="pf-device">Device</label>
		<select id="pf-device" class="input" bind:value={fDevice} disabled={userDevices.length === 0}>
			<option value="" disabled>{userDevices.length === 0 ? 'no devices for this user' : 'Select a device…'}</option>
			{#each userDevices as d (d.id)}
				<option value={d.id}>{d.name} ({d.platform || 'device'})</option>
			{/each}
		</select>
		{#if fUser && userDevices.length === 0}
			<p class="text-xs text-ink-3 mt-1">Enrol a device for this user first (`cox devices issue`).</p>
		{/if}

		<label class="label mt-4" for="pf-name">Name</label>
		<input id="pf-name" class="input" bind:value={fName} placeholder="US Direct" />

		<p class="overline mt-5">Egress</p>
		<div class="seg mt-1">
			<button class="seg-btn" class:active={egressType === 'node'} onclick={() => (egressType = 'node')}>
				Single node (direct)
			</button>
			<button class="seg-btn" class:active={egressType === 'path'} onclick={() => (egressType = 'path')}>
				Path (cascade)
			</button>
		</div>

		{#if egressType === 'node'}
			<select class="input mt-3" bind:value={fNode} onchange={() => (fEntryIPs = [])}>
				<option value="" disabled>Select a node…</option>
				{#each nodes as n (n.id)}
					<option value={n.id}>{n.name} — {n.region || 'unknown'} ({n.status})</option>
				{/each}
			</select>
			{#if entryPool.length > 1}
				<p class="overline mt-4">Entry IPs <span class="font-normal normal-case text-ink-3">(optional — all if none picked)</span></p>
				<div class="mt-1 flex flex-wrap gap-2">
					{#each entryPool as ip (ip)}
						<button
							class="chip"
							class:active={fEntryIPs.includes(ip)}
							onclick={() => toggleEntryIP(ip)}>{ip}</button
						>
					{/each}
				</div>
			{/if}
		{:else}
			<select class="input mt-3" bind:value={fPath} disabled={paths.length === 0}>
				<option value="" disabled>{paths.length === 0 ? 'no paths defined' : 'Select a path…'}</option>
				{#each paths as p (p.id)}
					<option value={p.id}>{p.name} ({p.status})</option>
				{/each}
			</select>
		{/if}

		<label class="label mt-5" for="pf-proto">Protocol</label>
		<select id="pf-proto" class="input" bind:value={fProtocol}>
			<option value="amneziawg">AmneziaWG</option>
			<option value="xray-reality">XRay/REALITY</option>
		</select>

		{#if addError}<p class="field-error" role="alert">{addError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (adding = false)}>Cancel</button>
			<button class="btn btn-primary" onclick={submitAdd} disabled={addBusy || !canSubmit}>
				{addBusy ? 'Creating…' : 'Create & provision'}
			</button>
		</div>
	</Modal>
{/if}

<!-- Remove profile -->
{#if removing}
	<Modal title="Remove profile" onclose={() => (removing = null)}>
		<p class="text-sm text-ink-2">
			Delete <span class="font-medium text-ink">{removing.name}</span> and re-provision the device
			(its peer is dropped)?
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
	.seg {
		display: inline-flex;
		gap: 4px;
		padding: 3px;
		border: 1px solid var(--c-line);
		border-radius: 8px;
	}
	.seg-btn {
		padding: 5px 12px;
		border: none;
		border-radius: 6px;
		background: transparent;
		color: var(--c-gray-200);
		font-size: 13px;
		cursor: pointer;
	}
	.seg-btn.active {
		background: var(--c-brand-700, var(--c-line));
		color: var(--c-gray-50);
	}
	.chip {
		padding: 4px 10px;
		border: 1px solid var(--c-line);
		border-radius: 999px;
		background: var(--c-bg);
		color: var(--c-gray-100);
		font-size: 12px;
		cursor: pointer;
	}
	.chip.active {
		border-color: var(--c-brand-100);
		color: var(--c-gray-50);
	}
</style>
