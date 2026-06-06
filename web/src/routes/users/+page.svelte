<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<script lang="ts">
	import { onMount } from 'svelte';
	import { api, errorMessage } from '$lib/api';
	import Modal from '$lib/components/Modal.svelte';
	import type { User, Device, ProvisionResult } from '$lib/types';

	let users = $state<User[]>([]);
	let loading = $state(true);
	let loadError = $state('');

	let adding = $state(false);
	let addName = $state('');
	let addEmail = $state('');
	let addPhone = $state('');
	let addPassword = $state('');
	let addError = $state('');
	let addBusy = $state(false);

	let deleting = $state<User | null>(null);
	let deleteError = $state('');
	let deleteBusy = $state(false);

	// Device management for one user.
	let devicesFor = $state<User | null>(null);
	let deviceList = $state<Device[]>([]);
	let deviceLoading = $state(false);
	let deviceError = $state('');
	let newDeviceName = $state('');
	let addDeviceBusy = $state(false);
	let busyDevice = $state(''); // device id mid-provision/remove
	let deviceNote = $state<Record<string, string>>({});

	async function loadUsers() {
		loading = true;
		loadError = '';
		try {
			users = await api.get<User[]>('/api/users');
		} catch (e) {
			loadError = errorMessage(e);
		}
		loading = false;
	}

	onMount(loadUsers);

	function openAdd() {
		adding = true;
		addName = '';
		addEmail = '';
		addPhone = '';
		addPassword = '';
		addError = '';
	}

	async function submitAdd() {
		addBusy = true;
		addError = '';
		try {
			const created = await api.post<User>('/api/users', {
				name: addName,
				email: addEmail,
				phone: addPhone,
				password: addPassword
			});
			users = [...users, created];
			adding = false;
		} catch (e) {
			addError = errorMessage(e);
		}
		addBusy = false;
	}

	async function confirmDelete() {
		if (!deleting) return;
		deleteBusy = true;
		deleteError = '';
		try {
			await api.del(`/api/users/${deleting.id}`);
			users = users.filter((u) => u.id !== deleting!.id);
			deleting = null;
		} catch (e) {
			deleteError = errorMessage(e);
		}
		deleteBusy = false;
	}

	// ───────── Devices ─────────
	async function openDevices(user: User) {
		devicesFor = user;
		deviceList = [];
		deviceError = '';
		deviceNote = {};
		newDeviceName = '';
		deviceLoading = true;
		try {
			deviceList = await api.get<Device[]>(`/api/users/${user.id}/devices`);
		} catch (e) {
			deviceError = errorMessage(e);
		}
		deviceLoading = false;
	}

	async function addDevice() {
		if (!devicesFor || newDeviceName === '') return;
		addDeviceBusy = true;
		deviceError = '';
		try {
			const created = await api.post<Device>(`/api/users/${devicesFor.id}/devices`, {
				name: newDeviceName
			});
			deviceList = [...deviceList, created];
			newDeviceName = '';
		} catch (e) {
			deviceError = errorMessage(e);
		}
		addDeviceBusy = false;
	}

	async function provisionDevice(d: Device) {
		busyDevice = d.id;
		try {
			const res = await api.post<ProvisionResult>(`/api/devices/${d.id}/provision`);
			deviceNote = {
				...deviceNote,
				[d.id]: `provisioned — ${res.tunnel_ip}, ${res.peer_count} node(s), profile rev ${res.profile_revision}`
			};
		} catch (e) {
			deviceNote = { ...deviceNote, [d.id]: errorMessage(e) };
		}
		busyDevice = '';
	}

	async function removeDevice(d: Device) {
		busyDevice = d.id;
		try {
			await api.del(`/api/devices/${d.id}`);
			deviceList = deviceList.filter((x) => x.id !== d.id);
		} catch (e) {
			deviceNote = { ...deviceNote, [d.id]: errorMessage(e) };
		}
		busyDevice = '';
	}
</script>

<svelte:head><title>Users — coxswain</title></svelte:head>

<div class="flex items-end justify-between">
	<div>
		<h1 class="section-title">Users</h1>
		<p class="section-subtitle">end-user accounts, their devices, and provisioning.</p>
	</div>
	<button class="btn btn-primary" onclick={openAdd}>Add user</button>
</div>

<div class="mt-6 card overflow-hidden">
	{#if loading}
		<div class="p-6 text-sm text-ink-3">Loading users…</div>
	{:else if loadError}
		<div class="p-6 text-sm" style="color: var(--c-danger)">{loadError}</div>
	{:else if users.length === 0}
		<div class="p-8 text-center">
			<div class="text-base font-semibold text-ink">No users yet</div>
			<p class="mt-1 text-sm text-ink-2">Add an end-user account to issue it a profile.</p>
		</div>
	{:else}
		<table class="dtable">
			<thead>
				<tr><th>Name</th><th>Contact</th><th>Status</th><th class="text-right">Actions</th></tr>
			</thead>
			<tbody>
				{#each users as u (u.id)}
					<tr>
						<td class="font-medium">{u.name || u.email || u.phone || u.id}</td>
						<td class="text-ink-2 text-sm">
							{#if u.email}<div dir="auto">{u.email}</div>{/if}
							{#if u.phone}<div dir="auto">{u.phone}</div>{/if}
							{#if !u.email && !u.phone}<span class="text-ink-3">—</span>{/if}
						</td>
						<td>
							<span class="badge {u.status === 'active' ? 'badge-success' : 'badge-gray'}">
								<span class="dot"></span>{u.status}
							</span>
						</td>
						<td class="text-right whitespace-nowrap">
							<button class="btn btn-text btn-sm" onclick={() => openDevices(u)}>Devices</button>
							<button
								class="btn btn-text btn-sm"
								style="color: var(--c-danger)"
								onclick={() => {
									deleting = u;
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

{#if adding}
	<Modal title="Add user" onclose={() => (adding = false)}>
		<label class="label" for="name">Name</label>
		<input id="name" class="input" bind:value={addName} dir="auto" placeholder="Jane Doe" />
		<label class="label mt-4" for="email">Email <span class="text-ink-3">(optional)</span></label>
		<input id="email" class="input" type="email" bind:value={addEmail} dir="auto" />
		<label class="label mt-4" for="phone">Phone <span class="text-ink-3">(optional)</span></label>
		<input id="phone" class="input" type="tel" bind:value={addPhone} dir="auto" />
		<label class="label mt-4" for="password">Password <span class="text-ink-3">(optional)</span></label>
		<input
			id="password"
			class="input"
			type="password"
			bind:value={addPassword}
			autocomplete="new-password"
		/>
		<p class="mt-1.5 text-xs text-ink-3">
			Devices sign in with their own key — a password is only needed for the legacy
			email login. If set, at least 8 characters.
		</p>
		{#if addError}<p class="field-error" role="alert">{addError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (adding = false)}>Cancel</button>
			<button class="btn btn-primary" onclick={submitAdd} disabled={addBusy}>
				{addBusy ? 'Adding…' : 'Add user'}
			</button>
		</div>
	</Modal>
{/if}

{#if deleting}
	<Modal title="Remove user" onclose={() => (deleting = null)}>
		<p class="text-sm text-ink-2">
			Remove <span class="font-medium text-ink">{deleting.name || deleting.email || deleting.id}</span>? Their profiles and
			devices are removed with the account.
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

{#if devicesFor}
	<Modal title="Devices — {devicesFor.name || devicesFor.email}" onclose={() => (devicesFor = null)}>
		{#if deviceLoading}
			<p class="text-sm text-ink-3">Loading devices…</p>
		{:else}
			{#if deviceList.length === 0}
				<p class="text-sm text-ink-3">No devices yet.</p>
			{:else}
				<ul class="flex flex-col gap-3">
					{#each deviceList as d (d.id)}
						<li class="rounded-md border border-line p-3">
							<div class="flex items-center justify-between gap-2">
								<span class="text-sm font-medium text-ink">{d.name}</span>
								<span class="flex gap-1">
									<button
										class="btn btn-text btn-sm"
										disabled={busyDevice === d.id}
										onclick={() => provisionDevice(d)}>Provision</button
									>
									<button
										class="btn btn-text btn-sm"
										style="color: var(--c-danger)"
										disabled={busyDevice === d.id}
										onclick={() => removeDevice(d)}>Remove</button
									>
								</span>
							</div>
							{#if deviceNote[d.id]}
								<p class="mt-1 text-xs text-ink-3">{deviceNote[d.id]}</p>
							{/if}
						</li>
					{/each}
				</ul>
			{/if}

			<div class="mt-4 flex gap-2">
				<input
					class="input"
					placeholder="New device name"
					bind:value={newDeviceName}
					dir="auto"
				/>
				<button
					class="btn btn-secondary"
					disabled={addDeviceBusy || newDeviceName === ''}
					onclick={addDevice}>Add</button
				>
			</div>
			{#if deviceError}<p class="field-error" role="alert">{deviceError}</p>{/if}
		{/if}

		<div class="mt-6 flex justify-end">
			<button class="btn btn-secondary" onclick={() => (devicesFor = null)}>Close</button>
		</div>
	</Modal>
{/if}
