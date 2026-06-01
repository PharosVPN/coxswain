<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<script lang="ts">
	import { onMount } from 'svelte';
	import { api, errorMessage } from '$lib/api';
	import { session } from '$lib/session.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import type { User } from '$lib/types';

	const FIXED_ADMIN_ID = 'usr_admin';

	let admins = $state<User[]>([]);
	let loading = $state(true);
	let loadError = $state('');

	let adding = $state(false);
	let addEmail = $state('');
	let addPassword = $state('');
	let addError = $state('');
	let addBusy = $state(false);

	let deleting = $state<User | null>(null);
	let deleteError = $state('');
	let deleteBusy = $state(false);

	async function loadAdmins() {
		loading = true;
		loadError = '';
		try {
			admins = await api.get<User[]>('/api/admins');
		} catch (e) {
			loadError = errorMessage(e);
		}
		loading = false;
	}

	onMount(loadAdmins);

	function openAdd() {
		adding = true;
		addEmail = '';
		addPassword = '';
		addError = '';
	}

	async function submitAdd() {
		addBusy = true;
		addError = '';
		try {
			const created = await api.post<User>('/api/admins', {
				email: addEmail,
				password: addPassword
			});
			admins = [...admins, created];
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
			await api.del(`/api/admins/${deleting.id}`);
			admins = admins.filter((a) => a.id !== deleting!.id);
			deleting = null;
		} catch (e) {
			deleteError = errorMessage(e);
		}
		deleteBusy = false;
	}

	function removable(a: User): boolean {
		return a.id !== FIXED_ADMIN_ID && a.id !== session.user?.id;
	}
</script>

<svelte:head><title>Admins — coxswain</title></svelte:head>

<div class="flex items-end justify-between">
	<div>
		<h1 class="section-title">Admins</h1>
		<p class="section-subtitle">accounts with access to this console.</p>
	</div>
	<button class="btn btn-primary" onclick={openAdd}>Add admin</button>
</div>

<div class="mt-6 card overflow-hidden">
	{#if loading}
		<div class="p-6 text-sm text-ink-3">Loading admins…</div>
	{:else if loadError}
		<div class="p-6 text-sm" style="color: var(--c-danger)">{loadError}</div>
	{:else}
		<table class="dtable">
			<thead>
				<tr><th>Email</th><th>Status</th><th></th><th class="text-right">Actions</th></tr>
			</thead>
			<tbody>
				{#each admins as a (a.id)}
					<tr>
						<td class="font-medium">{a.email}</td>
						<td>
							<span class="badge {a.status === 'active' ? 'badge-success' : 'badge-gray'}">
								<span class="dot"></span>{a.status}
							</span>
						</td>
						<td>
							{#if a.id === FIXED_ADMIN_ID}
								<span class="badge badge-brand">built-in</span>
							{:else if a.id === session.user?.id}
								<span class="badge badge-gray">you</span>
							{/if}
						</td>
						<td class="text-right">
							{#if removable(a)}
								<button
									class="btn btn-text btn-sm"
									style="color: var(--c-danger)"
									onclick={() => {
										deleting = a;
										deleteError = '';
									}}>Remove</button
								>
							{:else}
								<span class="text-xs text-ink-4">—</span>
							{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
</div>

{#if adding}
	<Modal title="Add admin" onclose={() => (adding = false)}>
		<label class="label" for="email">Email</label>
		<input id="email" class="input" type="email" bind:value={addEmail} dir="auto" />
		<label class="label mt-4" for="password">Password</label>
		<input
			id="password"
			class="input"
			type="password"
			bind:value={addPassword}
			autocomplete="new-password"
		/>
		<p class="mt-1.5 text-xs text-ink-3">At least 8 characters.</p>
		{#if addError}<p class="field-error" role="alert">{addError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (adding = false)}>Cancel</button>
			<button class="btn btn-primary" onclick={submitAdd} disabled={addBusy}>
				{addBusy ? 'Adding…' : 'Add admin'}
			</button>
		</div>
	</Modal>
{/if}

{#if deleting}
	<Modal title="Remove admin" onclose={() => (deleting = null)}>
		<p class="text-sm text-ink-2">
			Remove <span class="font-medium text-ink">{deleting.email}</span>? They lose console
			access immediately.
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
