<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<script lang="ts">
	import { onMount } from 'svelte';
	import { api, errorMessage } from '$lib/api';
	import Modal from '$lib/components/Modal.svelte';
	import type { Token, TokenCreated } from '$lib/types';

	let tokens = $state<Token[]>([]);
	let loading = $state(true);
	let loadError = $state('');

	function fmt(iso?: string): string {
		if (!iso) return '—';
		const d = new Date(iso);
		return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
	}

	function isExpired(t: Token): boolean {
		return !!t.expires_at && new Date(t.expires_at).getTime() < Date.now();
	}

	function statusBadge(t: Token): { cls: string; label: string } {
		if (t.revoked_at) return { cls: 'badge-danger', label: 'revoked' };
		if (isExpired(t)) return { cls: 'badge-gray', label: 'expired' };
		return { cls: 'badge-success', label: 'active' };
	}

	function scopeBadge(scope: string): string {
		if (scope === 'admin') return 'badge-brand';
		if (scope === 'monitor') return 'badge-info';
		return 'badge-gray';
	}

	async function load() {
		loading = true;
		loadError = '';
		try {
			tokens = await api.get<Token[]>('/api/tokens');
		} catch (e) {
			loadError = errorMessage(e);
		}
		loading = false;
	}
	onMount(load);

	// ───────── Create token ─────────
	let adding = $state(false);
	let fName = $state('');
	let fScope = $state('readonly');
	let fExpiry = $state(''); // a Go duration string, e.g. "720h"; empty = no expiry
	let addBusy = $state(false);
	let addError = $state('');

	// The plaintext secret — shown exactly once, after a successful create.
	let minted = $state<TokenCreated | null>(null);
	let copied = $state(false);

	function openAdd() {
		fName = '';
		fScope = 'readonly';
		fExpiry = '';
		addError = '';
		adding = true;
	}

	async function submitAdd() {
		addBusy = true;
		addError = '';
		try {
			const created = await api.post<TokenCreated>('/api/tokens', {
				name: fName,
				scope: fScope,
				expires: fExpiry.trim()
			});
			adding = false;
			minted = created;
			copied = false;
			await load();
		} catch (e) {
			addError = errorMessage(e);
		}
		addBusy = false;
	}

	async function copySecret() {
		if (!minted) return;
		try {
			await navigator.clipboard.writeText(minted.secret);
			copied = true;
			setTimeout(() => (copied = false), 1500);
		} catch {
			/* clipboard unavailable */
		}
	}

	// ───────── Revoke ─────────
	let revoking = $state<Token | null>(null);
	let revokeBusy = $state(false);
	let revokeError = $state('');

	async function confirmRevoke() {
		if (!revoking) return;
		revokeBusy = true;
		revokeError = '';
		try {
			await api.del(`/api/tokens/${revoking.id}`);
			revoking = null;
			await load();
		} catch (e) {
			revokeError = errorMessage(e);
		}
		revokeBusy = false;
	}
</script>

<svelte:head><title>API tokens — coxswain</title></svelte:head>

<div class="flex items-center justify-between">
	<div>
		<h1 class="section-title">API tokens</h1>
		<p class="section-subtitle">
			Scoped bearer credentials for the API and CLI. The secret is shown once at creation —
			store it then. Pick the narrowest scope a caller needs.
		</p>
	</div>
	<button class="btn btn-primary" onclick={openAdd}>Create token</button>
</div>

{#if loading}
	<div class="mt-6 card p-6 text-sm text-ink-3">Loading tokens…</div>
{:else if loadError}
	<div class="mt-6 card p-6 text-sm" style="color: var(--c-danger)">{loadError}</div>
{:else if tokens.length === 0}
	<div class="mt-6 card p-10 text-center">
		<div class="text-base font-semibold text-ink">No tokens yet</div>
		<p class="mx-auto mt-1 max-w-md text-sm text-ink-2">
			Mint a scoped token to let a script or the CLI call the API without the dashboard session.
		</p>
		<button class="btn btn-primary mt-4" onclick={openAdd}>Create your first token</button>
	</div>
{:else}
	<div class="mt-6 card overflow-hidden">
		<table class="dtable">
			<thead>
				<tr>
					<th>Name</th><th>Scope</th><th>Prefix</th><th>Created</th>
					<th>Expires</th><th>Last used</th><th>Status</th><th class="text-right">Actions</th>
				</tr>
			</thead>
			<tbody>
				{#each tokens as t (t.id)}
					{@const sb = statusBadge(t)}
					<tr>
						<td class="font-medium">{t.name}</td>
						<td><span class="badge {scopeBadge(t.scope)}">{t.scope}</span></td>
						<td class="tnum text-ink-2">{t.prefix}…</td>
						<td class="text-ink-2">{fmt(t.created_at)}</td>
						<td class="text-ink-2">{t.expires_at ? fmt(t.expires_at) : 'never'}</td>
						<td class="text-ink-2">{fmt(t.last_used_at)}</td>
						<td><span class="badge {sb.cls}">{sb.label}</span></td>
						<td class="text-right whitespace-nowrap">
							{#if !t.revoked_at}
								<button
									class="btn btn-text btn-sm"
									style="color: var(--c-danger)"
									onclick={() => { revoking = t; revokeError = ''; }}>Revoke</button
								>
							{:else}
								<span class="text-xs text-ink-3">revoked {fmt(t.revoked_at)}</span>
							{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

<!-- Create token -->
{#if adding}
	<Modal title="Create API token" onclose={() => (adding = false)}>
		<label class="label" for="tk-name">Name</label>
		<input id="tk-name" class="input" bind:value={fName} placeholder="ci-deploy" />

		<label class="label mt-4" for="tk-scope">Scope</label>
		<select id="tk-scope" class="input" bind:value={fScope}>
			<option value="readonly">readonly — GET only</option>
			<option value="monitor">monitor — sessions, alerts, live stream</option>
			<option value="admin">admin — full management</option>
		</select>

		<label class="label mt-4" for="tk-expiry">Expiry <span class="font-normal normal-case text-ink-3">(optional)</span></label>
		<input id="tk-expiry" class="input" bind:value={fExpiry} placeholder="720h (30 days) — blank for no expiry" />
		<p class="mt-1 text-xs text-ink-3">A Go duration, e.g. <code>24h</code>, <code>720h</code>. Blank means the token never expires.</p>

		{#if addError}<p class="field-error" role="alert">{addError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (adding = false)}>Cancel</button>
			<button class="btn btn-primary" onclick={submitAdd} disabled={addBusy || !fName}>
				{addBusy ? 'Creating…' : 'Create token'}
			</button>
		</div>
	</Modal>
{/if}

<!-- Plaintext secret — shown exactly once -->
{#if minted}
	<Modal title="Token created" onclose={() => (minted = null)}>
		<div class="secret-warn">
			<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="flex-none">
				<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
				<path d="M12 9v4M12 17h.01" />
			</svg>
			<span>Copy this secret now — it will <b>not</b> be shown again. There is no way to recover it later.</span>
		</div>

		<div class="label-row mt-4">
			<span class="label" style="margin-bottom:0">Secret for <span class="text-ink">{minted.name}</span> ({minted.scope})</span>
			<button class="btn btn-text btn-sm" onclick={copySecret}>{copied ? 'Copied' : 'Copy'}</button>
		</div>
		<code class="keybox">{minted.secret}</code>

		<div class="mt-6 flex justify-end">
			<button class="btn btn-primary" onclick={() => (minted = null)}>I've stored it</button>
		</div>
	</Modal>
{/if}

<!-- Revoke -->
{#if revoking}
	<Modal title="Revoke token" onclose={() => (revoking = null)}>
		<p class="text-sm text-ink-2">
			Revoke <span class="font-medium text-ink">{revoking.name}</span> ({revoking.scope})? Any caller
			using it stops working immediately. This cannot be undone.
		</p>
		{#if revokeError}<p class="field-error" role="alert">{revokeError}</p>{/if}
		<div class="mt-6 flex justify-end gap-3">
			<button class="btn btn-secondary" onclick={() => (revoking = null)}>Cancel</button>
			<button class="btn btn-danger" onclick={confirmRevoke} disabled={revokeBusy}>
				{revokeBusy ? 'Revoking…' : 'Revoke'}
			</button>
		</div>
	</Modal>
{/if}

<style>
	.secret-warn {
		display: flex;
		align-items: flex-start;
		gap: 10px;
		padding: 12px 14px;
		border: 1px solid var(--c-warning);
		border-radius: 10px;
		background: var(--c-warning-surface);
		color: var(--c-warning);
		font-size: 13px;
		line-height: 1.45;
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
		color: var(--c-gray-50);
		word-break: break-all;
	}
</style>
