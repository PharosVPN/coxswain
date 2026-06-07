<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<script lang="ts">
	import { onMount } from 'svelte';
	import { api, errorMessage } from '$lib/api';
	import type { AuditRecord } from '$lib/types';

	let records = $state<AuditRecord[]>([]);
	let loading = $state(true);
	let loadError = $state('');

	// Filters — mirror the API query params.
	let fAction = $state('');
	let fActor = $state('');
	let fTargetID = $state('');
	let fSince = $state(''); // a datetime-local value, converted to RFC3339
	let fLimit = $state(100);

	function fmt(iso: string): string {
		const d = new Date(iso);
		return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
	}

	function kindBadge(kind: string): string {
		if (kind === 'token') return 'badge-brand';
		if (kind === 'session') return 'badge-info';
		if (kind === 'cli') return 'badge-gray';
		return 'badge-gray';
	}

	function resultBadge(result: string): string {
		return result === 'ok' || result === 'success' ? 'badge-success' : 'badge-danger';
	}

	function targetLabel(r: AuditRecord): string {
		if (!r.target_type && !r.target_id) return '—';
		if (r.target_id) return `${r.target_type || ''} ${r.target_id}`.trim();
		return r.target_type;
	}

	async function load() {
		loading = true;
		loadError = '';
		try {
			const p = new URLSearchParams();
			if (fAction) p.set('action', fAction);
			if (fActor) p.set('actor', fActor);
			if (fTargetID) p.set('target_id', fTargetID);
			if (fSince) {
				const d = new Date(fSince);
				if (!Number.isNaN(d.getTime())) p.set('since', d.toISOString());
			}
			p.set('limit', String(fLimit));
			records = await api.get<AuditRecord[]>(`/api/audit?${p.toString()}`);
		} catch (e) {
			loadError = errorMessage(e);
		}
		loading = false;
	}
	onMount(load);

	function reset() {
		fAction = '';
		fActor = '';
		fTargetID = '';
		fSince = '';
		fLimit = 100;
		load();
	}
</script>

<svelte:head><title>Audit log — coxswain</title></svelte:head>

<div>
	<h1 class="section-title">Audit log</h1>
	<p class="section-subtitle">
		The management trail — every API and CLI mutation, newest first. Filter by action, actor, or
		time.
	</p>
</div>

<!-- Filters -->
<div class="mt-6 card p-4">
	<div class="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
		<div>
			<label class="label" for="f-action">Action</label>
			<input id="f-action" class="input" bind:value={fAction} placeholder="token.create" onkeydown={(e) => e.key === 'Enter' && load()} />
		</div>
		<div>
			<label class="label" for="f-actor">Actor</label>
			<input id="f-actor" class="input" bind:value={fActor} placeholder="admin@…" onkeydown={(e) => e.key === 'Enter' && load()} />
		</div>
		<div>
			<label class="label" for="f-target">Target ID</label>
			<input id="f-target" class="input" bind:value={fTargetID} placeholder="id" onkeydown={(e) => e.key === 'Enter' && load()} />
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
	<div class="mt-6 card p-6 text-sm text-ink-3">Loading audit log…</div>
{:else if loadError}
	<div class="mt-6 card p-6 text-sm" style="color: var(--c-danger)">{loadError}</div>
{:else if records.length === 0}
	<div class="mt-6 card p-10 text-center text-sm text-ink-3">No audit records match these filters.</div>
{:else}
	<div class="mt-6 card overflow-x-auto">
		<table class="dtable">
			<thead>
				<tr>
					<th>Time</th><th>Actor</th><th>Action</th><th>Target</th>
					<th>Result</th><th>Source IP</th>
				</tr>
			</thead>
			<tbody>
				{#each records as r (r.id)}
					<tr>
						<td class="tnum whitespace-nowrap text-ink-2">{fmt(r.at)}</td>
						<td>
							<div class="flex items-center gap-2">
								<span class="font-medium">{r.actor || '—'}</span>
								{#if r.actor_kind}<span class="badge {kindBadge(r.actor_kind)}">{r.actor_kind}</span>{/if}
							</div>
						</td>
						<td class="tnum text-ink-2">{r.action}</td>
						<td class="text-ink-2">{targetLabel(r)}</td>
						<td>
							<span class="badge {resultBadge(r.result)}">{r.result || 'ok'}</span>
							{#if r.error}<div class="mt-1 text-xs" style="color: var(--c-danger)">{r.error}</div>{/if}
						</td>
						<td class="tnum text-ink-2">{r.source_ip || '—'}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
