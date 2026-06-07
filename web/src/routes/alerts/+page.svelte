<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<script lang="ts">
	import { onMount } from 'svelte';
	import { api, errorMessage } from '$lib/api';
	import type { Alert, AlertsEnvelope } from '$lib/types';

	let alerts = $state<Alert[]>([]);
	let backendWarning = $state('');
	let warningDismissed = $state(false);
	let loading = $state(true);
	let loadError = $state('');

	// Filters — default to open alerts so the page lands on what needs action.
	let fStatus = $state('open');
	let fKind = $state('');
	let fSeverity = $state('');

	// Per-alert in-flight action, keyed by id, so only that card's buttons disable.
	let busyId = $state('');
	let actionError = $state('');

	function fmt(iso: string): string {
		const d = new Date(iso);
		return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
	}

	function severityBadge(sev: string): string {
		if (sev === 'critical') return 'badge-danger';
		if (sev === 'warning') return 'badge-warning';
		return 'badge-info';
	}

	function statusBadge(status: string): string {
		if (status === 'open') return 'badge-warning';
		if (status === 'acknowledged') return 'badge-info';
		if (status === 'resolved') return 'badge-success';
		return 'badge-gray';
	}

	// Pretty-print the evidence JSON for the card.
	function detailText(d?: Record<string, unknown>): string {
		if (!d || Object.keys(d).length === 0) return '';
		try {
			return JSON.stringify(d, null, 2);
		} catch {
			return '';
		}
	}

	async function load() {
		loading = true;
		loadError = '';
		try {
			const p = new URLSearchParams();
			if (fStatus) p.set('status', fStatus);
			if (fKind) p.set('kind', fKind);
			if (fSeverity) p.set('severity', fSeverity);
			const env = await api.get<AlertsEnvelope>(`/api/alerts?${p.toString()}`);
			alerts = env.alerts ?? [];
			backendWarning = env.backend_warning ?? '';
		} catch (e) {
			loadError = errorMessage(e);
		}
		loading = false;
	}
	onMount(load);

	async function act(a: Alert, op: 'ack' | 'resolve') {
		busyId = a.id;
		actionError = '';
		try {
			await api.post<Alert>(`/api/alerts/${a.id}/${op}`);
			await load();
		} catch (e) {
			actionError = errorMessage(e);
		}
		busyId = '';
	}
</script>

<svelte:head><title>Alerts — coxswain</title></svelte:head>

<div>
	<h1 class="section-title">Alerts</h1>
	<p class="section-subtitle">
		Anomaly-detection findings over the session history. Acknowledge one you're working, resolve it
		when handled.
	</p>
</div>

<!-- Analytics backend warning (SQLite) — dismissible. -->
{#if backendWarning && !warningDismissed}
	<div class="mt-6 warn-banner">
		<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="flex-none">
			<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
			<path d="M12 9v4M12 17h.01" />
		</svg>
		<span class="grow">Analytics on SQLite — consider Postgres for scale. ({backendWarning})</span>
		<button class="banner-x" aria-label="Dismiss" onclick={() => (warningDismissed = true)}>✕</button>
	</div>
{/if}

<!-- Filters -->
<div class="mt-6 card p-4">
	<div class="grid grid-cols-1 gap-3 sm:grid-cols-3">
		<div>
			<label class="label" for="f-status">Status</label>
			<select id="f-status" class="input" bind:value={fStatus} onchange={load}>
				<option value="open">Open</option>
				<option value="acknowledged">Acknowledged</option>
				<option value="resolved">Resolved</option>
				<option value="">All</option>
			</select>
		</div>
		<div>
			<label class="label" for="f-severity">Severity</label>
			<select id="f-severity" class="input" bind:value={fSeverity} onchange={load}>
				<option value="">All</option>
				<option value="critical">Critical</option>
				<option value="warning">Warning</option>
				<option value="info">Info</option>
			</select>
		</div>
		<div>
			<label class="label" for="f-kind">Kind</label>
			<input id="f-kind" class="input" bind:value={fKind} placeholder="e.g. impossible_travel" onkeydown={(e) => e.key === 'Enter' && load()} />
		</div>
	</div>
	<div class="mt-3 flex gap-2">
		<button class="btn btn-primary btn-sm" onclick={load} disabled={loading}>{loading ? 'Loading…' : 'Apply filters'}</button>
	</div>
</div>

{#if actionError}<p class="field-error mt-3" role="alert">{actionError}</p>{/if}

{#if loading}
	<div class="mt-6 card p-6 text-sm text-ink-3">Loading alerts…</div>
{:else if loadError}
	<div class="mt-6 card p-6 text-sm" style="color: var(--c-danger)">{loadError}</div>
{:else if alerts.length === 0}
	<div class="mt-6 card p-10 text-center text-sm text-ink-3">No alerts match these filters.</div>
{:else}
	<div class="mt-6 flex flex-col gap-3">
		{#each alerts as a (a.id)}
			{@const detail = detailText(a.detail)}
			<div class="card sev-card p-5" style="border-left-color: var(--c-{a.severity === 'critical' ? 'danger' : a.severity === 'warning' ? 'warning' : 'info'})">
				<div class="flex items-start justify-between gap-4">
					<div class="min-w-0">
						<div class="flex flex-wrap items-center gap-2">
							<span class="badge {severityBadge(a.severity)}">{a.severity}</span>
							<span class="text-base font-semibold text-ink">{a.kind}</span>
							<span class="badge {statusBadge(a.status)}">{a.status}</span>
						</div>
						<div class="mt-1 text-sm text-ink-2">
							{fmt(a.at)}
							{#if a.user_id}· user {a.user_id}{/if}
							{#if a.device_id}· device {a.device_id}{/if}
							{#if a.node_id}· node {a.node_id}{/if}
						</div>
						{#if a.source_ips && a.source_ips.length > 0}
							<div class="mt-1 text-sm text-ink-3">
								source IPs: <span class="tnum text-ink-2">{a.source_ips.join(', ')}</span>
							</div>
						{/if}
					</div>
					<div class="flex flex-none gap-2">
						{#if a.status === 'open'}
							<button class="btn btn-secondary btn-sm" onclick={() => act(a, 'ack')} disabled={busyId === a.id}>
								{busyId === a.id ? '…' : 'Ack'}
							</button>
						{/if}
						{#if a.status !== 'resolved'}
							<button class="btn btn-primary btn-sm" onclick={() => act(a, 'resolve')} disabled={busyId === a.id}>
								{busyId === a.id ? '…' : 'Resolve'}
							</button>
						{/if}
					</div>
				</div>

				{#if detail}
					<details class="mt-3">
						<summary class="cursor-pointer text-xs font-medium text-brand">Evidence</summary>
						<pre class="evidence">{detail}</pre>
					</details>
				{/if}
			</div>
		{/each}
	</div>
{/if}

<style>
	.warn-banner {
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
	.banner-x {
		flex: none;
		background: transparent;
		border: none;
		color: inherit;
		cursor: pointer;
		font-size: 13px;
		line-height: 1;
		padding: 2px 4px;
	}
	.grow {
		flex: 1 1 auto;
		min-width: 0;
	}
	.sev-card {
		border-left-width: 3px;
		border-left-style: solid;
	}
	.evidence {
		margin-top: 8px;
		padding: 10px 12px;
		border: 1px solid var(--c-line);
		border-radius: 8px;
		background: var(--c-bg);
		font-family: ui-monospace, monospace;
		font-size: 12px;
		color: var(--c-gray-200);
		white-space: pre-wrap;
		word-break: break-word;
		overflow-x: auto;
	}
</style>
