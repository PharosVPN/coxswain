<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { api, errorMessage } from '$lib/api';
	import { session } from '$lib/session.svelte';
	import type { User } from '$lib/types';

	let username = $state('');
	let password = $state('');
	let error = $state('');
	let busy = $state(false);

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		error = '';
		busy = true;
		try {
			session.user = await api.post<User>('/api/auth/login', { username, password });
			await goto('/');
		} catch (err) {
			error = errorMessage(err);
			busy = false;
		}
	}
</script>

<svelte:head><title>Sign in — coxswain</title></svelte:head>

<div class="flex min-h-[calc(100vh-3px)] items-center justify-center bg-bg p-4">
	<div class="card anim-fade w-full max-w-[360px] p-6">
		<div class="text-2xl font-bold text-ink">coxswain</div>
		<p class="overline mt-1">PharosVPN controller</p>

		<form class="mt-6 flex flex-col gap-4" onsubmit={submit}>
			<div>
				<label class="label" for="username">Username</label>
				<input
					id="username"
					class="input"
					bind:value={username}
					autocomplete="username"
					required
				/>
			</div>
			<div>
				<label class="label" for="password">Password</label>
				<input
					id="password"
					class="input"
					type="password"
					bind:value={password}
					autocomplete="current-password"
					required
				/>
			</div>

			{#if error}
				<div
					class="badge badge-danger w-full justify-start"
					style="border-radius: 12px; padding: 12px"
					role="alert"
				>
					{error}
				</div>
			{/if}

			<button class="btn btn-primary mt-2" type="submit" disabled={busy}>
				{busy ? 'Signing in…' : 'Sign in'}
			</button>
		</form>
	</div>
</div>
