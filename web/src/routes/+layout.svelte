<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<script lang="ts">
	import '../app.css';
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { api } from '$lib/api';
	import { session } from '$lib/session.svelte';
	import { theme } from '$lib/theme.svelte';
	import type { User } from '$lib/types';

	let { children } = $props();
	let checking = $state(true);

	const path = $derived($page.url.pathname);
	const isLogin = $derived(path === '/login');

	const nav = [
		{ href: '/', label: 'Fleet' },
		{ href: '/users', label: 'Users' },
		{ href: '/admins', label: 'Admins' }
	];

	onMount(async () => {
		if (isLogin) {
			checking = false;
			return;
		}
		try {
			session.user = await api.get<User>('/api/auth/me');
		} catch {
			await goto('/login');
		}
		checking = false;
	});

	async function logout() {
		try {
			await api.post('/api/auth/logout');
		} catch {
			/* logging out locally regardless */
		}
		session.user = null;
		await goto('/login');
	}
</script>

<a href="#main" class="skip-link">Skip to content</a>
<!-- Brand gradient strip — bodaay guide 07: 3px page-top decoration only. -->
<div style="height: 3px; background: linear-gradient(to right, #0f4c5c, #2a8090, #5bb1c2)"></div>

{#if isLogin}
	{@render children()}
{:else if session.user}
	<div class="flex min-h-[calc(100vh-3px)]">
		<aside class="flex w-56 flex-none flex-col border-r border-line bg-toolbar p-4">
			<div class="px-2 py-3">
				<div class="text-xl font-bold text-ink">coxswain</div>
				<div class="text-xs text-ink-3">PharosVPN controller</div>
			</div>
			<nav class="mt-4 flex flex-col gap-1">
				{#each nav as item (item.href)}
					{@const active = path === item.href}
					<a
						href={item.href}
						aria-current={active ? 'page' : undefined}
						class="rounded-md px-3 py-2 text-sm font-medium"
						style={active
							? 'background: var(--hover-overlay); color: var(--c-brand-100)'
							: 'color: var(--c-gray-200)'}
					>
						{item.label}
					</a>
				{/each}
			</nav>
		</aside>

		<div class="flex min-w-0 flex-1 flex-col">
			<header
				class="flex h-16 flex-none items-center justify-end gap-3 border-b border-line bg-toolbar px-6"
			>
				<button
					class="icon-button"
					onclick={() => theme.toggle()}
					aria-label="Toggle dark and light theme"
				>
					{#if theme.mode === 'dark'}
						<!-- sun -->
						<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor"
							stroke-width="2" stroke-linecap="round">
							<circle cx="12" cy="12" r="4" />
							<path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2" />
						</svg>
					{:else}
						<!-- moon -->
						<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor"
							stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
							<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />
						</svg>
					{/if}
				</button>
				<span class="text-sm text-ink-2">{session.user.email}</span>
				<button class="btn btn-text" onclick={logout}>Sign out</button>
			</header>
			<main id="main" class="mx-auto w-full max-w-[1200px] flex-1 p-6">
				{@render children()}
			</main>
		</div>
	</div>
{:else if !checking}
	<div class="p-6 text-sm text-ink-3">Redirecting to sign in…</div>
{/if}
