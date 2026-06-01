<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<script lang="ts">
	interface Props {
		title: string;
		onclose: () => void;
		children: import('svelte').Snippet;
	}
	let { title, onclose, children }: Props = $props();

	function onkeydown(e: KeyboardEvent) {
		if (e.key === 'Escape') onclose();
	}
</script>

<svelte:window {onkeydown} />

<!-- Dialog backdrop. Click outside or Escape to dismiss. -->
<div
	class="fixed inset-0 z-40 flex items-center justify-center p-4"
	style="background: rgba(0,0,0,0.6)"
	role="presentation"
	onclick={(e) => {
		if (e.target === e.currentTarget) onclose();
	}}
>
	<div
		class="card anim-slide w-full max-w-[400px] p-6"
		style="box-shadow: var(--shadow-modal)"
		role="dialog"
		aria-modal="true"
		aria-label={title}
	>
		<h2 class="text-lg font-semibold text-ink">{title}</h2>
		<div class="mt-4">
			{@render children()}
		</div>
	</div>
</div>
