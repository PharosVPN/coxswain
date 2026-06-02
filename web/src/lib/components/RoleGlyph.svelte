<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<!--
  RoleGlyph — the role marks. Line icons in currentColor so they take the pin's
  status glow or the legend's ink.
    controller — a lighthouse (steers the fleet)
    node       — a life-ring (where you surface on the internet)
    relay      — a radiating signal (a hop that hides the controller)
-->
<script lang="ts">
	import type { Role } from '$lib/roles';
	let { role, size = 16 }: { role: Role; size?: number } = $props();
</script>

<svg
	width={size}
	height={size}
	viewBox="0 0 24 24"
	fill="none"
	stroke="currentColor"
	stroke-width="1.7"
	stroke-linecap="round"
	stroke-linejoin="round"
	aria-hidden="true"
>
	{#if role === 'controller'}
		<!-- lighthouse: lantern, beams, tapered tower, base -->
		<path d="M9.2 7.5 L12 4 L14.8 7.5" />
		<path d="M9.4 7.5 H14.6 V10 H9.4 Z" />
		<path d="M5.5 7 L9.4 8.4 M18.5 7 L14.6 8.4" />
		<path d="M9.6 10 L8.3 20 H15.7 L14.4 10" />
		<path d="M8.7 15 H15.3" />
		<path d="M6.8 20 H17.2" />
	{:else if role === 'node'}
		<!-- life-ring: outer + inner rings, four lashings -->
		<circle cx="12" cy="12" r="8" />
		<circle cx="12" cy="12" r="3.4" />
		<path d="M12 4 V8.6 M12 15.4 V20 M4 12 H8.6 M15.4 12 H20" />
	{:else if role === 'relay'}
		<!-- relay: emitter + radiating signal -->
		<circle cx="12" cy="17" r="1.6" fill="currentColor" stroke="none" />
		<path d="M12 17 V12.5" />
		<path d="M8.8 13.2 A4.6 4.6 0 0 1 15.2 13.2" />
		<path d="M6.6 11.2 A8 8 0 0 1 17.4 11.2" />
	{:else}
		<!-- server: a bare machine (stacked rack units), no role yet -->
		<rect x="4.5" y="5" width="15" height="6" rx="1.5" />
		<rect x="4.5" y="13" width="15" height="6" rx="1.5" />
		<circle cx="7.6" cy="8" r="0.9" fill="currentColor" stroke="none" />
		<circle cx="7.6" cy="16" r="0.9" fill="currentColor" stroke="none" />
	{/if}
</svg>
