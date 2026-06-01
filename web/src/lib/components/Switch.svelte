<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<!-- Presentational bodaay switch (guide 06.6). The enclosing row owns the
     click + role="switch" + 48dp hit area. -->
<script lang="ts">
	interface Props {
		checked: boolean;
		disabled?: boolean;
	}
	let { checked, disabled = false }: Props = $props();
</script>

<span class="track" class:on={checked} class:disabled aria-hidden="true">
	<span class="thumb"></span>
</span>

<style>
	.track {
		position: relative;
		display: inline-block;
		flex: none;
		width: 44px;
		height: 24px;
		border-radius: 12px;
		background: var(--c-gray-700);
		transition: background-color 0.15s ease;
	}
	.track.on {
		background: var(--c-brand-400);
	}
	.track.disabled {
		opacity: 0.45;
	}
	.thumb {
		position: absolute;
		top: 3px;
		left: 3px;
		width: 18px;
		height: 18px;
		border-radius: 50%;
		background: var(--c-gray-500);
		transition:
			transform 0.15s ease,
			background-color 0.15s ease;
	}
	.track.on .thumb {
		transform: translateX(20px);
		background: #ffffff;
	}
</style>
