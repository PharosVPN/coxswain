<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 The PharosVPN Authors -->
<!--
  GeoCredit renders the attribution the active IP-geolocation database's license
  requires (DB-IP Lite is CC-BY-4.0; MaxMind GeoLite2's EULA both mandate it).
  Drop this on ANY view that displays geo-derived locations so attribution is
  never accidentally omitted — it self-fetches /api/geoip and renders nothing
  when no database is in use (the region-map fallback needs no credit).
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api';

	let credit = $state<{ text: string; url: string } | null>(null);

	onMount(async () => {
		try {
			const g = await api.get<{ attribution: { text: string; url: string } }>('/api/geoip');
			credit = g.attribution?.text ? g.attribution : null;
		} catch {
			credit = null;
		}
	});
</script>

{#if credit}
	<p class="geo-credit">
		<a href={credit.url} target="_blank" rel="noopener noreferrer">{credit.text}</a>
	</p>
{/if}

<style>
	.geo-credit {
		margin-top: 6px;
		text-align: right;
		font-size: 11px;
		color: var(--c-gray-300);
	}
	.geo-credit a {
		color: inherit;
		text-decoration: none;
	}
	.geo-credit a:hover {
		text-decoration: underline;
	}
</style>
