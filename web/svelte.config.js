import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	kit: {
		// Single-page app: the Go binary embeds this output and serves
		// index.html for every non-asset route. coxswain opens no public ports.
		adapter: adapter({
			pages: '../internal/webui/dist',
			assets: '../internal/webui/dist',
			fallback: 'index.html',
			precompress: false,
			strict: true
		})
	}
};

export default config;
