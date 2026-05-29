import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [sveltekit()],
	server: {
		// `npm run dev` proxies the API + WebSocket to a running `cox serve`.
		proxy: {
			'/api': 'http://127.0.0.1:8443',
			'/ws': { target: 'ws://127.0.0.1:8443', ws: true }
		}
	}
});
