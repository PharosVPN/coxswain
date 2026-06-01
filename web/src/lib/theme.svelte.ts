// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Theme state. Dark is the bodaay default; .light-mode on <html> flips to
// light. app.html applies the saved theme before first paint.

type Mode = 'dark' | 'light';

function currentMode(): Mode {
	if (typeof document === 'undefined') return 'dark';
	return document.documentElement.classList.contains('light-mode') ? 'light' : 'dark';
}

class Theme {
	mode = $state<Mode>(currentMode());

	toggle() {
		this.mode = this.mode === 'dark' ? 'light' : 'dark';
		const light = this.mode === 'light';
		document.documentElement.classList.toggle('light-mode', light);
		try {
			localStorage.setItem('theme', this.mode);
		} catch {
			/* storage unavailable — theme still applies for this session */
		}
	}
}

export const theme = new Theme();
