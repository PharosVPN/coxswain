// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// coxswain's admin UI is a single-page app: no server-side rendering, no
// prerendering. The Go binary embeds the build and serves index.html for
// every route.
export const ssr = false;
export const prerender = false;
