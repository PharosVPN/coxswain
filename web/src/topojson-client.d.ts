// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// topojson-client ships no types; we only use feature() and cast its result for
// d3-geo, so a minimal ambient declaration is enough.
declare module 'topojson-client' {
	export function feature(topology: unknown, object: unknown): unknown;
	export function mesh(topology: unknown, object?: unknown): unknown;
}
