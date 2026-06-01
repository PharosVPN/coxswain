// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

import type { ApiError } from './types';

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
	const res = await fetch(path, {
		method,
		credentials: 'same-origin',
		headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
		body: body !== undefined ? JSON.stringify(body) : undefined
	});

	if (res.status === 204) {
		return undefined as T;
	}
	const data = await res.json().catch(() => ({}));
	if (!res.ok) {
		const err: ApiError = {
			status: res.status,
			message: (data as { error?: string }).error ?? res.statusText
		};
		throw err;
	}
	return data as T;
}

export const api = {
	get: <T>(path: string) => request<T>('GET', path),
	post: <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {}),
	patch: <T>(path: string, body: unknown) => request<T>('PATCH', path, body),
	del: (path: string) => request<void>('DELETE', path)
};

/** isApiError narrows an unknown caught value to an ApiError. */
export function isApiError(e: unknown): e is ApiError {
	return typeof e === 'object' && e !== null && 'status' in e && 'message' in e;
}

/** errorMessage extracts a human message from any thrown value. */
export function errorMessage(e: unknown): string {
	if (isApiError(e)) return e.message;
	if (e instanceof Error) return e.message;
	return 'Unexpected error';
}
