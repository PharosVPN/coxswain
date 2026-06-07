-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Scoped API tokens for programmatic access to the admin API alongside the
-- session cookie. A token carries one scope ('readonly' < 'monitor' < 'admin')
-- that gates what its bearer may do. coxswain stores only the SHA-256 of the
-- secret (hex) plus a short non-secret prefix for display; the plaintext secret
-- is returned exactly once at creation and never persisted. expires_at,
-- last_used_at, and revoked_at are nullable.

-- +goose Up

CREATE TABLE api_tokens (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    -- scope: 'readonly', 'monitor', or 'admin'.
    scope        TEXT NOT NULL,
    -- token_hash is the hex SHA-256 of the plaintext secret (never the secret).
    token_hash   TEXT NOT NULL UNIQUE,
    -- token_prefix is the first ~10 chars of the secret, shown in listings.
    token_prefix TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMP NOT NULL,
    created_by   TEXT NOT NULL DEFAULT '',
    expires_at   TIMESTAMP,
    last_used_at TIMESTAMP,
    revoked_at   TIMESTAMP
);

CREATE INDEX idx_api_tokens_hash ON api_tokens (token_hash);

-- +goose Down

DROP TABLE api_tokens;
