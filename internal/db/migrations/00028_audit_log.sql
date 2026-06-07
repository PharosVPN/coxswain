-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- A first-class audit log of every management mutation — who did what, to what,
-- from where, and whether it succeeded. Every API and CLI mutation writes one
-- row here (and emits a structured slog line, so it also reaches journald).
-- Rows are purged on the retention.audit_days schedule. The `detail` column is
-- a small JSON blob of action-specific context; `error` holds the failure
-- message when result = 'error'.
--
-- This replaces the unused placeholder audit_log table from the initial schema
-- (an auto-increment stub that no code ever wrote to) with a first-class one:
-- a TEXT id, explicit actor_kind/target_type/target_id, source_ip, JSON detail,
-- and a result/error pair. No data is lost — the legacy table was always empty.

-- +goose Up

DROP TABLE IF EXISTS audit_log;

CREATE TABLE audit_log (
    id          TEXT PRIMARY KEY,
    at          TIMESTAMP NOT NULL,
    -- actor is the token name or the session/CLI user that performed the action.
    actor       TEXT NOT NULL DEFAULT '',
    -- actor_kind is 'token', 'session', or 'cli'.
    actor_kind  TEXT NOT NULL DEFAULT '',
    -- action is a dotted verb, e.g. 'node.add', 'profile.create', 'token.revoke'.
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id   TEXT NOT NULL DEFAULT '',
    source_ip   TEXT NOT NULL DEFAULT '',
    -- detail is a small JSON object of action-specific context.
    detail      TEXT NOT NULL DEFAULT '',
    -- result is 'ok' or 'error'.
    result      TEXT NOT NULL DEFAULT 'ok',
    error       TEXT NOT NULL DEFAULT ''
);

-- Newest-first scans and the common filter columns.
CREATE INDEX idx_audit_log_at ON audit_log (at DESC);
CREATE INDEX idx_audit_log_actor ON audit_log (actor);
CREATE INDEX idx_audit_log_action ON audit_log (action);
CREATE INDEX idx_audit_log_target ON audit_log (target_id);

-- +goose Down

DROP TABLE audit_log;

-- Restore the original placeholder table from the initial schema.
CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    actor      TEXT,
    action     TEXT NOT NULL,
    target     TEXT,
    detail     TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_audit_log_created ON audit_log(created_at);
