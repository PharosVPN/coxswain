-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Tamper-evidence for the audit log (MED-9). The 00028 audit_log table is
-- documented as "append-only", but nothing made an edit/delete detectable. This
-- adds a lightweight hash chain: each row carries the row_hash of its
-- predecessor (prev_hash) and its own row_hash, computed in package audit as
--
--     row_hash = sha256hex( prev_hash || canonical(row fields) )
--
-- where canonical() is a deterministic, length-prefixed encoding of every stored
-- column. Editing or deleting any row breaks the link to the next row, so
-- `cox audit verify` (and audit.Verify) reports the first break. The columns
-- default to '' for any pre-existing rows; the db.Migrate backfill recomputes the
-- chain over them right after this migration applies, so the "append-only" claim
-- is now backed by a detectable, single-binary integrity check.

-- +goose Up

ALTER TABLE audit_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_log ADD COLUMN row_hash  TEXT NOT NULL DEFAULT '';

-- +goose Down

-- SQLite (and goose's split-statement runner) can't DROP COLUMN portably here;
-- rebuild the table without the chain columns to reverse the migration.
ALTER TABLE audit_log RENAME TO audit_log_chained;

CREATE TABLE audit_log (
    id          TEXT PRIMARY KEY,
    at          TIMESTAMP NOT NULL,
    actor       TEXT NOT NULL DEFAULT '',
    actor_kind  TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id   TEXT NOT NULL DEFAULT '',
    source_ip   TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    result      TEXT NOT NULL DEFAULT 'ok',
    error       TEXT NOT NULL DEFAULT ''
);

INSERT INTO audit_log (id, at, actor, actor_kind, action, target_type, target_id, source_ip, detail, result, error)
SELECT id, at, actor, actor_kind, action, target_type, target_id, source_ip, detail, result, error
FROM audit_log_chained;

DROP TABLE audit_log_chained;

CREATE INDEX idx_audit_log_at ON audit_log (at DESC);
CREATE INDEX idx_audit_log_actor ON audit_log (actor);
CREATE INDEX idx_audit_log_action ON audit_log (action);
CREATE INDEX idx_audit_log_target ON audit_log (target_id);
