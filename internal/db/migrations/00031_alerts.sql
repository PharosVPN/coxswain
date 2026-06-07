-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- alerts is the analytics engine's output (Phase C): one row per detected
-- anomaly over the connection_events session history. The engine (package
-- analytics) sweeps recent events on a periodic ticker, runs each rule, and
-- upserts findings here. An alert is deduplicated by dedup_key while still
-- 'open' — a persistent condition refreshes the existing row (bumping
-- updated_at and merging evidence) instead of spawning a new alert every sweep,
-- so a leaked profile that keeps reconnecting does not flood the table.
--
-- kind is the rule (leaked_profile, impossible_travel, concurrent_sessions,
-- new_geo, ...); severity is info|warning|critical; source_ips is a JSON array
-- of the client IPs involved; detail is a small JSON blob of rule-specific
-- evidence. Rows are purged on the retention.metrics_days schedule (same
-- time-series class as connection_events).

-- +goose Up

CREATE TABLE alerts (
    id          TEXT PRIMARY KEY,
    at          TIMESTAMP NOT NULL,
    -- kind is the rule that fired, e.g. 'leaked_profile', 'impossible_travel'.
    kind        TEXT NOT NULL DEFAULT '',
    -- severity is 'info', 'warning', or 'critical'.
    severity    TEXT NOT NULL DEFAULT 'info',
    -- device_id / user_id identify the subject. device_id is always set (rules
    -- filter device_id IS NOT NULL); user_id is the resolved owner when known.
    device_id   TEXT,
    user_id     TEXT,
    -- node_id is the node most relevant to the finding, when one applies.
    node_id     TEXT,
    -- source_ips is a JSON array of the client IPs involved in the finding.
    source_ips  TEXT NOT NULL DEFAULT '[]',
    -- detail is a small JSON object of rule-specific evidence.
    detail      TEXT NOT NULL DEFAULT '{}',
    -- status is 'open', 'acknowledged', or 'resolved'.
    status      TEXT NOT NULL DEFAULT 'open',
    -- dedup_key collapses repeated detections of the same condition; while an
    -- alert with this key is still 'open', the engine refreshes it in place.
    dedup_key   TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMP NOT NULL,
    updated_at  TIMESTAMP NOT NULL
);

-- Newest-first scans by status (the default list filter) and per-device drill-down.
CREATE INDEX idx_alerts_status_at ON alerts (status, at);
CREATE INDEX idx_alerts_device_at ON alerts (device_id, at);

-- The dedup guard: at most one OPEN alert per dedup_key. A partial unique index
-- (only over status='open' rows) lets a key recur once the prior alert is
-- acknowledged/resolved, while preventing duplicate open rows in between.
CREATE UNIQUE INDEX idx_alerts_dedup_open ON alerts (dedup_key) WHERE status = 'open';

-- +goose Down

DROP TABLE alerts;
