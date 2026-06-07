-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- connection_events is the persisted, source-IP-aware session history. The node
-- WatchEvents firehose is ephemeral; this table is its durable record, the
-- foundation the analytics engine (Phase C) consumes. coxswain ingests each
-- node event, resolves the peer public key to a device/user via the peers and
-- devices tables, derives the client source IP from the source endpoint, and
-- writes a row here for session boundaries (connect/disconnect; handshake
-- keepalives are not all stored). Rows are purged on the retention.metrics_days
-- schedule.

-- +goose Up

CREATE TABLE connection_events (
    id              TEXT PRIMARY KEY,
    at              TIMESTAMP NOT NULL,
    -- node_id is the node that observed the event (no FK: history outlives a
    -- deleted node).
    node_id         TEXT NOT NULL DEFAULT '',
    -- peer_id is the data-plane peer public key (AmneziaWG public key / XRay UUID).
    peer_id         TEXT NOT NULL DEFAULT '',
    -- device_id / user_id are resolved from peer_id at ingest; nullable when the
    -- peer is unknown (a removed device, or a peer coxswain never provisioned).
    device_id       TEXT,
    user_id         TEXT,
    protocol        TEXT NOT NULL DEFAULT '',
    -- event_type is 'connect', 'disconnect', or 'handshake'.
    event_type      TEXT NOT NULL DEFAULT '',
    -- source_ip is the client's public IP (the source_endpoint with its port
    -- stripped); source_endpoint keeps the full IP:port.
    source_ip       TEXT NOT NULL DEFAULT '',
    source_endpoint TEXT NOT NULL DEFAULT '',
    rx_bytes        INTEGER NOT NULL DEFAULT 0,
    tx_bytes        INTEGER NOT NULL DEFAULT 0
);

-- The analytics + history queries scan newest-first within a subject window.
CREATE INDEX idx_connection_events_device ON connection_events (device_id, at);
CREATE INDEX idx_connection_events_node ON connection_events (node_id, at);
CREATE INDEX idx_connection_events_source_ip ON connection_events (source_ip, at);

-- +goose Down

DROP TABLE connection_events;
