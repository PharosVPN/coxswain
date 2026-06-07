-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- LOW-14: when a node restarts or its WatchEvents stream drops, in-flight peers
-- never receive a 'disconnect', leaving sessions open forever (and inflating the
-- concurrent-sessions rule). The controller now closes out a dropped node's open
-- sessions with a synthetic 'disconnect'. This column records WHY a disconnect
-- was written ('stream-lost' for those synthetic closures, empty for ordinary
-- node-reported disconnects) so the two are distinguishable in the history.

-- +goose Up

ALTER TABLE connection_events ADD COLUMN reason TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE connection_events RENAME TO connection_events_reasoned;

CREATE TABLE connection_events (
    id              TEXT PRIMARY KEY,
    at              TIMESTAMP NOT NULL,
    node_id         TEXT NOT NULL DEFAULT '',
    peer_id         TEXT NOT NULL DEFAULT '',
    device_id       TEXT,
    user_id         TEXT,
    protocol        TEXT NOT NULL DEFAULT '',
    event_type      TEXT NOT NULL DEFAULT '',
    source_ip       TEXT NOT NULL DEFAULT '',
    source_endpoint TEXT NOT NULL DEFAULT '',
    rx_bytes        INTEGER NOT NULL DEFAULT 0,
    tx_bytes        INTEGER NOT NULL DEFAULT 0
);

INSERT INTO connection_events (id, at, node_id, peer_id, device_id, user_id, protocol, event_type, source_ip, source_endpoint, rx_bytes, tx_bytes)
SELECT id, at, node_id, peer_id, device_id, user_id, protocol, event_type, source_ip, source_endpoint, rx_bytes, tx_bytes
FROM connection_events_reasoned;

DROP TABLE connection_events_reasoned;

CREATE INDEX idx_connection_events_device ON connection_events (device_id, at);
CREATE INDEX idx_connection_events_node ON connection_events (node_id, at);
CREATE INDEX idx_connection_events_source_ip ON connection_events (source_ip, at);
