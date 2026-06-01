-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- device_exits records each device's chosen cascade exit (DESIGN §3, decision
-- 18): the node_link (entry→exit edge) a device's traffic egresses through.
-- One active binding per device — switching exit replaces the row, which is the
-- live server-side route flip the design describes. No row means the device
-- egresses normally at its entry (no cascade).

-- +goose Up

CREATE TABLE device_exits (
    device_id    TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    node_link_id TEXT NOT NULL REFERENCES node_links(id) ON DELETE CASCADE,
    version      INTEGER NOT NULL DEFAULT 1,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_device_exits_link ON device_exits(node_link_id);

-- +goose Down

DROP TABLE device_exits;
