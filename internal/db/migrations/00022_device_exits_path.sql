-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Re-key device_exits from a single node_link (entry→exit edge) to a named path
-- (DESIGN §3, decision 18 generalized): a device now binds to a multi-hop path,
-- and the cascade coordinator wires every segment along it. The DB is a blank
-- slate at this migration (no live bindings), so this is a clean drop/recreate
-- with no backfill. One active binding per device; switching path replaces the
-- row (the live route flip). No row means the device egresses normally.

-- +goose Up

DROP TABLE device_exits;

CREATE TABLE device_exits (
    device_id  TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    path_id    TEXT NOT NULL REFERENCES paths(id) ON DELETE CASCADE,
    version    INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_device_exits_path ON device_exits(path_id);

-- +goose Down

DROP TABLE device_exits;

CREATE TABLE device_exits (
    device_id    TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    node_link_id TEXT NOT NULL REFERENCES node_links(id) ON DELETE CASCADE,
    version      INTEGER NOT NULL DEFAULT 1,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_device_exits_link ON device_exits(node_link_id);
