-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 The PharosVPN Authors
--
-- node_links is the admin-defined node-cascade graph (DESIGN §3, decision 18):
-- each row is one entry→exit edge over an inner AmneziaWG link. coxswain is the
-- sole mesh coordinator; a device's selectable exits are the nodes reachable
-- from its entry across this graph.
--
-- The inner interface needs no tunnel address — WireGuard routes by AllowedIPs.
-- A row holds the edge plus the resources coxswain allocates on the ENTRY node:
-- the inner interface name, its listen port, and the fwmark / routing-table id
-- the per-device transit routes use. preshared_key is the link's PSK.

-- +goose Up

CREATE TABLE node_links (
    id              TEXT PRIMARY KEY,
    entry_node_id   TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    exit_node_id    TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    inner_interface TEXT NOT NULL,
    listen_port     INTEGER NOT NULL,
    fwmark          INTEGER NOT NULL,
    table_id        INTEGER NOT NULL,
    preshared_key   TEXT NOT NULL DEFAULT '',
    config_revision INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'pending',
    version         INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (entry_node_id <> exit_node_id),
    UNIQUE (entry_node_id, exit_node_id),
    UNIQUE (entry_node_id, inner_interface),
    UNIQUE (entry_node_id, listen_port),
    UNIQUE (entry_node_id, fwmark),
    UNIQUE (entry_node_id, table_id)
);

CREATE INDEX idx_node_links_entry ON node_links(entry_node_id);
CREATE INDEX idx_node_links_exit ON node_links(exit_node_id);

-- +goose Down

DROP TABLE node_links;
