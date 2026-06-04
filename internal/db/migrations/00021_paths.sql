-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- A "path" is a named, ordered data plane (DESIGN §3, decision 18 generalized):
-- entry → [mid] → exit, a chain a client's traffic traverses before egressing.
-- The hop list is the source of truth (what the admin edits, what the map draws);
-- the inner-link segments between consecutive hops are node_links rows, shared
-- across paths. A device binds to a path, not to a bare node_link (see 00022).
-- hop_index 0 is the entry, the last hop is the exit; up to MaxPathHops segments.

-- +goose Up

CREATE TABLE paths (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    -- color is the admin-chosen map colour for the whole path; empty lets the UI
    -- auto-assign one from the palette.
    color      TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'pending',
    version    INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (name)
);

CREATE TABLE path_hops (
    path_id   TEXT NOT NULL REFERENCES paths(id) ON DELETE CASCADE,
    hop_index INTEGER NOT NULL,
    -- ON DELETE RESTRICT: a node that is a hop of any path cannot be deleted out
    -- from under it (the schema backstop for the data-plane-safe removal block).
    node_id   TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    PRIMARY KEY (path_id, hop_index),
    UNIQUE (path_id, node_id)
);

CREATE INDEX idx_path_hops_node ON path_hops(node_id);

-- +goose Down

DROP TABLE path_hops;
DROP TABLE paths;
