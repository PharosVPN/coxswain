-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Control paths: the control-plane route is now a first-class, swappable object,
-- decoupled from server onboarding/deployment.
--
-- A control path is a named, ordered chain of relay-id hops coxswain dials OUT
-- through to reach EVERY node's control plane — hiding the controller's origin.
-- Exactly one path is active at a time (the fleet-wide control route); swapping
-- the active path reroutes the whole control plane live, with no re-onboarding.
-- An empty hop list = direct (coxswain dials nodes with no relay in between).
--
-- This replaces the old model where the route was pinned per-server at onboard
-- (servers.route); that column is retired in a later migration once all readers
-- move to the active control path.

-- +goose Up

CREATE TABLE control_paths (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    -- hops: the ordered relay-id chain (CSV), hop 1 closest to coxswain, the last
    -- hop reaches the node. Empty string = direct.
    hops        TEXT NOT NULL DEFAULT '',
    -- is_active marks the single fleet-wide active control path (1 = active).
    is_active   INTEGER NOT NULL DEFAULT 0,
    version     INTEGER NOT NULL DEFAULT 1,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- At most one active control path (mirrors servers_one_self).
CREATE UNIQUE INDEX control_paths_one_active ON control_paths (is_active) WHERE is_active = 1;

-- +goose Down

DROP TABLE control_paths;
