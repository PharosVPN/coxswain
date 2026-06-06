-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- A "profile" (the admin-created object) is a named connection config the
-- controller hands a device: an egress (either a multi-hop path, or a single
-- node for a direct exit), an optional subset of the entry node's IP pool, and
-- one data-plane protocol. A device can hold several profiles. Provisioning
-- instantiates a profile for the device (its own keys/tunnel IP/peers) and the
-- sealed sync bundle carries the device's profiles[]. Stored as `profile_specs`
-- so it doesn't collide with the existing `profiles` table (the sealed bundles).
-- peers.profile_spec_id ties each minted peer to the profile that created it, so
-- a device may have distinct peers per profile on the same node.

-- +goose Up

CREATE TABLE profile_specs (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    device_id  TEXT NOT NULL,
    name       TEXT NOT NULL,
    -- egress: exactly one of path_id (cascade) or node_id (direct single node).
    path_id    TEXT NOT NULL DEFAULT '',
    node_id    TEXT NOT NULL DEFAULT '',
    -- entry_ips is a comma-separated subset of the entry node's IP pool the
    -- client may enter on; empty = all of the entry node's IPs.
    entry_ips  TEXT NOT NULL DEFAULT '',
    -- protocol is the entry transport: 'amneziawg' or 'xray-reality'.
    protocol   TEXT NOT NULL,
    version    INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_profile_specs_device ON profile_specs (device_id);
CREATE INDEX idx_profile_specs_user ON profile_specs (user_id);

ALTER TABLE peers ADD COLUMN profile_spec_id TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE peers DROP COLUMN profile_spec_id;
DROP TABLE profile_specs;
