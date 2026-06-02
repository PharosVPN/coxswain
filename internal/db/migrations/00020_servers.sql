-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- The "server" layer (the machine cox owns) beneath node/relay roles. An admin
-- onboards a raw box by IP + username + one-time password; coxswain SSHes in
-- with the password, installs its SSH key, pins the host key, then uses key auth
-- forever. The password is never stored. Node/relay records then link to the
-- server they deploy onto; the controller's own host is a single is_self server.

-- +goose Up

CREATE TABLE servers (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    region       TEXT NOT NULL DEFAULT '',
    ssh_host     TEXT NOT NULL,
    ssh_user     TEXT NOT NULL,
    ssh_port     INTEGER NOT NULL DEFAULT 22,
    -- ssh_host_key pins the host's SSH key, captured at bootstrap (TOFU).
    ssh_host_key TEXT NOT NULL DEFAULT '',
    -- is_self marks the controller's own host: deploys run locally, not over SSH.
    is_self      INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'pending',
    version      INTEGER NOT NULL DEFAULT 1,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- At most one self row.
CREATE UNIQUE INDEX servers_one_self ON servers (is_self) WHERE is_self = 1;

-- Advisory link from a deployed role back to its server (empty = legacy
-- inline-SSH node/relay with no server row).
ALTER TABLE nodes  ADD COLUMN server_id TEXT NOT NULL DEFAULT '';
ALTER TABLE relays ADD COLUMN server_id TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE relays DROP COLUMN server_id;
ALTER TABLE nodes DROP COLUMN server_id;
DROP INDEX servers_one_self;
DROP TABLE servers;
