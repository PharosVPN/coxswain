-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- SSH-based node onboarding (DESIGN §5). coxswain reaches a node over SSH only to
-- install and update the buoy agent; all control is gRPC. This migration adds
-- the SSH connection details to `nodes` and a single-row table holding coxswain's
-- own SSH identity.

-- +goose Up

ALTER TABLE nodes ADD COLUMN ssh_host TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN ssh_user TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN ssh_port INTEGER NOT NULL DEFAULT 22;
-- ssh_host_key pins the node's SSH host key, captured on first connect (TOFU).
ALTER TABLE nodes ADD COLUMN ssh_host_key TEXT NOT NULL DEFAULT '';
-- agent_version records the buoy build last deployed to the node.
ALTER TABLE nodes ADD COLUMN agent_version TEXT NOT NULL DEFAULT '';

-- ssh_identity holds coxswain's own SSH keypair (one row). The operator adds the
-- public key to a new VM's authorized_keys; coxswain dials out with the private key.
CREATE TABLE ssh_identity (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    public_key  TEXT NOT NULL,
    private_key TEXT NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- +goose Down

DROP TABLE ssh_identity;
ALTER TABLE nodes DROP COLUMN agent_version;
ALTER TABLE nodes DROP COLUMN ssh_host_key;
ALTER TABLE nodes DROP COLUMN ssh_port;
ALTER TABLE nodes DROP COLUMN ssh_user;
ALTER TABLE nodes DROP COLUMN ssh_host;
