-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Peer provisioning: each node's AmneziaWG server public key. node generates
-- the node's data-plane keypair on the node (same principle as its mTLS key,
-- decision 14) and reports the public key; coxswain needs it to build the peer
-- entry in a user's profile.

-- +goose Up

ALTER TABLE nodes ADD COLUMN wg_public_key TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE nodes DROP COLUMN wg_public_key;
