-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Per-node network policy (DESIGN §3, decision 16). Operators set each buoy's
-- traffic handling: forwarding, masquerade (source NAT), client isolation.
-- New nodes default to the common internet-egress VPN posture.

-- +goose Up

ALTER TABLE nodes ADD COLUMN forwarding INTEGER NOT NULL DEFAULT 1;
ALTER TABLE nodes ADD COLUMN masquerade INTEGER NOT NULL DEFAULT 1;
ALTER TABLE nodes ADD COLUMN isolation  INTEGER NOT NULL DEFAULT 0;

-- +goose Down

ALTER TABLE nodes DROP COLUMN isolation;
ALTER TABLE nodes DROP COLUMN masquerade;
ALTER TABLE nodes DROP COLUMN forwarding;
