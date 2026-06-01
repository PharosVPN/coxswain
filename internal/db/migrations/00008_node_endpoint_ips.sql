-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Multi-endpoint nodes (DESIGN §3, decision 17). A node accepts AmneziaWG on
-- a set of public IPs; combined with a fleet-wide UDP port range, that is a
-- large pool of (ip, port) endpoints for client rotation. Comma-separated;
-- empty means "use public_ip only".

-- +goose Up

ALTER TABLE nodes ADD COLUMN endpoint_ips TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE nodes DROP COLUMN endpoint_ips;
