-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Control-plane egress relaying (DESIGN §3, decision 19): an enrolled relay can
-- also serve as coxswain's egress hop to the buoy fleet, so a node — and anyone
-- watching it — sees the relay's IP, never coxswain's. egress_endpoint is the
-- relay's `beacon egress` tunnel listener address that coxswain dials out to;
-- empty means the relay does not carry control-plane egress.

-- +goose Up

ALTER TABLE relays ADD COLUMN egress_endpoint TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE relays DROP COLUMN egress_endpoint;
