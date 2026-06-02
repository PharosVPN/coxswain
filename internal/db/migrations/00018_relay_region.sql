-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- A relay's region, so the admin map can pin a relay on its city the same way
-- it pins a node node. Mirrors nodes.region; empty until set at enrollment.

-- +goose Up

ALTER TABLE relays ADD COLUMN region TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE relays DROP COLUMN region;
