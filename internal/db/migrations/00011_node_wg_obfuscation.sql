-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Per-node AmneziaWG obfuscation (DESIGN §3). Every node runs AmneziaWG and
-- randomises its own obfuscation parameters (Jc/Jmin/Jmax, S1-S4, H1-H4,
-- I1-I5) for traffic diversity. buoy generates and applies them; coxswain stores
-- the set as a JSON document and a client needs the exact values to build a
-- tunnel that handshakes. Empty string means "not reported yet".

-- +goose Up

ALTER TABLE nodes ADD COLUMN wg_obfuscation TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE nodes DROP COLUMN wg_obfuscation;
