-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- An optional admin-chosen colour for a cascade path, so a fleet with several
-- data-plane routes can tell them apart at a glance on the map. Empty means the
-- UI auto-assigns one from a palette.

-- +goose Up

ALTER TABLE node_links ADD COLUMN color TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE node_links DROP COLUMN color;
