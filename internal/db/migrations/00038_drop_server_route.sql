-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Retire servers.route. The control-plane route is now a first-class, swappable
-- object (control_paths, migration 00036) that noderoute resolves fleet-wide; the
-- per-server route was only still feeding the onboard/deploy SSH dial. That dial
-- is now a transient, per-action choice (passed at add/deploy time, never stored),
-- so the column is dropped.

-- +goose Up

ALTER TABLE servers DROP COLUMN route;

-- +goose Down

ALTER TABLE servers ADD COLUMN route TEXT NOT NULL DEFAULT '';
