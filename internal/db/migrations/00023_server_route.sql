-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- A server's control-plane provision route: the ordered relay hops coxswain
-- dials it through (onboard SSH, deploy SSH, and the node's gRPC control plane),
-- stored as a comma-separated list of relay ids. Empty means DIRECT — the
-- default. This makes routing a deliberate, visible per-machine choice instead
-- of the old "route through every enrolled egress relay, always" behaviour.

-- +goose Up

ALTER TABLE servers ADD COLUMN route TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE servers DROP COLUMN route;
