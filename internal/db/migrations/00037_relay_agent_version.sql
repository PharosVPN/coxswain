-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Relays reach version parity with nodes: record the agent build last deployed
-- to each relay (relays.agent_version), so the dashboard can show the deployed
-- version per component and offer Update only when a newer binary is available.
-- Nodes already carry nodes.agent_version; this adds the matching column to
-- relays. Empty string = unknown (legacy rows / deploy-by-URL with no readback).

-- +goose Up

ALTER TABLE relays ADD COLUMN agent_version TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE relays DROP COLUMN agent_version;
