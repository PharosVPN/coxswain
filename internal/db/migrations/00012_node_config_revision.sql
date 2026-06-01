-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Per-node PushConfig revision counter. coxswain assigns a monotonically
-- increasing revision on every PushConfig to a buoy node; buoy rejects a
-- stale revision with FailedPrecondition (B2). 0 means "nothing pushed yet".

-- +goose Up

ALTER TABLE nodes ADD COLUMN config_revision INTEGER NOT NULL DEFAULT 0;

-- +goose Down

ALTER TABLE nodes DROP COLUMN config_revision;
