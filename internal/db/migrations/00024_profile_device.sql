-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Profiles become per-DEVICE. A user's devices each get their own provisioned
-- profile (own WireGuard keypair, tunnel IP, peers, and egress path), sealed to
-- the user's e2e key but specific to the device — so account sync returns the
-- *syncing device's* profile, not a generic per-user blob. device_id is nullable
-- for back-compat: existing per-user rows (device_id NULL) remain a fallback.

-- +goose Up

ALTER TABLE profiles ADD COLUMN device_id TEXT REFERENCES devices(id);
CREATE INDEX idx_profiles_user_device ON profiles(user_id, device_id, revision);

-- +goose Down

DROP INDEX idx_profiles_user_device;
ALTER TABLE profiles DROP COLUMN device_id;
