-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Record which device redeemed an enrollment ticket, so a one-time claim is
-- auditable end-to-end: used_at says WHEN, used_by_device_id says WHICH device.
-- The join-link/QR claim flow (ClaimEnrollment) stamps both atomically when it
-- marks the ticket spent.
--
-- It is deliberately NOT a foreign key: the claim redeems the ticket FIRST (the
-- one-time guard — a replayed token must update zero rows) and only then commits
-- the device row, so the id is recorded before the device exists. The column is
-- an audit breadcrumb, not a referential link; a device later deleted leaves the
-- historical claim record intact.

-- +goose Up

ALTER TABLE enrollment_tickets ADD COLUMN used_by_device_id TEXT;

-- +goose Down

ALTER TABLE enrollment_tickets DROP COLUMN used_by_device_id;
