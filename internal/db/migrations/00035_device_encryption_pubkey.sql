-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Per-device profile sealing for passphrase-less join-link enrollment. A device
-- enrolled via ClaimEnrollment generates its OWN X25519 encryption keypair
-- on-device and presents the public half in the claim; coxswain stores it here
-- and seals that device's profile bundle to it, so the device decrypts with its
-- own private key — no account passphrase.
--
-- Nullable: legacy account-sync devices (enrolled before the join flow) carry no
-- per-device key; their profiles stay sealed to the user's account encryption
-- key (users.public_key), and provisioning falls back to that when this is NULL.

-- +goose Up

ALTER TABLE devices ADD COLUMN encryption_pubkey BLOB;

-- +goose Down

ALTER TABLE devices DROP COLUMN encryption_pubkey;
