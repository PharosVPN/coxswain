-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- M6: end-to-end profile encryption (DESIGN §8) and per-peer preshared keys
-- (DESIGN §4, decision 15). coxswain's profile-signing key lets devices verify a
-- bundle's origin; the preshared key hardens each AmneziaWG peer post-quantum.

-- +goose Up

-- preshared_key is the base64 256-bit AmneziaWG PSK for the peer.
ALTER TABLE peers ADD COLUMN preshared_key TEXT NOT NULL DEFAULT '';

-- profile_signing_key holds coxswain's Ed25519 profile-signing keypair (one row).
-- coxswain signs every sealed profile bundle; devices pin the public key.
CREATE TABLE profile_signing_key (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    public_key  BLOB NOT NULL,
    private_key BLOB NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- +goose Down

DROP TABLE profile_signing_key;
ALTER TABLE peers DROP COLUMN preshared_key;
