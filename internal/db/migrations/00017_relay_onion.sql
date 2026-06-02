-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Control-plane onion routing (DESIGN §3, decision 20). An egress relay can also
-- be an onion hop: it runs `relay onion` and publishes an X25519 onion key.
-- onion_endpoint is the relay's onion listener address coxswain/relays dial;
-- onion_pubkey is its base64 X25519 onion public key, which coxswain seals
-- circuit layers to. The onion chain reuses the egress chain's egress_hop order.
-- Both empty means the relay carries no onion hop.

-- +goose Up

ALTER TABLE relays ADD COLUMN onion_endpoint TEXT NOT NULL DEFAULT '';
ALTER TABLE relays ADD COLUMN onion_pubkey TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE relays DROP COLUMN onion_endpoint;
ALTER TABLE relays DROP COLUMN onion_pubkey;
