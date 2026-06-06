-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- XRay/REALITY data-plane support (DESIGN §3, §12), mirroring AmneziaWG:
--   nodes.xray_public_key — the node's REALITY server public key (base64url),
--     reported by the node's GetStatus. Empty = "not reported yet"; provisioning
--     places a REALITY client on a node only once it is set.
--   peers.flow — the VLESS flow for an XRay/REALITY peer (e.g.
--     "xtls-rprx-vision"). Empty for AmneziaWG peers (the column is unused there).

-- +goose Up

ALTER TABLE nodes ADD COLUMN xray_public_key TEXT NOT NULL DEFAULT '';
ALTER TABLE peers ADD COLUMN flow TEXT NOT NULL DEFAULT '';

-- +goose Down

ALTER TABLE peers DROP COLUMN flow;
ALTER TABLE nodes DROP COLUMN xray_public_key;
