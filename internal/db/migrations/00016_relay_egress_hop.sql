-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Explicit egress-chain ordering (DESIGN §3, decision 19, ladder step 2). When
-- coxswain routes its control plane through several egress relays, the chain
-- order (coxswain → hop 1 → hop 2 → … → node) must be operator-controlled and
-- stable, not derived from enrollment timestamps. egress_hop is the relay's
-- 1-based position in the chain; 0 means the relay is not an egress hop (it is
-- ignored unless egress_endpoint is also set).

-- +goose Up

ALTER TABLE relays ADD COLUMN egress_hop INTEGER NOT NULL DEFAULT 0;

-- +goose Down

ALTER TABLE relays DROP COLUMN egress_hop;
