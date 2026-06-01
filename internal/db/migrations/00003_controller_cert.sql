-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- coxswain's own controller client certificate (DESIGN §4). coxswain presents this
-- when it dials a buoy node's mTLS control port. Unlike user/node keys, this
-- private key legitimately belongs to coxswain.

-- +goose Up

CREATE TABLE controller_cert (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    cert_pem   TEXT NOT NULL,
    key_pem    TEXT NOT NULL,
    serial     TEXT NOT NULL,
    not_after  TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- +goose Down

DROP TABLE controller_cert;
