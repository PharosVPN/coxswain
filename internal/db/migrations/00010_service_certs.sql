-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- coxswain's service certificates for the relay relay tier (M6b-2): the gRPC-leg
-- server cert (CN "coxswain-grpc") and the relay cert (one dual-EKU Fleet-CA leaf,
-- O="PharosVPN Relay"). Both are issued off the Fleet CA; coxswain holds the keys.

-- +goose Up

CREATE TABLE service_certs (
    role       TEXT PRIMARY KEY CHECK (role IN ('grpc', 'relay')),
    cert_pem   TEXT NOT NULL,
    key_pem    TEXT NOT NULL,
    serial     TEXT NOT NULL,
    not_after  TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- +goose Down

DROP TABLE service_certs;
