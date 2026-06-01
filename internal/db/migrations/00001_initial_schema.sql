-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- Initial coxswain state schema. See DESIGN §10 (Persistence). Every mutable row
-- carries `version` + `updated_at` for the optimistic concurrency in DESIGN §7.

-- +goose Up

-- ca holds the in-repo certificate authority (DESIGN §4): the self-signed root
-- and the Fleet/Device intermediates. The private keys never leave this table.
CREATE TABLE ca (
    role       TEXT PRIMARY KEY CHECK (role IN ('root', 'fleet', 'device')),
    cert_pem   TEXT NOT NULL,
    key_pem    TEXT NOT NULL,
    serial     TEXT NOT NULL,
    not_before TIMESTAMP NOT NULL,
    not_after  TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- nodes is the buoy fleet inventory.
CREATE TABLE nodes (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    region       TEXT NOT NULL,
    public_ip    TEXT,
    control_addr TEXT,
    cloud_id     TEXT,
    status       TEXT NOT NULL DEFAULT 'pending',
    version      INTEGER NOT NULL DEFAULT 1,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- relays is the beacon inventory (embedded + remote).
CREATE TABLE relays (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('embedded', 'remote')),
    endpoint   TEXT,
    status     TEXT NOT NULL DEFAULT 'pending',
    version    INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- users are authentication principals (DESIGN §8). coxswain holds only the public
-- key and the passphrase-wrapped private key blob — never a usable secret.
CREATE TABLE users (
    id              TEXT PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    role            TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    public_key      BLOB,
    wrapped_privkey BLOB,
    status          TEXT NOT NULL DEFAULT 'active',
    version         INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- admins records admin-scope grants layered on a user.
CREATE TABLE admins (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope      TEXT NOT NULL DEFAULT 'full',
    version    INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- devices are the per-user enrolled endpoints (caravel installs, admin browser).
CREATE TABLE devices (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    platform    TEXT,
    fingerprint TEXT,
    status      TEXT NOT NULL DEFAULT 'active',
    version     INTEGER NOT NULL DEFAULT 1,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- profiles holds E2E-encrypted profile bundles. coxswain stores only ciphertext.
CREATE TABLE profiles (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    revision   INTEGER NOT NULL DEFAULT 1,
    ciphertext BLOB NOT NULL,
    version    INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- peers binds a device to a node for a given data-plane protocol.
CREATE TABLE peers (
    id         TEXT PRIMARY KEY,
    node_id    TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    protocol   TEXT NOT NULL,
    public_key TEXT,
    allowed_ip TEXT,
    version    INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- node_certs tracks Fleet-CA leaf certs issued to buoy nodes.
CREATE TABLE node_certs (
    id         TEXT PRIMARY KEY,
    node_id    TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    serial     TEXT NOT NULL UNIQUE,
    cert_pem   TEXT NOT NULL,
    not_after  TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    version    INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- device_certs tracks Device-CA leaf certs issued to caravel installs/browsers.
CREATE TABLE device_certs (
    id         TEXT PRIMARY KEY,
    device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    serial     TEXT NOT NULL UNIQUE,
    cert_pem   TEXT NOT NULL,
    not_after  TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    version    INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- bootstrap_tokens are the one-time, short-TTL enrollment tokens (DESIGN §5).
CREATE TABLE bootstrap_tokens (
    id         TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    kind       TEXT NOT NULL CHECK (kind IN ('buoy', 'beacon')),
    node_id    TEXT REFERENCES nodes(id) ON DELETE SET NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at    TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- sessions are admin/user login sessions.
CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- audit_log is append-only.
CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    actor      TEXT,
    action     TEXT NOT NULL,
    target     TEXT,
    detail     TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- metrics_samples is append-only time-series, pruned by retention policy.
CREATE TABLE metrics_samples (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id    TEXT REFERENCES nodes(id) ON DELETE CASCADE,
    metric     TEXT NOT NULL,
    value      REAL NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_devices_user ON devices(user_id);
CREATE INDEX idx_profiles_user ON profiles(user_id);
CREATE INDEX idx_peers_node ON peers(node_id);
CREATE INDEX idx_peers_device ON peers(device_id);
CREATE INDEX idx_audit_log_created ON audit_log(created_at);
CREATE INDEX idx_metrics_samples_created ON metrics_samples(created_at);

-- +goose Down

DROP TABLE metrics_samples;
DROP TABLE audit_log;
DROP TABLE sessions;
DROP TABLE bootstrap_tokens;
DROP TABLE device_certs;
DROP TABLE node_certs;
DROP TABLE peers;
DROP TABLE profiles;
DROP TABLE devices;
DROP TABLE admins;
DROP TABLE users;
DROP TABLE relays;
DROP TABLE nodes;
DROP TABLE ca;
