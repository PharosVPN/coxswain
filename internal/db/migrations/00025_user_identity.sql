-- SPDX-License-Identifier: Apache-2.0
-- Copyright (C) 2026 The PharosVPN Authors
--
-- User identity model: a user is a uuid + name, with optional email and phone.
-- email was NOT NULL UNIQUE; making it optional (and adding phone) needs a table
-- rebuild (SQLite can't drop a column constraint in place). Other tables
-- reference users(id), so we rebuild with foreign_keys off — hence NO
-- TRANSACTION (PRAGMA foreign_keys is a no-op inside a transaction). email/phone
-- stay UNIQUE but nullable (SQLite treats NULLs as distinct, so many users may
-- have neither).

-- +goose NO TRANSACTION
-- +goose Up
PRAGMA foreign_keys=OFF;

CREATE TABLE users_new (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL DEFAULT '',
    email           TEXT UNIQUE,
    phone           TEXT UNIQUE,
    role            TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    public_key      BLOB,
    wrapped_privkey BLOB,
    status          TEXT NOT NULL DEFAULT 'active',
    password_hash   TEXT NOT NULL DEFAULT '',
    version         INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users_new (id, name, email, phone, role, public_key, wrapped_privkey, status, password_hash, version, created_at, updated_at)
    SELECT id, '', email, NULL, role, public_key, wrapped_privkey, status, password_hash, version, created_at, updated_at FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

PRAGMA foreign_key_check;
PRAGMA foreign_keys=ON;

-- +goose Down
PRAGMA foreign_keys=OFF;

CREATE TABLE users_old (
    id              TEXT PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    role            TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    public_key      BLOB,
    wrapped_privkey BLOB,
    status          TEXT NOT NULL DEFAULT 'active',
    version         INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    password_hash   TEXT NOT NULL DEFAULT ''
);

INSERT INTO users_old (id, email, role, public_key, wrapped_privkey, status, version, created_at, updated_at, password_hash)
    SELECT id, COALESCE(NULLIF(email, ''), 'unknown-' || id), role, public_key, wrapped_privkey, status, version, created_at, updated_at, password_hash FROM users;

DROP TABLE users;
ALTER TABLE users_old RENAME TO users;

PRAGMA foreign_keys=ON;
