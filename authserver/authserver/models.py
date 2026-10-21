"""SQLite 表结构；凭据材料仅保存哈希，邀请码是可分发的原文。"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS invites (
    code TEXT PRIMARY KEY,
    days INTEGER NOT NULL CHECK (days > 0),
    max_uses INTEGER NOT NULL CHECK (max_uses > 0),
    used INTEGER NOT NULL DEFAULT 0 CHECK (used >= 0 AND used <= max_uses),
    note TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    invite_code TEXT NOT NULL REFERENCES invites(code),
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    expires_at TEXT NOT NULL,
    device_limit INTEGER NOT NULL CHECK (device_limit > 0),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    uuid TEXT NOT NULL UNIQUE,
    platform TEXT NOT NULL,
    name TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    refresh_token_hash TEXT UNIQUE,
    last_seen TEXT NOT NULL,
    revoked_at TEXT,
    UNIQUE (account_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    who TEXT NOT NULL,
    what TEXT NOT NULL,
    at TEXT NOT NULL,
    ip TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS node_heartbeat (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    at TEXT NOT NULL,
    ip TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS devices_account ON devices(account_id);
CREATE INDEX IF NOT EXISTS sessions_device ON sessions(device_id);
"""
