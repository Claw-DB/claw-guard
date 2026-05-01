-- SQLite-compatible schema for claw-guard

CREATE TABLE IF NOT EXISTS roles (
    id   TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    scopes TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    agent_id   TEXT NOT NULL,
    role_id    TEXT NOT NULL REFERENCES roles(id),
    scopes     TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS policies (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    rules       TEXT NOT NULL DEFAULT '[]',
    priority    INTEGER NOT NULL DEFAULT 0,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          TEXT PRIMARY KEY,
    session_id  TEXT,
    agent_id    TEXT,
    action      TEXT NOT NULL,
    resource    TEXT,
    resource_id TEXT,
    decision    TEXT NOT NULL,
    reason      TEXT,
    risk_score  REAL NOT NULL DEFAULT 0.0,
    metadata    TEXT,
    ts          TEXT NOT NULL
);
