CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL UNIQUE,
    workspace_id TEXT NOT NULL,
    label TEXT,
    created_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    last_used_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_api_keys_workspace
    ON api_keys(workspace_id)
    WHERE revoked = 0;

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    role TEXT NOT NULL,
    scopes TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_agent
    ON sessions(agent_id)
    WHERE revoked = 0;

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    rules TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    workspace_id TEXT NOT NULL,
    agent_id TEXT,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    resource_id TEXT,
    decision TEXT NOT NULL,
    reason TEXT,
    risk_score REAL,
    metadata TEXT,
    ts INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_workspace_ts
    ON audit_log(workspace_id, ts DESC);

CREATE INDEX IF NOT EXISTS idx_audit_log_session
    ON audit_log(session_id);

CREATE TABLE IF NOT EXISTS data_masks (
    id TEXT PRIMARY KEY,
    field_pattern TEXT NOT NULL,
    mask_type TEXT NOT NULL,
    config TEXT
);