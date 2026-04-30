CREATE INDEX IF NOT EXISTS idx_policies_workspace ON policies(workspace_id);
CREATE INDEX IF NOT EXISTS idx_policies_active ON policies(workspace_id, is_active);
CREATE INDEX IF NOT EXISTS idx_audit_log_workspace ON audit_log(workspace_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(workspace_id, timestamp DESC);
