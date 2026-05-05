CREATE INDEX IF NOT EXISTS idx_policies_priority_enabled
    ON policies(priority DESC, enabled, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_policies_enabled_name
    ON policies(enabled, name);