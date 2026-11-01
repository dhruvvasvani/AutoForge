ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_reachable BOOLEAN;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS reachability_status VARCHAR(32);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS priority VARCHAR(20);

CREATE INDEX IF NOT EXISTS idx_findings_reachability ON findings(is_reachable);
