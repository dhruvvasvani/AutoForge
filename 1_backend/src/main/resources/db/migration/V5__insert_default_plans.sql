-- V5: Insert default plans if they don't exist
-- This handles the case where V1 was skipped because of baseline-version 4

INSERT INTO plans (name, max_repositories, max_scans_per_month, created_at)
SELECT 'FREE', 1, 10, NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM plans WHERE name = 'FREE'
);

INSERT INTO plans (name, max_repositories, max_scans_per_month, created_at)
SELECT 'PAID', 20, 500, NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM plans WHERE name = 'PAID'
);
