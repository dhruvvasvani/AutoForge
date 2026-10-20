INSERT INTO plans (name, max_repositories, max_scans_per_month, created_at)
SELECT 'FREE', 1, 10, CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT 1 FROM plans WHERE name = 'FREE');

INSERT INTO plans (name, max_repositories, max_scans_per_month, created_at)
SELECT 'PAID', 20, 500, CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT 1 FROM plans WHERE name = 'PAID');
