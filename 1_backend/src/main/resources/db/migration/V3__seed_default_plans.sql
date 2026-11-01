INSERT INTO plans (name, max_repositories, max_scans_per_month, created_at)
VALUES
  ('FREE', 1, 10, now()),
  ('PRO', 10, 100, now()),
  ('ENTERPRISE', 100, 1000, now())
ON CONFLICT (name) DO UPDATE SET
  max_repositories = EXCLUDED.max_repositories,
  max_scans_per_month = EXCLUDED.max_scans_per_month;