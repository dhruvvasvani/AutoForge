-- Week 6 deliverable: indexes to support pagination/admin listing at scale,
-- plus a uniqueness guard so the same commit can't double-enqueue a scan.

CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_plan_id ON users(plan_id);
CREATE INDEX idx_plan_requests_status ON plan_requests(status);
CREATE INDEX idx_repositories_user_id ON repositories(user_id);
CREATE INDEX idx_scans_repository_id ON scans(repository_id);
CREATE INDEX idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);

ALTER TABLE scans ADD CONSTRAINT uq_repo_commit UNIQUE (repository_id, commit_sha);
