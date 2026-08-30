-- AutoForge Phase 1 - initial schema (Week 2 deliverable)

CREATE TABLE plans (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    max_repositories INTEGER NOT NULL DEFAULT 1,
    max_scans_per_month INTEGER NOT NULL DEFAULT 10,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    full_name VARCHAR(150) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'USER',      -- USER | ADMIN | FACULTY
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',  -- ACTIVE | PAUSED
    plan_id BIGINT REFERENCES plans(id),
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE plan_requests (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    requested_plan_id BIGINT NOT NULL REFERENCES plans(id),
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING', -- PENDING | APPROVED | REJECTED
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    resolved_at TIMESTAMP
);

CREATE TABLE repositories (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    github_repo_full_name VARCHAR(255) NOT NULL,
    github_repo_id BIGINT,
    webhook_id BIGINT,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    UNIQUE(user_id, github_repo_full_name)
);

CREATE TABLE webhook_events (
    id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT REFERENCES repositories(id),
    event_type VARCHAR(50) NOT NULL,
    commit_sha VARCHAR(64),
    payload JSONB,
    received_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE scans (
    id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(id),
    webhook_event_id BIGINT REFERENCES webhook_events(id),
    commit_sha VARCHAR(64),
    status VARCHAR(20) NOT NULL DEFAULT 'QUEUED', -- QUEUED | RUNNING | COMPLETED | FAILED
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE vulnerabilities (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES scans(id),
    source_scanner VARCHAR(30) NOT NULL,        -- SEMGREP | CHECKOV
    file_path VARCHAR(500),
    line_number INTEGER,
    rule_id VARCHAR(255),
    severity VARCHAR(20),                       -- CRITICAL | HIGH | MEDIUM | LOW
    is_reachable BOOLEAN,
    priority VARCHAR(20),                       -- set by ML prioritization
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN',  -- OPEN | FIXED | IGNORED | DEAD_CODE
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE fixes (
    id BIGSERIAL PRIMARY KEY,
    vulnerability_id BIGINT NOT NULL REFERENCES vulnerabilities(id),
    suggested_patch TEXT,
    model_used VARCHAR(100) DEFAULT 'gemini-2.5-flash',
    validated BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE pull_requests (
    id BIGSERIAL PRIMARY KEY,
    fix_id BIGINT NOT NULL REFERENCES fixes(id),
    github_pr_number INTEGER,
    github_pr_url VARCHAR(500),
    branch_name VARCHAR(255),
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN', -- OPEN | MERGED | CLOSED
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE reports (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES scans(id),
    file_path VARCHAR(500),
    generated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor_user_id BIGINT REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    details TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

INSERT INTO plans (name, max_repositories, max_scans_per_month) VALUES
    ('FREE', 1, 10),
    ('PAID', 20, 500);
