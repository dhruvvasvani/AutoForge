CREATE TABLE IF NOT EXISTS projects (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    repo_url VARCHAR(512) NOT NULL,
    default_branch VARCHAR(64) NOT NULL DEFAULT 'main',
    user_id BIGINT REFERENCES users(id),
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

ALTER TABLE scans ADD COLUMN IF NOT EXISTS branch VARCHAR(64) DEFAULT 'main';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS error_message VARCHAR(1024);
ALTER TABLE scans ADD COLUMN IF NOT EXISTS progress INTEGER DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS idempotency_key VARCHAR(128);
ALTER TABLE scans ADD COLUMN IF NOT EXISTS project_id BIGINT REFERENCES projects(id);

CREATE TABLE IF NOT EXISTS findings (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id VARCHAR(128) NOT NULL,
    title VARCHAR(255) NOT NULL,
    file_path VARCHAR(512) NOT NULL,
    line_number INTEGER NOT NULL,
    severity VARCHAR(20) NOT NULL,
    code_snippet TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS call_traces (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    step_number INTEGER NOT NULL,
    file_path VARCHAR(512) NOT NULL,
    line_number INTEGER NOT NULL,
    symbol_name VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS ml_predictions (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    ml_confidence_score DOUBLE PRECISION NOT NULL,
    model_version VARCHAR(64) DEFAULT 'v1.0.0',
    feature_vector_summary JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policies (
    id BIGSERIAL PRIMARY KEY,
    project_id BIGINT REFERENCES projects(id),
    max_critical INTEGER NOT NULL DEFAULT 0,
    max_high INTEGER NOT NULL DEFAULT 2,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now()
);
