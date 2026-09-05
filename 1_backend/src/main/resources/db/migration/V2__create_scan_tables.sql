CREATE TABLE IF NOT EXISTS scan_results (
    id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL,
    commit_hash VARCHAR(40) NOT NULL,
    branch VARCHAR(255),
    scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_findings INT DEFAULT 0,
    reachable_findings INT DEFAULT 0,
    unreachable_findings INT DEFAULT 0,
    p0_count INT DEFAULT 0,
    p1_count INT DEFAULT 0,
    p2_count INT DEFAULT 0,
    p3_count INT DEFAULT 0,
    raw_results JSONB,
    filtered_results JSONB,
    scored_results JSONB,
    status VARCHAR(50) DEFAULT 'PENDING',
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

CREATE INDEX idx_scan_results_repo ON scan_results(repository_id);
CREATE INDEX idx_scan_results_timestamp ON scan_results(scan_timestamp);
CREATE INDEX idx_scan_results_commit ON scan_results(commit_hash);

CREATE TABLE IF NOT EXISTS findings (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL,
    rule_id VARCHAR(255) NOT NULL,
    file_path VARCHAR(1024) NOT NULL,
    line_number INT,
    severity VARCHAR(50),
    message TEXT,
    code_snippet TEXT,
    function_name VARCHAR(255),
    reachability VARCHAR(50) DEFAULT 'REACHABLE_CODE',
    priority VARCHAR(10),
    is_actionable BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE CASCADE
);

CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_rule ON findings(rule_id);
CREATE INDEX idx_findings_file ON findings(file_path);
CREATE INDEX idx_findings_priority ON findings(priority);
CREATE INDEX idx_findings_reachability ON findings(reachability);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL,
    commit_hash VARCHAR(40) NOT NULL,
    job_status VARCHAR(50) DEFAULT 'QUEUED',
    queue_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    start_timestamp TIMESTAMP,
    end_timestamp TIMESTAMP,
    scanner_output JSONB,
    error_details TEXT,
    FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE
);

CREATE INDEX idx_scan_jobs_repo ON scan_jobs(repository_id);
CREATE INDEX idx_scan_jobs_status ON scan_jobs(job_status);

CREATE TABLE IF NOT EXISTS scan_history (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL,
    action VARCHAR(100),
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE CASCADE
);

CREATE INDEX idx_scan_history_scan ON scan_history(scan_id);

