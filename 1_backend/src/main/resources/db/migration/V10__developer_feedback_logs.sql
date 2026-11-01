CREATE TABLE IF NOT EXISTS feedback_logs (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fix_id BIGINT REFERENCES fixes(id) ON DELETE SET NULL,
    feedback_action VARCHAR(32) NOT NULL,
    comment VARCHAR(2000),
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    CONSTRAINT chk_feedback_action CHECK (feedback_action IN ('DISMISS', 'FALSE_POSITIVE', 'ACCEPT_PATCH'))
);

CREATE INDEX IF NOT EXISTS idx_feedback_logs_finding_created
    ON feedback_logs(finding_id, created_at DESC);
