CREATE TABLE finding_feedback (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    finding_key VARCHAR(256) NOT NULL,
    label VARCHAR(32) NOT NULL CHECK (
        label IN ('FALSE_POSITIVE', 'CONFIRMED_VULNERABILITY')
    ),
    source_snippet TEXT NOT NULL,
    reason VARCHAR(2000) NOT NULL DEFAULT '',
    review_status VARCHAR(16) NOT NULL DEFAULT 'PENDING' CHECK (
        review_status IN ('PENDING', 'APPROVED', 'REJECTED')
    ),
    reviewed_by VARCHAR(150),
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    reviewed_at TIMESTAMP,
    trained_at TIMESTAMP,
    CONSTRAINT uq_finding_feedback_user_key UNIQUE (user_id, finding_key)
);

CREATE INDEX idx_finding_feedback_review
    ON finding_feedback (review_status, created_at);
