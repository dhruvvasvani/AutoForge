CREATE TABLE scan_metrics (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scan_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    metrics_json TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX idx_scan_metrics_user_timestamp
    ON scan_metrics(user_id, scan_timestamp DESC, id DESC);
