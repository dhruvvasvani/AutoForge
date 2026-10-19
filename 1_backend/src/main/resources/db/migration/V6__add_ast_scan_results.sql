ALTER TABLE scans
    ADD COLUMN combined_risk_score DOUBLE PRECISION;

ALTER TABLE vulnerabilities
    ADD COLUMN combined_risk_score DOUBLE PRECISION;
