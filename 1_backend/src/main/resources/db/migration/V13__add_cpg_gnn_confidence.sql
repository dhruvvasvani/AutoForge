ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS cpg_gnn_confidence DOUBLE PRECISION;

ALTER TABLE ml_predictions
    ADD COLUMN IF NOT EXISTS cpg_gnn_confidence DOUBLE PRECISION;
