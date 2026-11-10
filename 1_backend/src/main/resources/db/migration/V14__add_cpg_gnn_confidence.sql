ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS cpg_gnn_file_confidence DOUBLE PRECISION
        CHECK (
            cpg_gnn_file_confidence IS NULL
            OR (cpg_gnn_file_confidence >= 0.0 AND cpg_gnn_file_confidence <= 1.0)
        );
