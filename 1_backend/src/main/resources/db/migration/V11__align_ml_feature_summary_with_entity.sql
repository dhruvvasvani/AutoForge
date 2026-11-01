ALTER TABLE ml_predictions
    ALTER COLUMN feature_vector_summary TYPE TEXT
    USING feature_vector_summary::text;
