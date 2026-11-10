ALTER TABLE scans
    ADD COLUMN progress_stage VARCHAR(64),
    ADD COLUMN progress_message TEXT;
