ALTER TABLE scans
    ADD COLUMN progress_stage VARCHAR(80),
    ADD COLUMN progress_message VARCHAR(500);

UPDATE scans
SET progress_stage = status
WHERE progress_stage IS NULL;
