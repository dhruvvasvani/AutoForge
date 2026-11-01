ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS changed_file_paths TEXT;
