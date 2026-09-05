-- V4: Fix repositories table schema
-- The github_repo_full_name column may already exist (added by V1 or Hibernate ddl-auto).
-- We need to ensure it exists and has a default so we can set NOT NULL safely.

-- Step 1: Add column as nullable if it doesn't already exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'repositories'
          AND column_name = 'github_repo_full_name'
    ) THEN
        ALTER TABLE repositories ADD COLUMN github_repo_full_name VARCHAR(255);
    END IF;
END
$$;

-- Step 2: Fill any NULL values with a placeholder so we can add NOT NULL
UPDATE repositories
SET github_repo_full_name = 'unknown/unknown'
WHERE github_repo_full_name IS NULL;

-- Step 3: Add NOT NULL constraint if not already present
DO $$
BEGIN
    -- Check if the column is already NOT NULL
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'repositories'
          AND column_name = 'github_repo_full_name'
          AND is_nullable = 'YES'
    ) THEN
        ALTER TABLE repositories ALTER COLUMN github_repo_full_name SET NOT NULL;
    END IF;
END
$$;
