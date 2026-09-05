-- V3: Week 6 indexes and constraints
-- Safe version: all statements wrapped in IF NOT EXISTS checks
-- to handle schemas created by Hibernate ddl-auto before Flyway was enabled.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename='users' AND indexname='idx_users_status') THEN
        CREATE INDEX idx_users_status ON users(status);
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename='users' AND indexname='idx_users_plan_id') THEN
        CREATE INDEX idx_users_plan_id ON users(plan_id);
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename='plan_requests' AND indexname='idx_plan_requests_status') THEN
        CREATE INDEX idx_plan_requests_status ON plan_requests(status);
    END IF;
END $$;

-- repositories.user_id index - only create if column exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'repositories' AND column_name = 'user_id'
    ) AND NOT EXISTS (
        SELECT 1 FROM pg_indexes WHERE tablename='repositories' AND indexname='idx_repositories_user_id'
    ) THEN
        EXECUTE 'CREATE INDEX idx_repositories_user_id ON repositories(user_id)';
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename='scans' AND indexname='idx_scans_repository_id') THEN
        -- Only create if the scans table and repository_id column exist
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'scans' AND column_name = 'repository_id'
        ) THEN
            EXECUTE 'CREATE INDEX idx_scans_repository_id ON scans(repository_id)';
        END IF;
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename='vulnerabilities' AND indexname='idx_vulnerabilities_scan_id') THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'vulnerabilities' AND column_name = 'scan_id'
        ) THEN
            EXECUTE 'CREATE INDEX idx_vulnerabilities_scan_id ON vulnerabilities(scan_id)';
        END IF;
    END IF;
END $$;

-- Add unique constraint on scans(repository_id, commit_sha) if not already present
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE table_name = 'scans'
          AND constraint_name = 'uq_repo_commit'
          AND constraint_type = 'UNIQUE'
    ) THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'scans' AND column_name = 'repository_id'
        ) AND EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'scans' AND column_name = 'commit_sha'
        ) THEN
            EXECUTE 'ALTER TABLE scans ADD CONSTRAINT uq_repo_commit UNIQUE (repository_id, commit_sha)';
        END IF;
    END IF;
END $$;
