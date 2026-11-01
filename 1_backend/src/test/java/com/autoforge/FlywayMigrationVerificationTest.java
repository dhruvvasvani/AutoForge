package com.autoforge;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationInfo;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class FlywayMigrationVerificationTest {

    @Test
    void allFlywayMigrationsHaveUniqueSequentialVersions() {
        Flyway flyway = Flyway.configure()
                .dataSource("jdbc:h2:mem:flyway_validation;DB_CLOSE_DELAY=-1;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE", "sa", "")
                .locations("classpath:db/migration")
                .baselineOnMigrate(true)
                .load();

        MigrationInfo[] migrations = flyway.info().all();
        assertTrue(migrations.length >= 13, "Expected at least 13 migration files, found: " + migrations.length);

        Set<String> seenVersions = new HashSet<>();
        for (MigrationInfo migration : migrations) {
            String version = migration.getVersion().getVersion();
            assertFalse(seenVersions.contains(version), "Duplicate migration version detected: " + version);
            seenVersions.add(version);
        }

        assertEquals(13, seenVersions.size(), "Expected exactly 13 unique sequential migration versions");
    }
}
