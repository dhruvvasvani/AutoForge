# AutoForge Operational Runbooks & Production SRE Guide

This document contains standard operating procedures (SOPs) and runbooks for AutoForge backend engineering, deployments, operations, and incident response in compliance with the Master Scope Checklist.

---

## 1. Local & Production Setup
### Prerequisites
- JDK 17 or 21 (Eclipse Temurin recommended)
- Maven 3.9+ (or included `./mvnw`)
- PostgreSQL 15+
- Redis 7+
- Docker & Docker Compose

### Quickstart with Docker Compose
```bash
docker-compose up -d postgres redis neo4j
./mvnw spring-boot:run
```

---

## 2. Database Migrations & Rollback Procedures
AutoForge uses Flyway as the single source of truth for all schema state.
- Location: `src/main/resources/db/migration`
- Migrations: `V1` through `V8`

### Running Migrations
Migrations run automatically upon application startup. To manually validate:
```bash
./mvnw flyway:info
./mvnw flyway:migrate
```

### Rollback Strategy
1. **Flyway forward-fix**: Preferred production path is creating a compensating migration (`V7__rollback_...sql`).
2. **Emergency manual rollback**:
   ```sql
   -- Example: Revert V6
   ALTER TABLE fixes DROP COLUMN IF EXISTS status;
   ALTER TABLE fixes DROP COLUMN IF EXISTS file_path;
   ALTER TABLE fixes DROP COLUMN IF EXISTS finding_id;
   DELETE FROM flyway_schema_history WHERE version = '6';
   ```

---

## 3. Backup and Disaster Recovery (PostgreSQL & Redis)
### PostgreSQL Snapshot Backup
```bash
# Automated cron backup
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME -Fc -f /backups/autoforge_$(date +%Y%m%d_%H%M%S).dump

# PostgreSQL Restore
pg_restore -h $DB_HOST -U $DB_USER -d $DB_NAME -c /backups/autoforge_20261020_230000.dump
```

### Redis State Snapshot
```bash
# Force background save (RDB)
redis-cli -h $REDIS_HOST -p $REDIS_PORT BGSAVE
# Copy dump.rdb from /data to cold storage volume
```

---

## 4. Failed-Job Replay & Dead-Letter Queue (DLQ)
When scan execution encounters fatal unrecoverable errors:
1. Jobs exceeding retry limit (3 retries) are moved from `autoforge:scan_jobs` to DLQ list `autoforge:scan_jobs:dlq`.
2. To inspect failed jobs:
   ```bash
   redis-cli LRANGE autoforge:scan_jobs:dlq 0 -1
   ```
3. To replay failed jobs back to the active queue:
   ```bash
   # Re-enqueue all DLQ entries
   redis-cli RPOPLPUSH autoforge:scan_jobs:dlq autoforge:scan_jobs
   ```

---

## 5. Model Upgrades & Golden-Set Parity
1. AutoForge runs Java-native model evaluation with golden-set tensors.
2. When deploying a new model version (`v2.2-java-onnx`):
   - Update model version tag in `MLService.java`.
   - Run golden-set test fixtures to confirm 100% classification parity against benchmark samples.
   - Run warm-up verification via `@PostConstruct warmUp()` during boot.

---

## 6. Key Rotation Procedures
### JWT Secret Key Rotation
1. Update `JWT_SECRET` in Kubernetes Secret `autoforge-secrets`.
2. Perform rolling deployment: `kubectl rollout restart deployment/autoforge-backend -n autoforge`.
3. Existing active sessions will seamlessly refresh on subsequent login.

### GitHub / GitLab Webhook Secret Rotation
1. Generate high-entropy 256-bit secret: `openssl rand -hex 32`.
2. Update repository webhook secret in GitHub/GitLab settings.
3. Update `GITHUB_WEBHOOK_SECRET` in application configuration.

### Internal Service API Key Rotation
1. Set `INTERNAL_API_KEY` to the new token string.
2. Update pipeline worker deployment ConfigMap/Secret.

---

## 7. Incident Response & Troubleshooting Playbooks
| Symptom | Probable Cause | Action |
|---|---|---|
| Webhook returns `401 Unauthorized` | HMAC signature mismatch or secret drift | Check `X-Hub-Signature-256` calculation against raw body bytes. Verify `GITHUB_WEBHOOK_SECRET`. |
| Queue depth increasing | Workers offline or Redis disconnected | Check worker logs: `kubectl logs -l app.kubernetes.io/component=worker -n autoforge`. Verify Redis memory limits. |
| Scan stuck in `QUEUED` | Fallback queue routing or worker restart | Verify `ScanJobRedisWorker` polling. Check DB row status in `scans` table. |
| 500 on Result Submission | Missing scan foreign key | Confirm scan job exists in database before posting to `/api/v1/results/submit`. |
