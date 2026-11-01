# AutoForge Java Backend & Analyzer — Architecture & API Runbook

## Overview
AutoForge is an AI-powered DevSecOps platform with automated static analysis, reachability filtering, risk prioritization, automated fix generation, and CI/CD security gate enforcement.

---

## 1. Core Architecture
- **Language & Framework**: Java 17/21 + Spring Boot 3.3.4
- **Database**: PostgreSQL with Flyway versioned migrations (`V1` - `V5`)
- **Queue / Broker**: Redis list `autoforge:scan_jobs`
- **Security & RBAC**: Spring Security + JWT + BCrypt (`ADMIN`, `DEVELOPER`, `AUDITOR`)
- **WebSockets**: Spring WebSocket at `/api/v1/ws/scans/{job_id}`
- **Standards Export**: SARIF 2.1.0 output schema

---

## 2. API Reference Matrix

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check verifying application & database connectivity |
| `POST` | `/api/v1/projects` | Register repository (`name`, `repo_url`, `default_branch`) |
| `GET` | `/api/v1/projects` | Paginated repository list (`skip`, `limit`, `page`, `size`) |
| `GET` | `/api/v1/projects/{id}` | Retrieve individual project details |
| `POST` | `/api/v1/auth/register` | Register user account with role selection (`DEVELOPER`, `ADMIN`, `AUDITOR`) |
| `POST` | `/api/v1/auth/login` | Authenticate user; returns `access_token` and `token_type: bearer` |
| `GET` | `/api/v1/auth/me` | Fetch authenticated user profile |
| `POST` | `/api/v1/scans/trigger` | Trigger scan job (`project_id`, `commit_sha`, `branch`, `idempotency_key`) |
| `GET` | `/api/v1/scans/{jobId}` | Get scan job real-time status and timestamps |
| `GET` | `/api/v1/projects/{id}/scans` | Paginated scan history for a project |
| `POST` | `/api/v1/webhooks/github` | Ingest GitHub push/PR event with HMAC-SHA256 signature verification |
| `POST` | `/api/v1/webhooks/gitlab` | Ingest GitLab webhook with `X-Gitlab-Token` header validation |
| `GET` | `/api/v1/scans/{scanId}/findings` | Retrieve all findings detected in a scan |
| `GET` | `/api/v1/projects/{id}/findings` | Filter active project findings by severity & rule |
| `GET` | `/api/v1/findings/{id}/traces` | Retrieve ordered multi-file taint trace steps |
| `GET` | `/api/v1/scans/{scanId}/metrics` | Severity distribution counts and health score (0-100) |
| `GET` | `/api/v1/projects/{id}/metrics` | Historical repository security posture trends |
| `POST` | `/api/v1/ml/predictions` | Ingest PyTorch model probability score & feature summary |
| `POST` | `/api/v1/scans/results/ml` | Batch scan ML inference ingestion |
| `GET` | `/api/v1/findings/{id}/ml-score` | Retrieve ML confidence score for a finding |
| `POST` | `/api/v1/results/submit` | Atomic ingestion of hybrid AST + ML results |
| `PATCH` | `/api/v1/scans/{jobId}/status` | Update scan execution status (`PROCESSING`, `COMPLETED`, `FAILED`) |
| `WS` | `/api/v1/ws/scans/{jobId}` | Stream real-time progress and worker log frames |
| `POST` | `/api/v1/scans/{jobId}/logs` | Ingest worker execution logs and broadcast via WebSocket |
| `GET` | `/api/v1/scans/{scanId}/export/sarif` | Download standardized SARIF 2.1.0 report |
| `POST` | `/api/v1/policies/evaluate` | Evaluate commit against CI/CD merge gate policy |

---

## 3. Operational Runbook

### Run Tests
```bash
# Execute Java Spring Boot test suite (22 tests)
mvn clean test

# Execute Python Analyzer test suite (5 tests)
python -m unittest discover -s 3_ast_analyzer/tests
```

### Local Dev Run
```bash
mvn spring-boot:run
```

### Clean Workspace
```powershell
./scripts/cleanup_workspace.ps1
```
