# Pipeline Module — Birendra Nagar

**Role:** GitHub & Scan Pipeline Engineer
**Scope:** Semgrep/Checkov execution, Redis job queue consumer (worker), scan result hand-off

> **Webhook owner:** the real GitHub webhook receiver (HMAC signature check, Scan row creation) lives in the backend (`1_backend`, `GithubWebhookController`). This module does not run its own webhook server.

---

## Status

| Area | State |
|---|---|
| Semgrep + Checkov wrapper (`scan_wrapper.py`) | Done, tested |
| Redis queue producer (`redis_producer.py`) | Done, tested |
| Worker: job -> shallow fetch of exact commit -> Semgrep -> Checkov -> merge | Done, tested on a real repo |
| Worker: AST `/analyze` + `/score` client with fallback scoring | Written, **untested against Dhruv's service** (service not built yet) |
| Worker: AI fix (`/api/fix`) for P0/P1 findings | Written, untested with live Gemini |
| Worker: POST results to backend `/api/internal/scans/{id}/results` | Written, **needs Abhishek's Redis push to get a real scan id** |
| Worker: duplicate-job guard, failure result, clone cleanup, stage events | Done |
| Backend pushes a real job to Redis on webhook | **Pending (Abhishek)** |
| Job schema confirmed in writing with backend | **Pending** |

---

## Flow

```
GitHub push -> Backend webhook (verify signature, save Scan row)
            -> Redis list  scan_jobs
            -> worker.py:  fetch exact commit -> Semgrep -> Checkov -> merge
                           -> AST service /analyze + /score  (fallback: severity-only)
                           -> ai-fix-service /api/fix for P0/P1 (max 3 per scan)
                           -> POST backend /api/internal/scans/{id}/results
            -> Redis list  scan_results   (always)
            -> Redis channel scan_events  (stage events for live logs)
```

Every external service is optional. If AST, ai-fix or the backend is down, the worker still finishes and reports
it in the result (`ast_status`, `backend_posted`, `fixes_generated`).

---

## Weekly Progress

### Wk1 — Setup & Research
- Studied Semgrep (`semgrep --config auto`) and Checkov (`checkov -d .`) CLI output formats
- Studied GitHub push payload and `X-Hub-Signature-256` HMAC-SHA256 verification
- Created `2_pipeline/` structure (`webhook/`, `scanners/`, `queue/`)

### Wk2 — Webhook Receiver + Signature Verification
- Built and tested a webhook endpoint with HMAC-SHA256 verification in a standalone Spring Boot app (Demo 1)
- Backend now owns the real receiver, so the standalone copy was **removed in Week 7**

### Wk3 — Scanner Wrapper
- `scan_wrapper.py`: runs Semgrep + Checkov, normalizes output to `{source, rule_id, file, line, severity, message}`
- Windows fixes: UTF-8 env for Semgrep, `shell=True` for CLI lookup

### Wk4 — Redis Job Queue
- Redis via Docker, Python producer tested (push / peek)

### Wk5 — End-to-End (simulated)
- Demo 1: simulated push → signature verified → job in Redis, using a standalone test app (since removed)

### Wk7 - Fix the Broken Pipe
- `redis_producer.py`: new job schema (`repoFullName`, `commitSha`, `scan_id`, `repo_url`)
- `worker.py`: real git fetch of the exact commit into a temp folder (deleted after each job), `lpop` polling
  instead of `blpop`, Checkov via `python -m checkov.main --skip-download`, both old and new job field names accepted
- Removed dead webhook code: `GithubWebhookController.java` and `pipeline-test/`

### Wk8-9 (own side) - Worker integration
- AST client for Dhruv's documented `/analyze` + `/score` contract; local P0-P3 scoring if `/score` is unusable,
  severity-only priority if the service is down
- AI fix trigger for P0/P1 findings, results attached to the finding as `ai_fix`
- Results POSTed to the backend, stage events published to Redis (`scan_events`)
- Hardening: duplicate `scan_id` ignored, FAILED result pushed on any error, commit sha / https URL validated,
  shallow fetch with full-clone fallback, 10 min scanner timeout

---

## Folder Structure

```
2_pipeline/
├── webhook/
│   └── simulate_webhook.py      # sends a signed fake push to the backend webhook (needs update, see Open items)
├── scanners/
│   ├── scan_wrapper.py          # standalone Semgrep + Checkov wrapper, normalized output
│   ├── sample_semgrep_out.json  # sample Semgrep output (reference)
│   └── sample_checkov_out.json  # sample Checkov output (reference)
├── queue/
│   ├── redis_producer.py        # pushes a scan job to Redis (test/reference)
│   └── worker.py                # Redis consumer: clone, scan, push result
└── README.md
```

---

## How to Run / Test Locally

Needs: Docker, Python 3.11, `pip install redis requests semgrep checkov`.

1. `docker start redis` (first time: `docker run -d --name redis -p 6379:6379 redis`)
2. Terminal 1: `python 2_pipeline\queue\worker.py`
3. Terminal 2 (commit must exist on GitHub):
   ```
   $sha = git rev-parse origin/main
   $env:PYTHONPATH = "2_pipeline\queue"
   python -c "from redis_producer import push_scan_job; push_scan_job('dhruvvasvani/AutoForge', '$sha', 'https://github.com/dhruvvasvani/AutoForge.git')"
   ```
4. Result: `docker exec -it redis redis-cli lrange scan_results 0 -1` -> `"status":"COMPLETED"`
5. Live events: `docker exec -it redis redis-cli subscribe scan_events` (run before step 3)

Without AST / ai-fix / backend running, expect `"ast_status":"FALLBACK_SEVERITY_ONLY"` and `"backend_posted":false`. That is normal.

### Configuration (environment variables, all optional)

| Variable | Default |
|---|---|
| `AUTOFORGE_REDIS_HOST` / `AUTOFORGE_REDIS_PORT` | `localhost` / `6379` |
| `AUTOFORGE_AST_SERVICE_URL` | `http://localhost:8001` (empty = disabled) |
| `AUTOFORGE_BACKEND_URL` | `http://localhost:8080` |
| `AUTOFORGE_INTERNAL_SECRET` | empty (sent as `X-Internal-Secret` when set) |
| `AUTOFORGE_AI_FIX_URL` / `AUTOFORGE_AI_FIX_ENABLED` | `http://localhost:5050` / `true` |
| `AUTOFORGE_MAX_FIXES` | `3` fixes per scan |
| `AUTOFORGE_SCAN_TIMEOUT` / `AUTOFORGE_CLONE_TIMEOUT` | `600` / `300` seconds |

---

## Job Format

Pushed to Redis list `scan_jobs`:
```json
{ "repoFullName": "owner/repo", "commitSha": "<full sha>", "scan_id": 12, "repo_url": "https://github.com/owner/repo.git" }
```
`scan_id` must be the backend Scan row id (number) for the backend POST to happen; UUIDs are fine for local tests.

Result pushed to `scan_results`:
```json
{
  "job_id": 12, "repository_id": "owner/repo", "commit_hash": "<sha>", "status": "COMPLETED",
  "ast_status": "OK | OK_LOCAL_SCORING | FALLBACK_SEVERITY_ONLY",
  "raw_findings": 6, "actionable_findings": 4, "noise_removed": 2,
  "priority_summary": {"P0": 1, "P1": 2, "P3": 1},
  "fixes_generated": 2, "backend_posted": true,
  "results": { "actionable_findings": [], "filtered_noise": [] }
}
```
On error: `{"job_id", "status": "FAILED", "error": "..."}`.

Stage events on channel `scan_events`: `JOB_RECEIVED, REPO_CLONED, SEMGREP_DONE, CHECKOV_DONE, AST_DONE, FIX_GENERATED, RESULTS_POSTED, COMPLETED, FAILED, DUPLICATE_IGNORED`.
The event format is my own proposal; the WebSocket schema is not agreed with the backend yet.

---

## Open items (blocked on others)

1. **Abhishek:** push the job to Redis in `createScanJobFromPush()` and confirm the job schema in writing.
2. **Abhishek:** backend result endpoint currently reads only `repoFullName, commitSha, semgrep[], checkov[]`; extra fields
   (`reachability`, `priority`, `ai_fix`, `tagged_findings`) are sent but ignored until the payload is extended. Auth on `/api/internal/**` is not enforced yet.
3. **Dhruv:** AST HTTP service (`/analyze`, `/score`) - worker is ready, fallback used until then.
4. **Backend/frontend:** subscribe to or relay `scan_events` for live logs (schema to be agreed).
5. **Joint end-to-end test** (signed webhook -> backend -> Redis -> worker -> backend) once 1 and 3 are done.

---

## Team

Dhruv Vasvani · Birendra Nagar · Abhishek Vijayvargiya · Kartik Sharma
Government Engineering College, Ajmer — CSE/IT, 7th Semester, Project-I