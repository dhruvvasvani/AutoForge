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
| Worker (`worker.py`): consume job → git clone + checkout commit → Semgrep → Checkov → merge → push result | Done, tested on a real repo |
| Backend pushes a real job to Redis on webhook | **Pending (Abhishek)** |
| AST step inside worker | **Not working yet** — needs `tree-sitter-python` and Dhruv's HTTP service (Week 8) |
| Job schema confirmed in writing with backend | **Pending** (see "Open items") |

---

## Flow

```
GitHub push → Backend webhook (verify signature, save Scan row)
            → Redis list  scan_jobs
            → worker.py:  git clone <repo_url> → git checkout <commit>
                          → Semgrep → Checkov → merge findings
                          → AST analysis (pending)
            → Redis list  scan_results  (later: POST to backend /api/internal/scans/{id}/results)
```

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

### Wk7 — Fix the Broken Pipe (in progress)
- `redis_producer.py`: new job schema (`repoFullName`, `commitSha`, `scan_id`, `repo_url`)
- `worker.py`:
  - real `git clone` + `git checkout <commit>` into a temp folder, deleted after each job
  - accepts both new and old job field names until the schema is confirmed
  - Semgrep run with `--config auto`; Checkov run via `python -m checkov.main -o json --skip-download`
  - `lpop` polling instead of `blpop` (fixes `Timeout reading from socket` on Docker/Windows)
- Removed dead webhook code: `2_pipeline/webhook/GithubWebhookController.java` and `2_pipeline/pipeline-test/`

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

Needs: Docker, Python 3.11, `pip install redis semgrep checkov`.

1. Start Redis:
   ```
   docker start redis
   ```
   (first time: `docker run -d --name redis -p 6379:6379 redis`)
2. Start the worker (terminal 1):
   ```
   python 2_pipeline\queue\worker.py
   ```
3. Push a job (terminal 2). The commit must already exist on GitHub, because the worker clones from GitHub:
   ```
   $sha = git rev-parse origin/main
   $env:PYTHONPATH = "2_pipeline\queue"
   python -c "from redis_producer import push_scan_job; push_scan_job('dhruvvasvani/AutoForge', '$sha', 'https://github.com/dhruvvasvani/AutoForge.git')"
   ```
4. Worker log shows: clone → checkout → Semgrep → Checkov → merge → result pushed.
5. Check the result:
   ```
   docker exec -it redis redis-cli lrange scan_results 0 -1
   ```
   Expect `"status":"COMPLETED"`.

---

## Job Format

Pushed to Redis list `scan_jobs` (current producer):
```json
{
  "repoFullName": "owner/repo",
  "commitSha": "<full commit hash>",
  "scan_id": "<uuid>",
  "repo_url": "https://github.com/owner/repo.git"
}
```
Result pushed to Redis list `scan_results`:
```json
{
  "job_id": "<scan_id>",
  "repository_id": "<repo>",
  "commit_hash": "<sha>",
  "status": "COMPLETED",
  "raw_findings": 6,
  "actionable_findings": 0,
  "noise_removed": 6,
  "results": { "...AST output..." }
}
```

---

## Open items

1. **Job schema must be confirmed in writing with Abhishek.** The Week 7 plan says `{repository_id, commit_sha, scan_id, repo_url}`. The backend code works with `repoFullName` + `commitSha`. Producer sends the second form; worker accepts both. Pick one and update the producer.
2. **Backend must push the job to Redis** inside `createScanJobFromPush()` (Abhishek). Today it only saves a Scan row.
3. **AST step fails** (`No module named 'tree_sitter_python'`, and it receives a folder, not a file). Replace with Dhruv's `/analyze` + `/score` HTTP service (Week 8).
4. **`simulate_webhook.py` is out of date** for the real backend webhook: it needs the `X-GitHub-Event: push` header and the commit in the `after` field.
5. **Results go to Redis only.** Posting them to `/api/internal/scans/{id}/results` comes with the Week 9 payload change.

---

## Team

Dhruv Vasvani · Birendra Nagar · Abhishek Vijayvargiya · Kartik Sharma
Government Engineering College, Ajmer — CSE/IT, 7th Semester, Project-I