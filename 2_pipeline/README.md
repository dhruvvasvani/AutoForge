# Pipeline Module — Birendra Nagar

**Role:** GitHub & Scan Pipeline Engineer
**Scope:** GitHub Webhook receiver + signature verification, Semgrep/Checkov execution wrapper, Redis job queue

---

## Status: Demo 1 Complete ✅

Full pipeline tested end-to-end: webhook received → signature verified → payload parsed → scan job pushed to Redis queue.

---

## Weekly Progress

### Wk1 — Setup & Research
- Studied Semgrep CLI (`semgrep --config auto`), tested on sample code, reviewed JSON output structure
- Studied Checkov CLI (`checkov -d .`), tested locally, reviewed JSON output structure
- Studied GitHub webhook push event payload and `X-Hub-Signature-256` signature verification mechanism
- Created `2_pipeline/` folder structure (`webhook/`, `scanners/`, `queue/`)

### Wk2 — Webhook Receiver + Signature Verification
- Built `POST /api/webhooks/github` endpoint (Spring Boot)
- Implemented HMAC-SHA256 signature verification against GitHub's `X-Hub-Signature-256` header
- Rejects invalid signatures with 401, accepts valid ones

### Wk3 — Scanner Wrapper Script
- Built `scan_wrapper.py`: runs Semgrep + Checkov on a repo path
- Normalizes both tools' output into a common format: `{source, rule_id, file, line, severity, message}`
- Tested successfully — combined output written to `combined_scan_results.json`

### Wk4 — Redis Job Queue
- Set up Redis via Docker (`docker run -d --name redis -p 6379:6379 redis`)
- Built and tested Python producer script (`redis_producer.py`) — job push/read confirmed working
- Built Java `RedisQueueService` using Jedis client for backend integration

### Wk5 — End-to-End Integration Test
- Built standalone Spring Boot test project (`pipeline-test/`) to validate integration ahead of main backend readiness
- Wired webhook controller → payload parsing → `RedisQueueService.pushScanJob()`
- Simulated a GitHub push using `simulate_webhook.py` (generates valid HMAC signature + fake payload)
- **Confirmed working:** webhook hit → signature verified → payload parsed → job pushed to Redis → verified via `redis-cli lrange scan_jobs 0 -1`

---

## Folder Structure

```
2_pipeline/
├── webhook/
│   ├── GithubWebhookController.java   # webhook endpoint + signature verification
│   └── simulate_webhook.py            # test script to simulate GitHub push locally
├── scanners/
│   ├── scan_wrapper.py                # Semgrep + Checkov wrapper, normalized output
│   ├── sample_semgrep_out.json        # sample Semgrep output (reference)
│   └── sample_checkov_out.json        # sample Checkov output (reference)
├── queue/
│   ├── RedisQueueService.java         # Java Redis producer (Jedis)
│   └── redis_producer.py              # Python test producer (reference)
├── pipeline-test/                     # standalone Spring Boot project for isolated testing
└── README.md
```

---

## How to Run / Test Locally

1. Start Redis: `docker start redis` (or `docker run -d --name redis -p 6379:6379 redis` if not created yet)
2. Start the test backend:
   ```
   cd 2_pipeline/pipeline-test
   .\mvnw spring-boot:run
   ```
3. In a separate terminal, simulate a webhook push:
   ```
   python 2_pipeline/webhook/simulate_webhook.py
   ```
4. Expected: `Status: 200`, response includes a `Scan ID`
5. Verify job landed in Redis:
   ```
   docker exec -it redis redis-cli lrange scan_jobs 0 -1
   ```

---

## Dependencies Used

- Java: Spring Boot 4.1.1, Jedis 5.1.0, org.json 20240303
- Python: `semgrep`, `checkov`, `redis`, `requests`

---

## Next Steps (Post Demo 1 / Phase 2)

- Merge webhook + queue code into main `1_backend` Spring Boot project once ready
- Add Scan entity creation in DB (Wk3 backend task, pending Dhruv's entity schema)
- Replace standalone `pipeline-test` project with integration into main backend
- Add background worker to consume jobs from Redis queue and trigger actual Semgrep/Checkov scans
- Test with real GitHub webhook (via ngrok) instead of simulated payload

---

## Team

Dhruv Vasvani · Birendra Nagar · Abhishek Vijayvargiya · Kartik Sharma
Government Engineering College, Ajmer — CSE/IT, 7th Semester, Project-I