`# 1_backend — Spring Boot Core

## Week-by-week status

| Week | Deliverable | File(s) |
|---|---|---|
| 1-3 | Spring Boot scaffolding, JPA persistence, health/projects/scans APIs, JWT auth, DTOs, exception handling | `entity/`, `repository/`, `controller/`, `security/`, `dto/` |
| 4-5 | ZIP/local source ingestion and asynchronous scanner process execution | `controller/ScanSourceController.java`, `service/ScanSourceStorageService.java`, `service/ScanProcessWorker.java` |
| 6 | Parse scored scanner results and persist findings, traces, ML confidence, reachability, and metrics before marking scans complete | `dto/ScoredFindingDto.java`, `service/ScanService.java`, migration `V9` |
| 7 | OpenAI-compatible configurable LLM remediation for findings confirmed reachable by the scanner | `service/LlmRemediationClient.java`, `service/RemediationService.java` |
| 8 | Public registration assigns least-privilege DEVELOPER role; client-supplied roles are ignored | `service/AuthService.java` |
| 9 | Scheduled Redis/in-memory queue worker clones a GitHub repository and hands it to the scanner | `service/ScanQueueScheduler.java`, `service/ScanJobRedisWorker.java`, `service/ScanProcessWorker.java` |
| 10 | Saved project quality-gate thresholds and authenticated downloadable PDF audit reports | `service/PolicyEngine.java`, `service/PdfReportService.java`, `controller/PdfReportController.java` |
| 11 | Redis jobs move atomically to a processing list, are acknowledged after durable scan handoff, and are requeued after backend restart; in-memory fallback remains non-durable | `service/QueueService.java`, `service/ScanJobRedisWorker.java` |
| 12 | Explicit-origin CORS allowlist and global JWT bearer scheme in OpenAPI/Swagger | `config/WebCorsConfiguration.java`, `config/OpenApiConfiguration.java`, `config/SecurityConfig.java` |
| 13 | Authenticated, owner-scoped developer feedback is persisted for dismissals, false positives, and accepted fixes | `controller/FeedbackController.java`, `service/FeedbackService.java`, migration `V10` |
| 14 | An approved patch can be applied to its target file, pushed to a security branch, and opened as a real GitHub PR | `service/GitHubPatchPublisher.java`, `service/GitHubPullRequestClient.java` |
| 15 | PostgreSQL is the non-local datasource, with Flyway schema migrations and Hibernate schema validation; local development retains H2 | `application.yml`, `db/migration/` |
| 16 | Actuator health is public while info/metrics require authentication; application health reports database outages as HTTP 503 | `application.yml`, `config/SecurityConfig.java`, `controller/HealthController.java` |

## Run

```bash
.\mvnw.cmd spring-boot:run
```

The default `localtest` profile uses an in-memory H2 database. The local H2
console is available at `http://localhost:8080/h2-console`.

For PostgreSQL, disable the default local profile by activating a non-local
profile (for example `SPRING_PROFILES_ACTIVE=postgres`) and configure
`DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, and `DB_PASSWORD`. Flyway applies
the versioned schema and Hibernate validates it at startup. Do not expose the
H2 console outside local development.

### Upload and run a local scan (Weeks 4–5)

Authenticate first and pass the returned bearer token to these protected APIs.
ZIP uploads are extracted under `uploads/` by default; absolute paths and ZIP
path traversal are rejected. Set `AUTOFORGE_UPLOAD_DIR` to change the storage
root. Uploads are limited to 20 MiB compressed and 512 MiB extracted by default.

```powershell
curl.exe -X POST http://localhost:8080/api/v1/scans/upload `
  -H "Authorization: Bearer <token>" `
  -F "projectName=demo" `
  -F "file=@C:\path\to\source.zip"

curl.exe -X POST http://localhost:8080/api/v1/scans/run `
  -H "Authorization: Bearer <token>" `
  -H "Content-Type: application/json" `
  -d '{"scan_id":1}'
```

`POST /api/v1/scans/import-path` accepts `project_name`, `source_path`,
`branch`, and optional `commit_sha`. Imported paths must resolve inside
`AUTOFORGE_UPLOAD_DIR`; this deliberately prevents authenticated users from
asking the server to scan arbitrary host directories. Place approved source
directories under that root before importing them.

The scanner launcher calls the configured Python executable without a shell:

```text
<PYTHON_EXECUTABLE> <SCANNER_WRAPPER_PATH> --source-dir <source> --output <scored_results.json>
```

The wrapper path defaults to `../2_pipeline/scanners/scan_wrapper.py` and the
process timeout defaults to 15 minutes. This repository currently contains no
`2_pipeline` directory or scanner wrapper; supply that module and its runtime
dependencies, or configure `SCANNER_WRAPPER_PATH` and `PYTHON_EXECUTABLE`.
The backend container includes the Python 3 interpreter, but pipeline-specific
Python packages still need to be supplied with that module.
The scan transitions from `QUEUED` to `RUNNING`, then to `COMPLETED` only when
the process exits successfully, writes a valid result JSON document, and all
findings/metrics persist successfully. Invalid output, failures, and timeouts
are recorded as `FAILED`.

## Key endpoints added in Weeks 6-9

- `POST /api/plans/request?planName=PAID` — request a plan upgrade
- `GET /api/admin/users` — paginated user list (Admin/Faculty only)
- `PATCH /api/admin/users/{id}/status?status=PAUSED` — pause/activate a user
- `PATCH /api/admin/users/{id}/limit` — change a user's plan
- `DELETE /api/admin/users/{id}` — delete a user
- `GET /api/admin/plan-requests?status=PENDING` — list plan requests
- `PATCH /api/admin/plan-requests/{id}/approve` / `/reject`
- `POST /api/repositories` — connect a GitHub repo (`{ "githubRepoFullName": "org/repo" }`)
- `GET /api/repositories` — list your connected repos
- `DELETE /api/repositories/{id}` — disconnect a repo
- `POST /api/webhooks/github` — now persists a `WebhookEvent` + `QUEUED` `Scan` row on a verified push
- `GET /api/v1/scans?skip=0&limit=10` — paginated scan list
- `POST /api/v1/scans/upload` — extract a ZIP into local source storage and create a queued scan
- `POST /api/v1/scans/import-path` — register a local source directory under the configured upload root
- `POST /api/v1/scans/run` — asynchronously invoke the configured scanner for a queued local-source scan
- `GET /api/v1/scans` — user-scoped scan history
- `POST /api/v1/policies/evaluate` — evaluate findings against saved project thresholds (optional request thresholds override them)
- `GET /api/v1/reports/pdf/{scanId}` — download a PDF report for a scan you own
- `GET /api/v1/scans/{scanId}/export/sarif` — download SARIF JSON

### Weeks 6–10 integration requirements

The scanner must write `scored_results.json` as a JSON object with a `findings`
array (or `scored_findings`, `semgrep`, or `checkov` arrays). Each finding needs
`rule_id`, `title`, `file_path`, and non-negative `line_number`; severity,
reachability, priority, confidence, code snippet, and call traces are optional.
Optional `job_id`/`scan_id` must match the running scan. A `metrics` object is
stored in `ast_metrics`; if omitted, finding/severity counts are recorded.
Malformed findings fail the scan rather than being silently dropped.

LLM remediation uses an OpenAI-compatible chat-completions endpoint. Configure
`AUTOFORGE_LLM_API_KEY`, `AUTOFORGE_LLM_MODEL`, and optionally
`AUTOFORGE_LLM_ENDPOINT`. Remediation preview/generation is unavailable until
configured and is restricted to findings explicitly marked reachable. Generated
patches are stored as unvalidated suggestions; they still require review and
testing before application.

Queued webhook/project scans use Redis when available and the in-memory fallback
otherwise. The worker currently clones HTTPS GitHub repositories only; set
`GITHUB_TOKEN` for private repository access. Set `SCAN_QUEUE_POLL_INTERVAL_MS`
to tune polling. The scanner wrapper must still be provided separately as
described above; without it, the background job correctly fails rather than
returning fabricated findings.

### Weeks 11–16 integrations

Redis queue claims use a processing list so a queued item is not lost between
polling and scan handoff. Unacknowledged items are restored to the ready queue
on backend startup. If Redis is unavailable, the in-memory fallback works only
for the lifetime of that backend process and is not durable.

Set `CORS_ALLOWED_ORIGINS` to a comma-separated list of exact frontend origins;
wildcard origins are rejected. Swagger UI is available at
`/swagger-ui.html` and documents the JWT bearer authorization scheme.

`POST /api/v1/feedback` accepts `finding_id`, an `action` of `DISMISS`,
`FALSE_POSITIVE`, or `ACCEPT_PATCH`, and an optional comment. Accepting a patch
also requires its `fix_id` and changes that generated fix to `APPROVED`. Users
can only submit feedback for findings in their own projects or repositories.

`POST /api/v1/remediations/{id}/create-pr` publishes only an approved fix.
Configure `GITHUB_TOKEN`
with repository contents-write, pull-request, and commit-status permissions.
The optional `POST /api/v1/policies/evaluate/github-status` endpoint evaluates
the reachability-aware gate and posts `success` or `failure` to the scan's
commit with context `AutoForge/quality-gate`. Configure GitHub branch
protection to require that context if a failing result should block merging.
The service
pushes a branch and creates a real PR; it does not merge or auto-apply the fix.
External GitHub credentials and a disposable test repository are required to
verify that live integration end to end.

`/actuator/health` is public for health probes. `/actuator/info` and
`/actuator/metrics` require authentication. `GET /api/v1/health` returns HTTP
503 when its database connectivity check fails. Production database migration
should be verified against an isolated PostgreSQL instance before deployment.

GitHub push webhooks persist the branch and up to 500 safe changed paths from
the event's commit list on the scan job and queue payload. Pull-request
webhooks use the head branch and SHA; changed paths are included only when the
payload supplies a `pull_request.files` list. Standard GitHub PR webhooks do
not include that list, and the scanner wrapper currently has no documented
changed-path argument, so these paths are metadata and do not yet restrict
scanner execution.

Interrupted scans that remain `RUNNING`/`PROCESSING` for more than
`SCAN_RECOVERY_STALE_AFTER` (default 35 minutes) are re-claimed and restarted
by the scheduled recovery worker. The delay avoids restarting legitimate scans
whose clone and scan phases can each use the configured timeout.

`POST /api/v1/fix/generate?findingId={id}` is also available as an alias for
the finding remediation generation route. `GET /api/v1/feedback/export`
returns the authenticated user's feedback rows as JSON for downstream
retraining workflows; it does not train or deploy a model.
